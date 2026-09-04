"""
Async HTTP probing worker.

Turns the passive rules (which evaluate data handed to them) into an
active collector that hits real endpoints and feeds their output back
into the rule interface. The one design choice worth calling out:

The prober's own concurrency is governed by the same QueueDynamicsTracker
used by rules/resource_consumption.py to *detect* overload in a target.
Instead of a fixed "N requests per second" ceiling, the prober tracks its
own modelled queue length against the target and backs off exactly when
Q(t) would start growing — i.e. it uses its own detection math to avoid
becoming the attacker it's built to find.

The target's drain rate (μ) starts from a guess (`initial_drain_rate`)
and is then refined online from real response timing: every completed
request is recorded as a departure via
`QueueDynamicsTracker.record_departure`, which maintains an EWMA of the
observed completion rate for departures that occur while the modelled
queue is non-empty (see that method's docstring for why only those
departures count). Until `min_departures_before_adapting` such samples
have been observed, μ stays at the initial guess — `mu_is_adapted` /
`drain_rate_estimate` on the tracker expose whether the current value is
still that guess or has actually been learned.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import httpx

from entropica_audit_engine.core.queue_dynamics import QueueDynamicsTracker
from entropica_audit_engine.core.welford import WelfordTracker, EWMAAnomalyTracker
from entropica_audit_engine.observability.audit_log import (
    get_audit_logger,
    log_backoff_cleared,
    log_backoff_started,
    log_drain_rate_adapted,
    log_probe_result,
    log_probe_sent,
    log_scan_complete,
    log_scan_start,
)


@dataclass
class ProbeResult:
    """One HTTP response, reduced to what the rules need."""
    url: str
    status_code: Optional[int]
    latency_ms: float
    error: Optional[str] = None
    body: Any = None


@dataclass
class ProbeSession:
    """
    Accumulated evidence from a probing run against one target, in the
    shapes the existing rules already expect via **kwargs.
    """
    sample_ids: List[str] = field(default_factory=list)
    field_samples: Dict[str, List[Any]] = field(default_factory=dict)
    rate_samples: List[tuple] = field(default_factory=list)
    latencies_ms: List[float] = field(default_factory=list)
    results: List[ProbeResult] = field(default_factory=list)


class AsyncProber:
    """
    Concurrency-adaptive async HTTP prober.

    Parameters
    ----------
    max_concurrency : int
        Hard ceiling on simultaneous in-flight requests, regardless of
        what the queue model would otherwise allow. A safety backstop,
        not the primary throttle.
    initial_drain_rate : float
        Starting estimate of the target's requests/sec capacity (μ).
        Refined online as real responses come back — see
        `QueueDynamicsTracker.record_departure`, called from `probe_one`
        on every completion.
    queue_backoff_threshold : float
        When the modelled queue length exceeds this, the prober pauses
        new requests until it drains — this is the self-governance loop.
    """

    def __init__(
        self,
        max_concurrency: int = 10,
        initial_drain_rate: float = 5.0,
        queue_backoff_threshold: float = 20.0,
        request_timeout: float = 10.0,
    ) -> None:
        self.max_concurrency = max_concurrency
        self.queue_backoff_threshold = queue_backoff_threshold
        self.request_timeout = request_timeout

        self._queue_model = QueueDynamicsTracker(drain_rate=initial_drain_rate)
        self._latency_tracker = WelfordTracker()
        self._anomaly_tracker = EWMAAnomalyTracker()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._completed_count = 0
        self._start_time: Optional[float] = None
        self._audit_logger = get_audit_logger()

    async def _wait_for_capacity(self, url: str) -> None:
        """
        Block briefly while the modelled queue is above the backoff
        threshold. This is the loop that ties the prober's own throughput
        to the same math used elsewhere in this project to *detect*
        overload — the prober refuses to put itself in the state its own
        rules would flag.

        Every entry into and exit from a backoff period is logged (see
        observability/audit_log.py) — this is the safety-critical event
        in the whole system: the concrete evidence that self-throttling
        actually happened, not just a design claim.
        """
        backoff_start: Optional[float] = None
        while True:
            now = time.monotonic()
            elapsed = max(now - (self._start_time or now), 1e-6)
            current_rate = self._completed_count / elapsed
            q = self._queue_model.update(now, current_rate)
            if q < self.queue_backoff_threshold:
                if backoff_start is not None:
                    log_backoff_cleared(
                        self._audit_logger, url, queue_length=q,
                        wait_seconds=now - backoff_start,
                    )
                return
            if backoff_start is None:
                backoff_start = now
                log_backoff_started(
                    self._audit_logger, url, queue_length=q,
                    threshold=self.queue_backoff_threshold,
                )
            await asyncio.sleep(0.05)

    async def probe_one(self, client: httpx.AsyncClient, url: str) -> ProbeResult:
        if self._start_time is None:
            self._start_time = time.monotonic()

        await self._wait_for_capacity(url)
        async with self._semaphore:
            log_probe_sent(self._audit_logger, url)
            t0 = time.monotonic()
            try:
                resp = await client.get(url, timeout=self.request_timeout)
                completion_t = time.monotonic()
                latency_ms = (completion_t - t0) * 1000.0
                self._completed_count += 1
                mu_before = self._queue_model.mu
                self._queue_model.record_departure(completion_t)
                if self._queue_model.mu != mu_before:
                    log_drain_rate_adapted(
                        self._audit_logger, url, previous_mu=mu_before,
                        new_mu=self._queue_model.mu,
                        n_departures_observed=self._queue_model.mu_sample_count,
                    )
                z = self._latency_tracker.update(latency_ms)
                self._anomaly_tracker.update(z)
                body: Any = None
                try:
                    body = resp.json()
                except Exception:
                    body = None
                log_probe_result(self._audit_logger, url, resp.status_code, latency_ms)
                return ProbeResult(
                    url=url,
                    status_code=resp.status_code,
                    latency_ms=latency_ms,
                    body=body,
                )
            except httpx.HTTPError as exc:
                completion_t = time.monotonic()
                latency_ms = (completion_t - t0) * 1000.0
                self._completed_count += 1
                mu_before = self._queue_model.mu
                self._queue_model.record_departure(completion_t)
                if self._queue_model.mu != mu_before:
                    log_drain_rate_adapted(
                        self._audit_logger, url, previous_mu=mu_before,
                        new_mu=self._queue_model.mu,
                        n_departures_observed=self._queue_model.mu_sample_count,
                    )
                log_probe_result(self._audit_logger, url, None, latency_ms, error=str(exc))
                return ProbeResult(
                    url=url, status_code=None, latency_ms=latency_ms, error=str(exc)
                )

    async def probe_many(
        self, urls: Sequence[str], headers: Optional[Dict[str, str]] = None
    ) -> ProbeSession:
        """
        Probe every URL, collecting results into the shapes rules expect.
        Numeric trailing path segments are treated as candidate resource
        IDs for the BOLA rule; JSON response keys are collected per-field
        for the excessive-data-exposure rule.
        """
        session = ProbeSession()
        log_scan_start(self._audit_logger, urls, self.max_concurrency)
        scan_t0 = time.monotonic()
        async with httpx.AsyncClient(headers=headers) as client:
            tasks = [self.probe_one(client, url) for url in urls]
            results = await asyncio.gather(*tasks)

        for result in results:
            session.results.append(result)
            session.latencies_ms.append(result.latency_ms)

            tail = result.url.rstrip("/").rsplit("/", 1)[-1]
            if tail:
                session.sample_ids.append(tail)

            if isinstance(result.body, dict):
                for key, value in result.body.items():
                    session.field_samples.setdefault(key, []).append(value)

        log_scan_complete(
            self._audit_logger,
            target_count=len(urls),
            duration_seconds=time.monotonic() - scan_t0,
            anomaly_detected=self.anomaly_detected,
            final_drain_rate_estimate=self.drain_rate_estimate,
            drain_rate_is_adapted=self.mu_is_adapted,
        )
        return session

    @property
    def anomaly_detected(self) -> bool:
        """True if latency has shown a sustained elevation (see EWMA tracker)."""
        return self._anomaly_tracker.is_anomaly()

    @property
    def queue_snapshot(self) -> float:
        return self._queue_model.Q

    @property
    def drain_rate_estimate(self) -> float:
        """Current μ — either still the initial guess, or the online EWMA
        estimate once enough in-queue departures have been observed
        (see `mu_is_adapted`)."""
        return self._queue_model.mu

    @property
    def mu_is_adapted(self) -> bool:
        """True once drain_rate_estimate reflects observed departures
        rather than the constructor's initial_drain_rate guess."""
        return self._queue_model.mu_is_adapted
