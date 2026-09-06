"""
Collects the observations SSRFDifferentialRule judges, by actually
issuing requests with a parameter substituted across a control value and
one or more intervention values. This is the I/O half of the causal-probe
split described in core/causal_probe.py's module docstring: the rule
stays a thin, testable judgment layer; this is where HTTP actually
happens, mirroring how AsyncProber is the I/O half of the queue/EWMA math
in core/.

Self-throttling
----------------
This prober used to fire every request in a flat sequential loop with
zero concurrency and zero governance - gentle by construction in the
sense that it never outran the target (each request waited for the
previous response), but that also meant no protection at all if a
single condition's request volume started visibly stressing a slow or
already-loaded target.

Rather than build a second, parallel self-throttling mechanism, this
now reuses AsyncProber directly: every sample is issued through
`prober.probe_one()`, which already provides the queue-model backoff
loop, adaptive drain-rate (mu) estimation, and audit logging (see
worker/prober.py's module docstring). An AsyncProber instance can be
passed in explicitly - the intended use when this collector runs as
part of a larger scan against the same target, so the target's learned
capacity (mu) is shared rather than re-learned from scratch by two
independent probers that don't know about each other. If none is
passed, a fresh one is constructed, scoped to just this call.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Mapping, Optional

import httpx

from entropica_audit_engine.worker.prober import AsyncProber


async def collect_differential_observations(
    client: httpx.AsyncClient,
    url_template: str,
    conditions: Mapping[str, str],
    samples_per_condition: int = 8,
    request_timeout: float = 10.0,
    prober: Optional[AsyncProber] = None,
) -> Dict[str, List[float]]:
    """
    For each (label, value) in `conditions`, substitutes `value` into
    `url_template` (which must contain a "{value}" placeholder) and
    issues `samples_per_condition` GET requests via `prober.probe_one`,
    recording latency_ms for each. Requests within one condition run
    concurrently, bounded and self-throttled by whatever the prober's
    own max_concurrency / queue_backoff_threshold are configured to;
    conditions themselves are processed one at a time - not because
    concurrency across conditions would be unsafe, but because mixing
    conditions' timing together would make Welch's t-test comparison
    noisier for no real benefit (background load affecting one
    condition's batch shouldn't bleed into another's).

    A failed/timed-out request still contributes a sample - at whatever
    time it actually took - rather than being silently dropped, because
    a host that reliably times out (e.g. an unroutable internal IP) is
    itself a meaningful, real latency signal for this rule, not missing
    data to be discarded. AsyncProber.probe_one already handles this the
    same way for regular probing, so this inherits that behavior rather
    than reimplementing it.

    prober : AsyncProber, optional
        Pass an existing instance to share its learned drain-rate
        estimate and queue state with other probing already happening
        against the same target. If omitted, a fresh AsyncProber is
        constructed (max_concurrency=5 - more conservative than
        AsyncProber's own default of 10, since a suspected-SSRF endpoint
        may trigger a server-side downstream request per hit, plausibly
        more expensive per-request than a normal endpoint).

    Returns {label: [latency_ms, ...]}, ready to pass straight into
    SSRFDifferentialRule via kwargs["observations"].
    """
    if prober is None:
        prober = AsyncProber(max_concurrency=5, request_timeout=request_timeout)

    results: Dict[str, List[float]] = {}
    for label, value in conditions.items():
        url = url_template.format(value=value)
        tasks = [prober.probe_one(client, url) for _ in range(samples_per_condition)]
        probe_results = await asyncio.gather(*tasks)
        results[label] = [r.latency_ms for r in probe_results]

    return results
