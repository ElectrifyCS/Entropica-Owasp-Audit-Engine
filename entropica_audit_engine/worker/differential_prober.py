"""
Collects the observations SSRFDifferentialRule judges, by actually
issuing requests with a parameter substituted across a control value and
one or more intervention values. This is the I/O half of the causal-probe
split described in core/causal_probe.py's module docstring: the rule
stays a thin, testable judgment layer; this is where HTTP actually
happens, mirroring how AsyncProber is the I/O half of the queue/EWMA math
in core/.

Logging note: this is the second prober in the codebase, and — unlike
AsyncProber — it has no queue/backoff governance at all right now; it
just fires samples_per_condition requests per condition in a tight
sequential loop. Logging every request here (this file) makes that
absence visible in the audit trail rather than hiding it — a security
engineer watching the log stream sees the requests going out with no
backoff events ever appearing, which is honest about what's actually
happening rather than silently leaving this prober unobserved. Whether
this prober should gain the same self-throttling AsyncProber has is a
separate, real question, not addressed by this change.
"""

from __future__ import annotations

import time
from typing import Dict, List, Mapping

import httpx

from entropica_audit_engine.observability.audit_log import (
    get_audit_logger,
    log_probe_result,
    log_probe_sent,
)


async def collect_differential_observations(
    client: httpx.AsyncClient,
    url_template: str,
    conditions: Mapping[str, str],
    samples_per_condition: int = 8,
    request_timeout: float = 10.0,
) -> Dict[str, List[float]]:
    """
    For each (label, value) in `conditions`, substitutes `value` into
    `url_template` (which must contain a "{value}" placeholder) and issues
    `samples_per_condition` GET requests, recording latency_ms for each.

    A failed/timed-out request still contributes a sample - at
    `request_timeout * 1000` ms - rather than being silently dropped,
    because a host that reliably times out (e.g. an unroutable internal
    IP) is itself a meaningful, real latency signal for this rule, not
    missing data to be discarded.

    Every request sent and its outcome is logged (see
    observability/audit_log.py) - the same probe_sent/probe_result event
    types AsyncProber uses, so a security engineer watching the log
    stream sees ALL outbound probing activity through one consistent
    event vocabulary, not two different logging conventions for the two
    probers.

    Returns {label: [latency_ms, ...]}, ready to pass straight into
    SSRFDifferentialRule via kwargs["observations"].
    """
    logger = get_audit_logger()
    results: Dict[str, List[float]] = {}

    for label, value in conditions.items():
        url = url_template.format(value=value)
        samples: List[float] = []
        for _ in range(samples_per_condition):
            log_probe_sent(logger, url)
            t0 = time.monotonic()
            status_code = None
            error = None
            try:
                resp = await client.get(url, timeout=request_timeout)
                status_code = resp.status_code
            except httpx.HTTPError as exc:
                error = str(exc)
            latency_ms = (time.monotonic() - t0) * 1000.0
            log_probe_result(logger, url, status_code, latency_ms, error=error)
            samples.append(latency_ms)
        results[label] = samples

    return results
