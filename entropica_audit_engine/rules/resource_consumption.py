"""
ENTROPICA API4:2023 – Unrestricted Resource Consumption

Wraps QueueDynamicsTracker + AccelerationTracker (already built and tested
in core/queue_dynamics.py) in the same Finding-producing interface used by
every other rule. No new math here — this rule existed as pure functions
before it existed as a rule; this file is the missing plumbing.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple

from entropica_audit_engine.core.queue_dynamics import (
    AccelerationTracker,
    QueueDynamicsTracker,
)
from .base import BaseAuditRule, Finding, Severity


class UnrestrictedResourceConsumptionRule(BaseAuditRule):
    """
    Feeds a time series of (timestamp, arrival_rate) observations through
    the queue and acceleration trackers and raises a Finding when either:

      1. The modelled queue length exceeds `queue_threshold` (arrivals are
         sustained above the endpoint's estimated drain rate), or
      2. Acceleration stays above `accel_threshold` for `sustained_windows`
         consecutive samples in a row (a scripted ramp, not an organic
         spike).

    Both trackers already carry their own tests in test_math_core.py; this
    rule only decides *when a Finding is warranted* from their output.
    """

    def __init__(
        self,
        drain_rate: float = 10.0,
        queue_threshold: float = 50.0,
        accel_threshold: float = 20.0,
        sustained_windows: int = 3,
    ) -> None:
        super().__init__(
            rule_id="API4:2023",
            name="Unrestricted Resource Consumption",
            severity=Severity.HIGH,
            description=(
                "Observed request arrivals sustain a rate above the "
                "endpoint's estimated drain rate, and/or the request rate "
                "shows sustained positive acceleration consistent with "
                "scripted or brute-force traffic rather than organic load."
            ),
            recommendation=(
                "Enforce per-client rate limiting and request quotas. "
                "Consider adaptive throttling that responds to sustained "
                "positive acceleration in request rate, not just a static "
                "requests-per-minute ceiling."
            ),
        )
        self.drain_rate = drain_rate
        self.queue_threshold = queue_threshold
        self.accel_threshold = accel_threshold
        self.sustained_windows = sustained_windows

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects `rate_samples`: a sequence of (timestamp, arrival_rate)
        tuples in chronological order — one point per observation window
        (e.g. requests/second measured every second).
        """
        rate_samples: Sequence[Tuple[float, float]] = kwargs.get("rate_samples") or []
        if len(rate_samples) < 3:
            return None

        queue = QueueDynamicsTracker(drain_rate=self.drain_rate)
        accel = AccelerationTracker()

        max_q = 0.0
        max_sustained_accel = False
        trace: List[dict] = []

        for t, rate in rate_samples:
            q = queue.update(t, rate)
            velocity, acceleration = accel.update(t, rate)
            max_q = max(max_q, q)
            if accel.is_brute_force(
                accel_threshold=self.accel_threshold,
                sustained=self.sustained_windows,
            ):
                max_sustained_accel = True
            trace.append(
                {
                    "t": t,
                    "arrival_rate": rate,
                    "queue_length": round(q, 2),
                    "velocity": round(velocity, 2),
                    "acceleration": round(acceleration, 2),
                }
            )

        overloaded = max_q >= self.queue_threshold
        triggered_by: List[str] = []
        if overloaded:
            triggered_by.append("queue_overload")
        if max_sustained_accel:
            triggered_by.append("sustained_acceleration")

        if not triggered_by:
            return None

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            target=target_url,
            evidence={
                "sample_count": len(rate_samples),
                "trace_preview": trace[-10:],  # last 10 windows, not the full history
            },
            metrics={
                "max_queue_length": round(max_q, 2),
                "queue_threshold": self.queue_threshold,
                "accel_threshold": self.accel_threshold,
                "sustained_windows": self.sustained_windows,
                "triggered_by": triggered_by,
            },
        )
