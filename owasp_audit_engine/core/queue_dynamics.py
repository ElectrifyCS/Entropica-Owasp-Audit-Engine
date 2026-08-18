"""
Differential models for rate-limiting / unrestricted resource consumption (OWASP API4).

Continuous form:
    dQ/dt = f_in(t) - μ

Discrete recurrence:
    Q_{k+1} = max(0, Q_k + (λ_k - μ) Δt)

Brute-force acceleration:
    R''(t) ≈ second derivative of request rate → detects automated bursts.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional, Tuple


@dataclass(frozen=True)
class QueueSnapshot:
    t: float
    queue_length: float
    arrival_rate: float
    drain_rate: float


class QueueDynamicsTracker:
    """
    Models endpoint queue accumulation under variable arrival rate.
    Useful for detecting when an attacker is overwhelming a resource
    faster than the server can drain it.
    """

    def __init__(self, drain_rate: float = 10.0) -> None:
        """
        drain_rate (μ): estimated requests the backend can process per second.
        """
        self.mu = drain_rate
        self.Q: float = 0.0
        self.last_t: Optional[float] = None
        self.history: Deque[QueueSnapshot] = deque(maxlen=1000)

    def update(self, t: float, lambda_rate: float) -> float:
        """
        Advance the queue model.

        Parameters
        ----------
        t : float
            Current timestamp (seconds, monotonic).
        lambda_rate : float
            Observed arrival rate (requests / second) in the current window.

        Returns
        -------
        float
            Current estimated queue length Q(t).
        """
        if self.last_t is not None:
            dt = max(0.0, t - self.last_t)
            self.Q = max(0.0, self.Q + (lambda_rate - self.mu) * dt)

        self.last_t = t
        snap = QueueSnapshot(t=t, queue_length=self.Q, arrival_rate=lambda_rate, drain_rate=self.mu)
        self.history.append(snap)
        return self.Q

    def is_overloaded(self, threshold: float = 50.0) -> bool:
        """Simple overload signal when queue grows beyond threshold."""
        return self.Q >= threshold

    def reset(self) -> None:
        self.Q = 0.0
        self.last_t = None
        self.history.clear()


class AccelerationTracker:
    """
    Tracks first and second derivatives of request rate to distinguish
    organic traffic spikes from automated brute-force acceleration.

    R'(t)  ≈ velocity  (change in rate)
    R''(t) ≈ acceleration
    """

    def __init__(self, window: int = 5) -> None:
        self.window = window
        self.rates: Deque[Tuple[float, float]] = deque(maxlen=window)  # (t, rate)
        self._last_velocity: float = 0.0
        self._last_accel: float = 0.0
        # Keep more accel history than `window` so is_brute_force can look
        # back further than the rate window used to compute each point.
        self._accel_history: Deque[float] = deque(maxlen=max(window * 2, 10))

    def update(self, t: float, rate: float) -> Tuple[float, float]:
        """
        Ingest a new (timestamp, rate) sample.

        Returns
        -------
        (velocity, acceleration)
        """
        self.rates.append((t, rate))

        if len(self.rates) < 3:
            return 0.0, 0.0

        # Simple finite differences on the last three points
        t0, r0 = self.rates[-3]
        t1, r1 = self.rates[-2]
        t2, r2 = self.rates[-1]

        dt1 = t1 - t0 or 1e-9
        dt2 = t2 - t1 or 1e-9

        v1 = (r1 - r0) / dt1
        v2 = (r2 - r1) / dt2
        velocity = v2
        accel = (v2 - v1) / ((dt1 + dt2) / 2.0)

        self._last_velocity = velocity
        self._last_accel = accel
        self._accel_history.append(accel)
        return velocity, accel

    @property
    def velocity(self) -> float:
        return self._last_velocity

    @property
    def acceleration(self) -> float:
        return self._last_accel

    def is_brute_force(self, accel_threshold: float = 20.0, sustained: int = 3) -> bool:
        """
        True when the last `sustained` consecutive acceleration readings
        have ALL exceeded accel_threshold. A single spike is easily organic
        (a cache miss, a slow dependency); acceleration staying elevated
        across several consecutive windows in a row is much more consistent
        with scripted traffic ramping up than with normal usage.
        """
        if sustained < 1 or len(self._accel_history) < sustained:
            return False
        recent = list(self._accel_history)[-sustained:]
        return all(a > accel_threshold for a in recent)

    def reset(self) -> None:
        self.rates.clear()
        self._last_velocity = 0.0
        self._last_accel = 0.0
