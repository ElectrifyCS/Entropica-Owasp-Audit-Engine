"""
Differential models for rate-limiting / unrestricted resource consumption (ENTROPICA API4).

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

    def __init__(
        self,
        drain_rate: float = 10.0,
        mu_learning_rate: float = 0.2,
        min_departures_before_adapting: int = 5,
    ) -> None:
        """
        drain_rate (μ): starting estimate of requests the backend can
        process per second. Refined online by `record_departure` once
        enough in-queue departures have been observed (see below) —
        this is the *initial guess*, not a fixed value for the tracker's
        lifetime.

        mu_learning_rate : EWMA smoothing factor (0-1) applied to each
            new inter-departure-rate sample. Higher = adapts faster but
            noisier; lower = smoother but slower to react to a real
            capacity change.
        min_departures_before_adapting : number of in-queue departure
            samples required before the EWMA is trusted over the initial
            guess. Guards against a single lucky/unlucky gap swinging μ
            (and therefore Q) around on almost no evidence.
        """
        self.mu = drain_rate
        self._initial_mu = drain_rate
        self.Q: float = 0.0
        self.last_t: Optional[float] = None
        self.history: Deque[QueueSnapshot] = deque(maxlen=1000)

        # --- online μ (drain-rate) estimation state ---
        self.mu_learning_rate = mu_learning_rate
        self.min_departures_before_adapting = min_departures_before_adapting
        self._last_departure_t: Optional[float] = None
        self._mu_ewma: Optional[float] = None
        self.mu_sample_count: int = 0

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

    def record_departure(self, t: float) -> None:
        """
        Record an actual observed completion ("departure") at time t —
        e.g. an HTTP response actually came back, as opposed to the
        modelled arrivals fed to `update()`.

        Project notes, section 3 ("Adaptive Service Rate μ"): "when the
        modelled queue is non-empty, departures reveal capacity. Simple
        approach: exponentially weighted estimate of completion rate
        while Q > 0."

        While self.Q > 0 — the model currently believes arrivals are
        outpacing drain — the actual gap since the last departure is
        evidence of the real service rate:

            μ̂_k = α · (1 / Δt_departure) + (1 − α) · μ̂_{k−1}

        Departures observed while Q == 0 still update the timing
        baseline (so the next in-queue gap is measured correctly) but do
        NOT feed the estimate: with no backlog, inter-departure spacing
        reflects arrival spacing, not the server's true capacity — using
        it would bias μ toward whatever rate the prober happens to be
        issuing requests at, not what the target can actually absorb.

        `self.mu` is only overwritten once `min_departures_before_adapting`
        in-queue samples have accumulated, and is floored at a small
        positive value — an estimate that collapsed to ~0 would make Q
        grow without bound on the next `update()` call regardless of the
        true arrival rate.
        """
        if self._last_departure_t is not None and self.Q > 0:
            dt = t - self._last_departure_t
            if dt > 1e-6:
                instantaneous_rate = 1.0 / dt
                if self._mu_ewma is None:
                    self._mu_ewma = instantaneous_rate
                else:
                    a = self.mu_learning_rate
                    self._mu_ewma = a * instantaneous_rate + (1 - a) * self._mu_ewma
                self.mu_sample_count += 1
                if self.mu_sample_count >= self.min_departures_before_adapting:
                    self.mu = max(0.1, self._mu_ewma)

        self._last_departure_t = t

    @property
    def mu_is_adapted(self) -> bool:
        """True once μ reflects observed departures rather than the initial guess."""
        return self.mu_sample_count >= self.min_departures_before_adapting

    def reset(self) -> None:
        self.Q = 0.0
        self.last_t = None
        self.history.clear()
        self.mu = self._initial_mu
        self._last_departure_t = None
        self._mu_ewma = None
        self.mu_sample_count = 0


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
