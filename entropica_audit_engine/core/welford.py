"""
Streaming Welford algorithm for online mean / variance / z-score,
plus an EWMA sequential anomaly layer.

Constant memory, numerically stable.  All updates are O(1).

Mathematical foundations (first principles, IB Maths AA HL style)
-----------------------------------------------------------------
Welford’s method is a numerically stable online algorithm for the
sample mean and the sum of squared deviations.  The EWMA layer turns
the instantaneous z-score stream into a smoothed sequential test that
detects *sustained* departures rather than single outliers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class WelfordStats:
    """Snapshot of the current tracker state."""
    count: int
    mean: float
    std_dev: float
    z_score: Optional[float]  # z of the most recent sample


class WelfordTracker:
    """
    Online computation of mean and sample standard deviation.

    Recurrence (Welford, 1962)
    --------------------------
    Let x₁, x₂, … be a stream of real observations.  Define

        M_k = M_{k-1} + (x_k − M_{k-1}) / k
        S_k = S_{k-1} + (x_k − M_{k-1})(x_k − M_k)

    with M_0 = 0, S_0 = 0.  Then

        sample variance  s²_k = S_k / (k − 1)   (k ≥ 2)
        sample std-dev   s_k  = √(s²_k)
        z-score          Z_k  = (x_k − M_k) / s_k

    The algorithm uses only O(1) memory and avoids the catastrophic
    cancellation that appears in the naïve two-pass formula
    ∑x² − (∑x)²/n when the data are large and nearly constant.

    Anomaly condition commonly used: |Z| > 3.0 (three-sigma rule).
    """

    def __init__(self) -> None:
        self.count: int = 0
        self.mean: float = 0.0
        self.M2: float = 0.0  # sum of squared differences (S_k)
        self._last_z: Optional[float] = None

    def update(self, x: float) -> float:
        """
        Ingest a new observation and return its z-score.
        Returns 0.0 while count < 2 (insufficient data).
        """
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.M2 += delta * delta2

        if self.count < 2:
            self._last_z = 0.0
            return 0.0

        variance = self.M2 / (self.count - 1)
        std_dev = math.sqrt(variance) if variance > 0 else 1e-9
        z = (x - self.mean) / std_dev
        self._last_z = z
        return z

    @property
    def std_dev(self) -> float:
        if self.count < 2:
            return 0.0
        variance = self.M2 / (self.count - 1)
        return math.sqrt(variance) if variance > 0 else 0.0

    def stats(self) -> WelfordStats:
        return WelfordStats(
            count=self.count,
            mean=self.mean,
            std_dev=self.std_dev,
            z_score=self._last_z,
        )

    def is_anomaly(self, threshold: float = 3.0) -> bool:
        """True if the most recent sample has |z| > threshold."""
        return self._last_z is not None and abs(self._last_z) > threshold

    def reset(self) -> None:
        self.count = 0
        self.mean = 0.0
        self.M2 = 0.0
        self._last_z = None


# ----------------------------------------------------------------------
# EWMA sequential anomaly detector
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class EWMAStats:
    """Snapshot of the EWMA tracker."""
    count: int
    ewma: float
    last_z: Optional[float]
    is_anomaly: bool


class EWMAAnomalyTracker:
    """
    Exponentially Weighted Moving Average of absolute z-scores.

    Motivation (first principles)
    -----------------------------
    A single |Z| > 3 may be an organic spike (cache miss, GC pause).
    A *sustained* elevation of |Z| is far more consistent with a
    systematic side-channel, resource exhaustion, or scripted attack.

    The EWMA provides a simple one-parameter sequential test:

        S_t = λ |Z_t| + (1 − λ) S_{t−1} ,   S_0 = 0

    where λ ∈ (0, 1] is the smoothing constant (typical values 0.1–0.3).
    An alarm is raised when S_t exceeds a threshold τ.

    Why EWMA?
    ---------
    • Memory of past anomalies decays exponentially: the weight of an
      observation k steps ago is (1−λ)^k.
    • Only O(1) state is required.
    • The same numerical stability properties as Welford are inherited
      because we feed it already-computed z-scores.

    Relationship to CUSUM
    ---------------------
    Page’s CUSUM is the optimal sequential test for a sustained mean
    shift under certain assumptions.  EWMA is a close relative that is
    slightly simpler to tune and interpret for security tooling; both
    can be added later if needed.  The current implementation already
    supplies the streaming infrastructure.
    """

    def __init__(
        self,
        lambda_: float = 0.2,
        threshold: float = 2.5,
        min_count: int = 5,
    ) -> None:
        """
        Parameters
        ----------
        lambda_ : float
            Smoothing factor λ ∈ (0, 1].  Larger → more responsive,
            smaller → smoother.
        threshold : float
            Alarm level τ for S_t.
        min_count : int
            Minimum number of updates before an anomaly can be declared
            (avoids false alarms on the first few samples).
        """
        if not 0.0 < lambda_ <= 1.0:
            raise ValueError("lambda_ must be in (0, 1]")
        self.lambda_ = lambda_
        self.threshold = threshold
        self.min_count = min_count

        self.count: int = 0
        self.S: float = 0.0
        self._last_z: Optional[float] = None

    def update(self, z: float) -> float:
        """
        Ingest a new z-score and return the updated EWMA value S_t.
        """
        self.count += 1
        self._last_z = z
        abs_z = abs(z)
        self.S = self.lambda_ * abs_z + (1.0 - self.lambda_) * self.S
        return self.S

    def is_anomaly(self) -> bool:
        """True when the EWMA has exceeded the threshold for long enough."""
        return self.count >= self.min_count and self.S >= self.threshold

    def stats(self) -> EWMAStats:
        return EWMAStats(
            count=self.count,
            ewma=self.S,
            last_z=self._last_z,
            is_anomaly=self.is_anomaly(),
        )

    def reset(self) -> None:
        self.count = 0
        self.S = 0.0
        self._last_z = None
