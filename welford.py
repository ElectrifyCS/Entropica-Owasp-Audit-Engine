"""
Streaming Welford algorithm for online mean / variance / z-score.
Constant memory, numerically stable.
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

    M_k = M_{k-1} + (x_k - M_{k-1}) / k
    S_k = S_{k-1} + (x_k - M_{k-1})(x_k - M_k)

    Anomaly condition commonly used: |Z| > 3.0
    """

    def __init__(self) -> None:
        self.count: int = 0
        self.mean: float = 0.0
        self.M2: float = 0.0  # sum of squared differences
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
