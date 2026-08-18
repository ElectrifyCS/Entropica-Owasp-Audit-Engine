"""
Pure mathematical primitives for the OWASP Audit Engine.
No I/O, no side effects — fully unit-testable.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence, Union


class MathCore:
    """Stateless mathematical helpers."""

    @staticmethod
    def shannon_entropy(data: Union[str, bytes, Sequence]) -> float:
        """
        Shannon entropy H(X) in bits per symbol.

        H(X) = -Σ P(x_i) log₂ P(x_i)

        Low values (→ 0) indicate sequential / repeated tokens (BOLA risk).
        High values (→ log₂ |alphabet|) indicate cryptographic randomness.
        """
        if not data:
            return 0.0

        length = len(data)
        counts = Counter(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @staticmethod
    def normalized_entropy(data: Union[str, bytes, Sequence]) -> float:
        """
        Entropy normalized to [0, 1] by the maximum possible entropy
        for the observed alphabet size.
        """
        if not data:
            return 0.0
        alphabet_size = len(set(data))
        if alphabet_size <= 1:
            return 0.0
        max_h = math.log2(alphabet_size)
        return MathCore.shannon_entropy(data) / max_h

    @staticmethod
    def sequential_score(ids: Sequence[Union[int, str]]) -> float:
        """
        Measure how sequential a list of IDs is.
        Returns a score in [0, 1] where 1.0 = perfectly sequential integers.

        Useful complement to entropy when IDs are short numeric strings.
        """
        if len(ids) < 2:
            return 0.0

        numeric: list[int] = []
        for item in ids:
            try:
                numeric.append(int(item))
            except (ValueError, TypeError):
                return 0.0  # mixed / non-numeric → not sequential

        diffs = [numeric[i + 1] - numeric[i] for i in range(len(numeric) - 1)]
        if not diffs:
            return 0.0

        # Perfect sequential: all diffs == 1 (or all equal constant step)
        unique_diffs = set(diffs)
        if len(unique_diffs) == 1 and diffs[0] != 0:
            return 1.0

        # Partially sequential: many small positive steps
        small_steps = sum(1 for d in diffs if 0 < d <= 5)
        return small_steps / len(diffs)
