"""
Pure mathematical primitives for the OWASP Audit Engine.
No I/O, no side effects — fully unit-testable.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, List, Optional, Sequence, Union


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
    def parse_numeric_ids(ids: Sequence[Union[int, str]]) -> Optional[List[int]]:
        """
        Try to parse every ID as an int. Returns the parsed list, or None if
        any ID isn't purely numeric (mixed/alphanumeric ID schemes should be
        judged by entropy instead — see PredictableResourceIDRule).
        """
        numeric: List[int] = []
        for item in ids:
            try:
                numeric.append(int(item))
            except (ValueError, TypeError):
                return None
        return numeric

    @staticmethod
    def sequential_score(ids: Sequence[Union[int, str]]) -> float:
        """
        Measure how sequential a list of IDs is.
        Returns a score in [0, 1] where 1.0 = perfectly sequential integers.

        Useful complement to entropy when IDs are short numeric strings.

        IDs are sorted by value before scoring. A real probe has no control
        over the order it happens to encounter IDs in (pagination, response
        ordering, concurrent requests) — scoring on encounter order means
        the exact same auto-increment ID space can score anywhere from 1.0
        to near-0.0 purely by luck of collection order. Sorting first makes
        the score a property of the ID *space*, not the sampling order.
        """
        numeric = MathCore.parse_numeric_ids(ids)
        if numeric is None or len(numeric) < 2:
            return 0.0

        numeric = sorted(numeric)
        diffs = [numeric[i + 1] - numeric[i] for i in range(len(numeric) - 1)]
        if not diffs:
            return 0.0

        # Perfect sequential: all diffs equal the same constant step
        unique_diffs = set(diffs)
        if len(unique_diffs) == 1 and diffs[0] != 0:
            return 1.0

        # Partially sequential: many small positive steps
        small_steps = sum(1 for d in diffs if 0 < d <= 5)
        return small_steps / len(diffs)

    @staticmethod
    def estimated_keyspace_bits(ids: Sequence[Union[int, str]]) -> Optional[float]:
        """
        Estimate the size (in bits) of the underlying numeric ID keyspace
        from a *sample* of observed IDs. Returns None for non-numeric IDs
        (use entropy for those instead — see PredictableResourceIDRule).

        This exists because per-character Shannon entropy is capped at
        log2(10) ≈ 3.32 bits for any purely-numeric string, regardless of
        how large the real keyspace is — a random 10-digit ID and a
        predictable 5-digit one can both read as "low entropy" even though
        one has a ~9-billion-value keyspace and the other has ~90,000.
        Entropy answers "does this string look locally random"; this answers
        "how many values could this ID plausibly take," which is the
        question BOLA guessability actually depends on.

        The naive estimate — bits = log2(max_observed - min_observed) —
        systematically UNDERESTIMATES the true range, since a small sample
        is unlikely to contain the true extremes. For n values drawn
        uniformly from an unknown range, the expected sample range is
        (n-1)/(n+1) of the true range (a standard order-statistics result,
        the same family of estimator used in the classic "German tank
        problem"). Inverting that gives a less-biased estimate:

            range_hat = observed_range * (n + 1) / (n - 1)

        This is still a rough estimate from a small sample, not a proof —
        treat it as a signal to combine with entropy and sequential_score,
        not a standalone verdict.
        """
        numeric = MathCore.parse_numeric_ids(ids)
        if numeric is None or len(numeric) < 3:
            return None

        n = len(numeric)
        observed_range = max(numeric) - min(numeric)
        if observed_range <= 0:
            return 0.0

        estimated_range = observed_range * (n + 1) / (n - 1)
        return math.log2(estimated_range) if estimated_range > 0 else 0.0
