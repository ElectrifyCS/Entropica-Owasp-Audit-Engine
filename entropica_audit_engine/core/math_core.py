"""
Pure mathematical primitives for the ENTROPICA Audit Engine.
No I/O, no side effects — fully unit-testable.

Mathematical foundations (first principles, IB Maths AA HL style)
-----------------------------------------------------------------
Shannon entropy, order statistics (German-tank / range estimation),
and bias-corrected estimators are derived from elementary probability
and information theory. All formulas are exact or standard asymptotic
corrections; no black-box libraries.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import List, Optional, Sequence, Tuple, Union


class MathCore:
    """Stateless mathematical helpers."""

    # ------------------------------------------------------------------
    # 1. Shannon entropy (discrete)
    # ------------------------------------------------------------------
    @staticmethod
    def shannon_entropy(data: Union[str, bytes, Sequence]) -> float:
        """
        Shannon entropy H(X) in bits per symbol.

        Definition (first principles)
        -----------------------------
        Let X be a discrete random variable taking values in a finite
        alphabet 𝒜 with probability mass function p(x) = P(X = x).

            H(X) = − ∑_{x ∈ 𝒜} p(x) log₂ p(x)

        Units are bits because the logarithm is base-2.

        Properties used here
        --------------------
        • H(X) = 0  ⇔  X is deterministic (one symbol has probability 1).
        • H(X) ≤ log₂ |𝒜|, with equality iff p is uniform on 𝒜.
        • For a finite sample of size n the plug-in estimator replaces
          p(x) by the relative frequency n_x / n.

        Low values indicate sequential / repeated tokens (BOLA risk).
        High values (approaching log₂ |alphabet|) indicate cryptographic
        randomness.
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
        for the observed alphabet size:

            H_norm = H(X) / log₂ |𝒜|

        where |𝒜| is the number of distinct symbols actually seen.
        This makes short and long strings comparable on the same scale.
        """
        if not data:
            return 0.0
        alphabet_size = len(set(data))
        if alphabet_size <= 1:
            return 0.0
        max_h = math.log2(alphabet_size)
        return MathCore.shannon_entropy(data) / max_h

    # ------------------------------------------------------------------
    # 2. Miller–Madow bias-corrected entropy
    # ------------------------------------------------------------------
    @staticmethod
    def miller_madow_entropy(data: Union[str, bytes, Sequence]) -> float:
        """
        Miller–Madow bias-corrected Shannon entropy (bits).

        Motivation (first principles)
        -----------------------------
        The naïve plug-in estimator

            Ĥ_plugin = − ∑ (n_x / n) log₂ (n_x / n)

        is negatively biased for finite samples.  The expected bias for
        a discrete distribution with K distinct symbols is approximately

            E[Ĥ_plugin] ≈ H − (K − 1) / (2 n ln 2) + O(1/n²)

        (Miller 1955; see also Cover & Thomas, Elements of Information
        Theory).  The Miller–Madow correction therefore adds the leading
        term:

            Ĥ_MM = Ĥ_plugin + (K − 1) / (2 n ln 2)

        where ln denotes the natural logarithm.  Conversion between
        natural and base-2 logarithms produces the factor 1/ln 2.

        When n is large or K is small the correction vanishes, recovering
        the ordinary Shannon entropy.  For the small samples typical of
        early API probing the correction is material and reduces systematic
        under-estimation of randomness.
        """
        if not data:
            return 0.0

        n = len(data)
        counts = Counter(data)
        k = len(counts)  # number of distinct symbols observed
        if n == 0 or k == 0:
            return 0.0

        h_plugin = -sum(
            (c / n) * math.log2(c / n) for c in counts.values()
        )
        # Miller–Madow correction term (bits)
        correction = (k - 1) / (2.0 * n * math.log(2))
        return h_plugin + correction

    # ------------------------------------------------------------------
    # 3. Numeric ID utilities
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # 4. Order-statistics keyspace estimator + confidence interval
    # ------------------------------------------------------------------
    @staticmethod
    def estimated_keyspace_bits(ids: Sequence[Union[int, str]]) -> Optional[float]:
        """
        Point estimate of the size (in bits) of the underlying numeric
        ID keyspace from a sample of observed IDs.

        Returns None for non-numeric IDs (use entropy for those).

        Derivation (order statistics / German-tank problem)
        ---------------------------------------------------
        Assume the true IDs are drawn uniformly from an unknown interval
        of integer length R = max_true − min_true + 1.  Let

            X_{(1)} < X_{(2)} < … < X_{(n)}

        be the order statistics of a sample of size n ≥ 2.  The expected
        range of the sample is

            E[X_{(n)} − X_{(1)}] = R · (n − 1) / (n + 1)

        (standard result for uniform order statistics).  Solving for R
        yields the unbiased estimator

            R̂ = (X_{(n)} − X_{(1)}) · (n + 1) / (n − 1)

        The keyspace size in bits is then log₂(R̂).  (We omit the “+1”
        inside the log for large ranges; it is negligible.)

        This corrects the systematic under-estimation that occurs when
        one simply takes log₂(max − min) on a small sample that has not
        yet hit the true extremes.
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

    @staticmethod
    def keyspace_bits_ci(
        ids: Sequence[Union[int, str]],
        confidence: float = 0.95,
    ) -> Optional[Tuple[float, float, float]]:
        """
        Confidence interval for the keyspace size in bits.

        Returns (point_estimate, lower_bits, upper_bits) or None.

        Method (first principles — exact, not asymptotic)
        ---------------------------------------------------
        Under the uniform-order-statistics model, W = X_(n) − X_(1)
        (the sample range) scaled by R is a *known* Beta random variable:

            W / R  ~  Beta(n − 1, 2)

        This is a standard result: with n iid Uniform(0, R) draws, the
        range's distribution depends only on n, and for the Beta(a, b)
        family with a = n − 1, b = 2,

            E[W/R]   = a / (a + b)              = (n − 1) / (n + 1)
            Var[W/R] = a·b / [(a+b)²(a+b+1)]    = 2(n − 1) / [(n+1)²(n+2)]

        The mean matches the point estimator already used above. For the
        variance of ln(R̂) we apply the delta method to g(u) = ln(1/u)
        around u = E[W/R], since R̂ = W · (n+1)/(n−1) = W / E[W/R]:

            Var(ln R̂) ≈ Var(W/R) / E[W/R]²

        Unlike a central-limit / Gumbel-tail approximation, this uses the
        *exact* first two moments of the Beta law, so it stays accurate
        even for the small samples typical of early API probing (n as
        low as 3–10) rather than only in the large-n limit. A quick
        Monte-Carlo check confirms this tracks empirical variance far
        better than a naive Var(ln R̂) ≈ 2/n guess, which overstates the
        uncertainty by a factor of √n and makes the interval needlessly
        wide as n grows.

        We form a normal interval on the log-bits scale and exponentiate
        back:

            σ_bits = √(Var(ln R̂)) / ln(2)
            half-width = z_{α/2} · σ_bits

        where z_{α/2} is the standard normal quantile for the desired
        two-sided confidence level. The interval is reported on the bits
        scale so a finding can say, e.g.,

            “estimated keyspace 28.4 bits  [26.9, 29.9]”

        rather than a bare point estimate. For very small n the interval
        is wide, correctly reflecting limited information; it tightens
        roughly as 1/n rather than 1/√n, matching the fact that the
        range statistic itself concentrates quickly for uniform data.
        """
        numeric = MathCore.parse_numeric_ids(ids)
        if numeric is None or len(numeric) < 3:
            return None

        n = len(numeric)
        observed_range = max(numeric) - min(numeric)
        if observed_range <= 0:
            return (0.0, 0.0, 0.0)

        # Point estimate (same as estimated_keyspace_bits)
        est_range = observed_range * (n + 1) / (n - 1)
        point = math.log2(est_range)

        # Exact Beta(n-1, 2) moments for W/R, then delta method to ln(R̂)
        a, b = n - 1, 2
        mean_ratio = a / (a + b)                              # = (n-1)/(n+1)
        var_ratio = (a * b) / ((a + b) ** 2 * (a + b + 1))     # Var(W/R)
        var_ln_r = var_ratio / (mean_ratio ** 2)               # delta method
        sd_bits = math.sqrt(var_ln_r) / math.log(2)

        # Normal quantile (two-sided).  For 95 % we use the conventional 1.96.
        # General formula: erfinv(confidence) * √2, but we keep a small table
        # for the common levels used in security tooling.
        z = {
            0.90: 1.645,
            0.95: 1.960,
            0.99: 2.576,
        }.get(round(confidence, 2), 1.960)

        half = z * sd_bits
        lower = max(0.0, point - half)
        upper = point + half
        return (point, lower, upper)

    # ------------------------------------------------------------------
    # 5. Structural / templated-ID signal (prefix + varying suffix)
    # ------------------------------------------------------------------
    @staticmethod
    def longest_common_prefix(strings: Sequence[str]) -> str:
        """
        Longest common prefix of a sequence of strings.

        Returns the empty string if the sequence is empty or the strings
        share no common prefix.  Used as the structural signal that pure
        per-character entropy misses: a fixed, predictable prefix (e.g.
        "bookTitle") followed by a small varying suffix is highly
        guessable even when whole-string entropy looks healthy.
        """
        if not strings:
            return ""
        strs = [str(s) for s in strings if str(s)]
        if not strs:
            return ""
        prefix = strs[0]
        for s in strs[1:]:
            while not s.startswith(prefix) and prefix:
                prefix = prefix[:-1]
            if not prefix:
                break
        return prefix

    @staticmethod
    def decompose_template(ids: Sequence[Union[str, int]]) -> dict:
        """
        Pure structural decomposition: splits the sample into its shared
        longest-common-prefix and each ID's varying remainder. No security
        judgment is made here — the same split MathCore keeps everywhere
        else (estimated_keyspace_bits and sequential_score both return
        bare numbers; the rule decides what counts as "too predictable").

        `suffixes_numeric` is the varying remainders parsed as integers
        (via parse_numeric_ids), or None if any remainder isn't purely
        numeric (or any is empty). That's the signal a rule uses to pick
        the right tool for the remainder: keyspace_bits_ci — the same
        order-statistics estimator already used for plain numeric IDs —
        measures true cardinality and gives a confidence interval,
        neither of which a short suffix's character entropy actually
        provides (character entropy only correlates with true keyspace
        size for numeric strings by structural coincidence — both scale
        with digit-string length — not because it measures the same
        thing). Entropy-on-the-remainder-only remains the right tool
        when the remainder isn't numeric.
        """
        str_ids = [str(s) for s in ids]
        if len(str_ids) < 2:
            return {
                "common_prefix": "",
                "prefix_length": 0,
                "avg_fixed_fraction": 0.0,
                "suffixes": [],
                "suffixes_numeric": None,
            }

        prefix = MathCore.longest_common_prefix(str_ids)
        plen = len(prefix)
        suffixes = [s[plen:] for s in str_ids]
        fixed_fractions = [plen / len(s) if len(s) > 0 else 0.0 for s in str_ids]
        avg_fixed = sum(fixed_fractions) / len(fixed_fractions)
        suffixes_numeric = MathCore.parse_numeric_ids(suffixes) if all(suffixes) else None

        return {
            "common_prefix": prefix,
            "prefix_length": plen,
            "avg_fixed_fraction": round(avg_fixed, 3),
            "suffixes": suffixes,
            "suffixes_numeric": suffixes_numeric,
        }
