"""
Unit tests for Miller–Madow entropy, keyspace CI, and EWMA tracker.
"""

import math
import pytest

from entropica_audit_engine.core.math_core import MathCore
from entropica_audit_engine.core.welford import WelfordTracker, EWMAAnomalyTracker


class TestMillerMadow:
    def test_empty(self):
        assert MathCore.miller_madow_entropy("") == 0.0

    def test_single_symbol_zero(self):
        # Plugin is 0; correction is (1-1)/(...) = 0
        assert MathCore.miller_madow_entropy("aaaa") == 0.0

    def test_correction_positive(self):
        # Any multi-symbol sample should have MM >= plugin
        data = "aabbcc"
        h_plugin = MathCore.shannon_entropy(data)
        h_mm = MathCore.miller_madow_entropy(data)
        assert h_mm >= h_plugin

    def test_large_n_converges(self):
        # For large uniform samples the correction vanishes
        data = "abcd" * 500
        h_plugin = MathCore.shannon_entropy(data)
        h_mm = MathCore.miller_madow_entropy(data)
        assert math.isclose(h_plugin, h_mm, abs_tol=0.01)


class TestKeyspaceCI:
    def test_non_numeric_returns_none(self):
        assert MathCore.keyspace_bits_ci(["a", "b", "c"]) is None

    def test_too_few_returns_none(self):
        assert MathCore.keyspace_bits_ci([1, 2]) is None

    def test_ci_contains_point(self):
        ids = [10, 20, 30, 40, 50, 60, 70]
        ci = MathCore.keyspace_bits_ci(ids)
        assert ci is not None
        point, lo, hi = ci
        assert lo <= point <= hi
        assert lo >= 0.0

    def test_small_keyspace_ci_low(self):
        import random
        random.seed(7)
        ids = [random.randint(10_000, 99_999) for _ in range(12)]
        ci = MathCore.keyspace_bits_ci(ids)
        assert ci is not None
        point, lo, hi = ci
        assert point < 20.0  # well under 32-bit threshold

    def test_ci_width_shrinks_faster_than_naive_1_over_sqrt_n(self):
        # Regression test: an earlier draft used Var(ln R_hat) ~ 2/n, a
        # central-limit-style guess that overstates uncertainty by ~sqrt(n).
        # The correct model (exact Beta(n-1, 2) moments for the scaled
        # range, via the delta method) gives Var(ln R_hat) ~ 2/n^2, so the
        # interval should tighten roughly like 1/n as n grows, not 1/sqrt(n).
        import random

        def width(n, seed):
            random.seed(seed)
            ids = [random.randint(0, 1_000_000) for _ in range(n)]
            ci = MathCore.keyspace_bits_ci(ids)
            assert ci is not None
            point, lo, hi = ci
            return hi - lo

        w_small = width(10, seed=1)
        w_large = width(100, seed=1)
        naive_ratio = math.sqrt(10)  # what a 1/sqrt(n) scaling would predict
        # The actual shrinkage (n=10 -> n=100, a 10x increase in n) should be
        # noticeably steeper than the naive sqrt(n) prediction.
        assert w_small / w_large > naive_ratio


class TestEWMA:
    def test_constant_z_decays_toward_abs_z(self):
        ewma = EWMAAnomalyTracker(lambda_=0.3, threshold=10.0, min_count=1)
        for _ in range(30):
            ewma.update(2.0)
        # Should converge near |2.0|
        assert abs(ewma.S - 2.0) < 0.1

    def test_sustained_high_z_triggers(self):
        ewma = EWMAAnomalyTracker(lambda_=0.3, threshold=2.5, min_count=5)
        # Feed moderate then high absolute z-scores
        for z in [0.5, 0.6, 0.4, 0.5, 0.7, 4.0, 4.2, 3.8, 4.1, 3.9]:
            ewma.update(z)
        assert ewma.is_anomaly()

    def test_single_spike_may_not_trigger(self):
        ewma = EWMAAnomalyTracker(lambda_=0.2, threshold=3.0, min_count=5)
        for z in [0.5, 0.4, 0.6, 0.5, 0.3, 5.0, 0.4, 0.5]:
            ewma.update(z)
        # Depending on lambda the single spike may or may not push S over
        # the threshold; we only require that the tracker remains consistent.
        assert ewma.count == 8

    def test_reset(self):
        ewma = EWMAAnomalyTracker()
        ewma.update(3.0)
        ewma.reset()
        assert ewma.count == 0
        assert ewma.S == 0.0
