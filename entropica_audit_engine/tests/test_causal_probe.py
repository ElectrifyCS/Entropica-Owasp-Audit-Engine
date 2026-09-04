"""
Tests for core/causal_probe.py.

Three layers, deliberately:
  1. The regularized incomplete beta function against exact closed-form
     values (df=1 Cauchy, df=2 closed form) — if this is wrong, every
     p-value downstream is silently wrong in a way no "does it run"
     test would catch.
  2. CausalProbe against constructed distributions where the right
     answer is known by construction (identical distributions -> not
     significant; a large mean shift -> significant).
  3. Edge cases: too few samples, zero variance, condition == control.
"""
from __future__ import annotations

import math
import random

import pytest

from entropica_audit_engine.core.causal_probe import (
    CausalProbe,
    regularized_incomplete_beta,
    student_t_two_sided_p,
)


class TestIncompleteBetaExactValues:
    def test_beta_1_1_is_identity(self):
        # Beta(1,1) = Uniform(0,1), so I_x(1,1) = x exactly.
        for x in (0.0, 0.1, 0.37, 0.5, 0.99, 1.0):
            assert regularized_incomplete_beta(x, 1, 1) == pytest.approx(x, abs=1e-9)

    def test_boundary_values(self):
        assert regularized_incomplete_beta(0.0, 3, 5) == 0.0
        assert regularized_incomplete_beta(1.0, 3, 5) == 1.0

    def test_symmetry_identity(self):
        # I_x(a,b) = 1 - I_{1-x}(b,a) for any valid x, a, b.
        for x, a, b in [(0.2, 2, 3), (0.6, 5, 1.5), (0.9, 0.5, 4)]:
            lhs = regularized_incomplete_beta(x, a, b)
            rhs = 1 - regularized_incomplete_beta(1 - x, b, a)
            assert lhs == pytest.approx(rhs, abs=1e-9)


class TestStudentTExactValues:
    def test_df1_is_standard_cauchy(self):
        # Student's t with df=1 IS the standard Cauchy distribution.
        # P(|T| > 1) = 0.5 exactly for standard Cauchy.
        assert student_t_two_sided_p(1.0, 1) == pytest.approx(0.5, abs=1e-9)

    def test_df2_closed_form(self):
        # df=2 has a closed form: P(|T|>t) = 1 - t/sqrt(2+t^2)
        for t in (0.5, 1.0, 2.0, 3.5):
            expected = 1 - t / math.sqrt(2 + t * t)
            assert student_t_two_sided_p(t, 2) == pytest.approx(expected, abs=1e-9)

    def test_matches_standard_t_table_critical_values(self):
        # Two-sided alpha=0.05 critical t-values from any standard table.
        table = {1: 12.706, 5: 2.571, 10: 2.228, 30: 2.042}
        for df, t_crit in table.items():
            p = student_t_two_sided_p(t_crit, df)
            assert p == pytest.approx(0.05, abs=0.001)

    def test_large_df_approaches_normal(self):
        # As df -> infinity, Student's t -> standard normal.
        # z=1.96 two-sided normal p-value is ~0.05.
        assert student_t_two_sided_p(1.96, 1_000_000) == pytest.approx(0.05, abs=1e-3)

    def test_t_zero_gives_p_one(self):
        assert student_t_two_sided_p(0.0, 10) == pytest.approx(1.0, abs=1e-9)


class TestCausalProbeConstructedCases:
    def test_identical_distributions_not_significant(self):
        # Same generator, same seed offset removed -> genuinely no effect.
        rng = random.Random(1)
        probe = CausalProbe(control_label="control", alpha=0.05, min_samples=5)
        for _ in range(200):
            probe.observe("control", rng.gauss(100.0, 5.0))
        rng2 = random.Random(2)  # different seed, same distribution
        for _ in range(200):
            probe.observe("same_dist", rng2.gauss(100.0, 5.0))

        effect = probe.effect("same_dist")
        assert effect is not None
        assert effect.significant is False

    def test_large_mean_shift_is_significant(self):
        # A real, large, sustained shift (the SSRF case: hitting an
        # internal host is genuinely slower) should be caught easily.
        rng = random.Random(1)
        probe = CausalProbe(control_label="control", alpha=0.05, min_samples=5)
        for _ in range(50):
            probe.observe("control", rng.gauss(50.0, 5.0))     # external host: fast
        for _ in range(50):
            probe.observe("internal", rng.gauss(500.0, 5.0))   # internal host: slow

        effect = probe.effect("internal")
        assert effect is not None
        assert effect.significant is True
        assert effect.delta == pytest.approx(450.0, abs=5.0)
        assert effect.p_value_two_sided < 0.001

    def test_tiny_noise_level_shift_not_significant_at_low_n(self):
        # A shift that's small relative to noise, with few samples,
        # should honestly report "not enough evidence" rather than a
        # false positive.
        rng = random.Random(3)
        probe = CausalProbe(control_label="control", min_samples=5)
        for _ in range(5):
            probe.observe("control", rng.gauss(100.0, 20.0))
        for _ in range(5):
            probe.observe("noisy_cond", rng.gauss(103.0, 20.0))

        effect = probe.effect("noisy_cond")
        assert effect is not None
        assert effect.significant is False


class TestCausalProbeEdgeCases:
    def test_returns_none_below_min_samples(self):
        probe = CausalProbe(min_samples=5)
        probe.observe("control", 1.0)
        probe.observe("control", 2.0)
        probe.observe("cond", 1.0)
        probe.observe("cond", 2.0)
        assert probe.effect("cond") is None

    def test_returns_none_for_control_label_itself(self):
        probe = CausalProbe(control_label="control", min_samples=2)
        for v in (1.0, 2.0, 3.0):
            probe.observe("control", v)
        assert probe.effect("control") is None

    def test_returns_none_for_unobserved_condition(self):
        probe = CausalProbe(min_samples=2)
        for v in (1.0, 2.0, 3.0):
            probe.observe("control", v)
        assert probe.effect("never_observed") is None

    def test_identical_constant_values_no_crash_no_false_positive(self):
        # Zero variance in both conditions, but same value -> se_sq=0.
        # Must not divide by zero; must report "no difference", not a
        # spurious significant result.
        probe = CausalProbe(min_samples=5)
        for _ in range(10):
            probe.observe("control", 42.0)
            probe.observe("cond", 42.0)
        effect = probe.effect("cond")
        assert effect is not None
        assert effect.significant is False
        assert effect.delta == 0.0

    def test_rejects_bad_alpha_and_min_samples(self):
        with pytest.raises(ValueError):
            CausalProbe(alpha=0.0)
        with pytest.raises(ValueError):
            CausalProbe(alpha=1.0)
        with pytest.raises(ValueError):
            CausalProbe(min_samples=1)

    def test_all_effects_skips_control_and_underpowered_conditions(self):
        probe = CausalProbe(control_label="control", min_samples=5)
        for _ in range(10):
            probe.observe("control", 10.0)
            probe.observe("enough_samples", 50.0)
        probe.observe("too_few_samples", 99.0)  # only 1 observation

        effects = probe.all_effects()
        assert "control" not in effects
        assert "enough_samples" in effects
        assert "too_few_samples" not in effects
