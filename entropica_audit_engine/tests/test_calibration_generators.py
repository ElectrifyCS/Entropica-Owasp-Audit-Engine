import uuid

import pytest

from entropica_audit_engine.calibration.generators import GENERATORS
from entropica_audit_engine.core.math_core import MathCore


class TestGeneratorContract:
    """Every generator must obey the same shape, regardless of scheme."""

    @pytest.mark.parametrize("name", list(GENERATORS.keys()))
    def test_returns_n_samples_and_valid_label(self, name):
        gen = GENERATORS[name]
        samples, label = gen(10, seed=0)
        assert len(samples) == 10
        assert label in ("safe", "vulnerable", "mixed")

    @pytest.mark.parametrize("name", list(GENERATORS.keys()))
    def test_reproducible_given_same_seed(self, name):
        gen = GENERATORS[name]
        a, label_a = gen(20, seed=42)
        b, label_b = gen(20, seed=42)
        assert a == b
        assert label_a == label_b

    def test_time_based_schemes_reproducible_across_real_delay(self):
        """
        snowflake_like and ulid_like previously built their timestamp
        component from time.time(), which made
        test_reproducible_given_same_seed pass by accident — both calls
        in that test land in the same millisecond, so the bug never
        showed up there. Sleeping between calls here is what actually
        exercises the "reproducible" claim.
        """
        import time as time_module

        for name in ("snowflake_like", "ulid_like"):
            gen = GENERATORS[name]
            a, _ = gen(10, seed=7)
            time_module.sleep(0.01)
            b, _ = gen(10, seed=7)
            assert a == b, f"{name} is not reproducible across a real time delay"

    @pytest.mark.parametrize("name", list(GENERATORS.keys()))
    def test_different_seeds_differ(self, name):
        gen = GENERATORS[name]
        a, _ = gen(20, seed=1)
        b, _ = gen(20, seed=2)
        assert a != b


class TestLabelSemantics:
    """Ground-truth labels must actually match what the generator produces —
    a mislabeled generator would silently corrupt every downstream TP/FP
    count, so these are checked against MathCore directly, not just
    against the generator's own docstring claim."""

    def test_auto_increment_is_labeled_vulnerable_and_is_sequential(self):
        samples, label = GENERATORS["auto_increment"](10, seed=0)
        assert label == "vulnerable"
        assert MathCore.sequential_score(samples) == 1.0

    def test_large_random_int_is_labeled_safe_and_has_large_keyspace(self):
        samples, label = GENERATORS["large_random_int"](10, seed=0)
        assert label == "safe"
        bits = MathCore.estimated_keyspace_bits(samples)
        assert bits is not None and bits > 32.0

    def test_uuidv4_produces_valid_uuids(self):
        samples, label = GENERATORS["uuidv4"](10, seed=0)
        assert label == "safe"
        for s in samples:
            parsed = uuid.UUID(s)
            assert parsed.version == 4

    def test_predictable_session_token_is_low_entropy(self):
        samples, label = GENERATORS["predictable_session_token"](10, seed=0)
        assert label == "vulnerable"
        avg = sum(MathCore.miller_madow_entropy(str(s)) for s in samples) / len(samples)
        assert avg < 3.0

    def test_snowflake_and_ulid_are_mixed_not_binary(self):
        _, snowflake_label = GENERATORS["snowflake_like"](10, seed=0)
        _, ulid_label = GENERATORS["ulid_like"](10, seed=0)
        assert snowflake_label == "mixed"
        assert ulid_label == "mixed"
