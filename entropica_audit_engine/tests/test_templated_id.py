"""
Tests for core/templated_id.py — the shared measurement/decision module
used by both rules/bola.py and calibration/harness.py.
"""
from __future__ import annotations

from entropica_audit_engine.core.templated_id import (
    measure_templated_id,
    templated_id_triggered,
)

DEFAULT_THRESHOLDS = dict(entropy_threshold=3.0, sequential_threshold=0.7, keyspace_bit_threshold=32.0)


class TestMeasureTemplatedId:
    def test_book_title_pattern_numeric_suffix(self):
        ids = ["bookTitle7", "bookTitle38", "bookTitle17", "bookTitle42"]
        m = measure_templated_id(ids)
        assert m["has_template"] is True
        assert m["common_prefix"] == "bookTitle"
        assert m["suffix_kind"] == "numeric"
        assert m["suffix_keyspace_bits"] is not None
        assert m["suffix_keyspace_bits_ci_95"] is not None
        assert m["suffix_entropy_bits"] is None  # not computed for the numeric branch

    def test_non_numeric_enum_suffix(self):
        ids = ["session-prod", "session-stag", "session-test", "session-perf"]
        m = measure_templated_id(ids)
        assert m["has_template"] is True
        assert m["suffix_kind"] == "non-numeric"
        assert m["suffix_entropy_bits"] is not None
        assert m["suffix_keyspace_bits"] is None  # not computed for the non-numeric branch

    def test_no_template_returns_all_none(self):
        ids = [
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
        ]
        m = measure_templated_id(ids)
        assert m["has_template"] is False
        assert m["suffix_kind"] is None
        assert m["suffix_keyspace_bits"] is None
        assert m["suffix_entropy_bits"] is None

    def test_min_prefix_len_and_fixed_fraction_are_respected(self):
        ids = ["bookTitle7", "bookTitle38", "bookTitle17"]
        # A very long required prefix should suppress detection even
        # though the actual prefix ("bookTitle", 9 chars) is real.
        m = measure_templated_id(ids, min_prefix_len=20)
        assert m["has_template"] is False

        # A very high fixed-fraction requirement should do the same.
        m2 = measure_templated_id(ids, min_fixed_fraction=0.99)
        assert m2["has_template"] is False


class TestTemplatedIdTriggered:
    def test_small_numeric_keyspace_triggers(self):
        m = measure_templated_id(["order-7", "order-38", "order-17", "order-42"])
        assert templated_id_triggered(m, **DEFAULT_THRESHOLDS) is True

    def test_large_numeric_keyspace_does_not_trigger(self):
        ids = [
            "txn-0593469561024", "txn-0078385080571", "txn-0038720616736",
            "txn-0912233445566", "txn-0567890123456",
        ]
        m = measure_templated_id(ids)
        assert templated_id_triggered(m, **DEFAULT_THRESHOLDS) is False

    def test_low_entropy_non_numeric_suffix_triggers(self):
        m = measure_templated_id(["session-prod", "session-stag", "session-test", "session-perf"])
        assert templated_id_triggered(m, **DEFAULT_THRESHOLDS) is True

    def test_no_template_never_triggers_regardless_of_thresholds(self):
        m = measure_templated_id(["alpha", "beta", "gamma"])
        # Even absurdly permissive thresholds shouldn't trigger a
        # structural signal that was never detected in the first place.
        assert templated_id_triggered(
            m, entropy_threshold=100.0, sequential_threshold=0.0, keyspace_bit_threshold=1000.0
        ) is False

    def test_threshold_sweep_changes_verdict_on_same_stored_measurement(self):
        # This is the whole point of separating measure/decide: the exact
        # same measured dict should give different verdicts as the
        # threshold is swept, without re-measuring anything.
        m = measure_templated_id(["order-7", "order-38", "order-17", "order-42"])
        bits = m["suffix_keyspace_bits"]
        assert templated_id_triggered(
            m, entropy_threshold=3.0, sequential_threshold=0.7, keyspace_bit_threshold=bits - 1
        ) is False
        assert templated_id_triggered(
            m, entropy_threshold=3.0, sequential_threshold=0.7, keyspace_bit_threshold=bits + 1
        ) is True


class TestBolaAndHarnessAgree:
    """
    The actual guarantee this module exists to provide: bola.py's rule
    and a harness-style caller, given the same sample and the same
    thresholds, must reach the identical verdict - by construction,
    since both now call the same two functions, not by coincidence.
    """

    def test_identical_verdict_via_rule_and_via_shared_module_directly(self):
        import asyncio
        from entropica_audit_engine.rules.bola import PredictableResourceIDRule

        ids = ["bookTitle7", "bookTitle38", "bookTitle17", "bookTitle42"]
        rule = PredictableResourceIDRule()
        finding = asyncio.run(rule.execute("https://x/{id}", sample_ids=ids))

        m = measure_templated_id(
            ids,
            min_prefix_len=rule.min_prefix_len,
            min_fixed_fraction=rule.min_fixed_fraction,
            use_miller_madow=rule.use_miller_madow,
        )
        direct_verdict = templated_id_triggered(
            m,
            entropy_threshold=rule.entropy_threshold,
            sequential_threshold=rule.sequential_threshold,
            keyspace_bit_threshold=rule.keyspace_bit_threshold,
        )

        assert finding is not None
        assert "templated_id" in finding.metrics["triggered_by"]
        assert direct_verdict is True
        assert finding.metrics["suffix_keyspace_bits"] == m["suffix_keyspace_bits"]
