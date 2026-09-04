import tempfile
from pathlib import Path

import pytest

from entropica_audit_engine.calibration.generators import GENERATORS
from entropica_audit_engine.calibration.harness import (
    CalibrationRecord,
    collect,
    confusion,
    decisive_signal_counts,
    load_jsonl,
    records_from_samples,
    render_markdown,
    save_jsonl,
    scheme_summary,
    sweep,
    would_trigger,
)


class TestTemplatedIdWiring:
    """
    The calibration harness's half of the templated-ID signal
    (core/templated_id.py) — populated by records_from_samples, decided
    by would_trigger, surfaced correctly (not misleadingly) by
    scheme_summary.
    """

    def test_templated_numeric_scheme_populates_suffix_fields(self):
        samples, label = GENERATORS["templated_numeric_suffix_small"](20, seed=0)
        r = records_from_samples("templated_numeric_suffix_small", samples, label, seed=0)
        assert r.has_template is True
        assert r.suffix_kind == "numeric"
        assert r.suffix_keyspace_bits is not None
        assert r.suffix_keyspace_ci_lower is not None
        assert r.suffix_entropy_mm is None  # not the branch that ran

    def test_templated_enum_scheme_populates_suffix_entropy(self):
        samples, label = GENERATORS["templated_enum_suffix"](20, seed=0)
        r = records_from_samples("templated_enum_suffix", samples, label, seed=0)
        assert r.has_template is True
        assert r.suffix_kind == "non-numeric"
        assert r.suffix_entropy_mm is not None
        assert r.suffix_keyspace_bits is None

    def test_would_trigger_flags_small_templated_keyspace(self):
        samples, label = GENERATORS["templated_numeric_suffix_small"](20, seed=0)
        r = records_from_samples("templated_numeric_suffix_small", samples, label, seed=0)
        triggered, triggered_by = would_trigger(r)
        assert triggered is True
        assert "templated_id" in triggered_by

    def test_would_trigger_does_not_flag_large_templated_keyspace(self):
        samples, label = GENERATORS["templated_numeric_suffix_large"](20, seed=0)
        r = records_from_samples("templated_numeric_suffix_large", samples, label, seed=0)
        triggered, triggered_by = would_trigger(r)
        assert "templated_id" not in triggered_by

    def test_would_trigger_threshold_sweep_changes_verdict(self):
        # Same stored record, no re-measurement - exactly what a sweep
        # depends on being possible.
        samples, label = GENERATORS["templated_numeric_suffix_small"](20, seed=0)
        r = records_from_samples("templated_numeric_suffix_small", samples, label, seed=0)
        bits = r.suffix_keyspace_bits
        _, low = would_trigger(r, keyspace_bit_threshold=bits - 1)
        _, high = would_trigger(r, keyspace_bit_threshold=bits + 1)
        assert "templated_id" not in low
        assert "templated_id" in high

    def test_scheme_summary_shows_suffix_metric_not_whole_string_entropy(self):
        # Regression test: scheme_summary used to always fall back to
        # whole-string entropy for any non-numeric id_type, including
        # templated schemes - showing a healthy-looking number (e.g.
        # 3.8 bits) that had nothing to do with why the scheme was
        # actually flagged (a 6-bit suffix keyspace). Found by reading
        # actual report output, not assumed.
        records = collect(sample_sizes=(20,), seeds=(0,))
        rows = {row["scheme"]: row for row in scheme_summary(records)}

        small = rows["templated_numeric_suffix_small"]
        assert small["metric"] == "suffix_keyspace_bits (templated)"
        assert small["mean"] < 32.0  # the actual reason it's vulnerable

        large = rows["templated_numeric_suffix_large"]
        assert large["metric"] == "suffix_keyspace_bits (templated)"
        assert large["mean"] > 32.0  # the actual reason it's safe

        enum_row = rows["templated_enum_suffix"]
        assert enum_row["metric"] == "suffix_entropy_bits_mm (templated)"

    def test_full_collect_run_does_not_crash_with_new_generators(self):
        records = collect(sample_sizes=(5, 20), seeds=(0, 1))
        schemes = {r.scheme for r in records}
        assert "templated_numeric_suffix_small" in schemes
        assert "templated_numeric_suffix_large" in schemes
        assert "templated_enum_suffix" in schemes
        # And the report renders without raising.
        text = render_markdown(records)
        assert "templated_numeric_suffix_small" in text


class TestRecordsFromSamples:
    def test_numeric_scheme_populates_keyspace_fields(self):
        samples, label = GENERATORS["auto_increment"](10, seed=0)
        r = records_from_samples("auto_increment", samples, label, seed=0)
        assert r.id_type == "numeric"
        assert r.estimated_keyspace_bits is not None
        assert r.keyspace_ci_lower is not None
        assert r.avg_entropy_mm is None

    def test_non_numeric_scheme_populates_entropy_fields(self):
        samples, label = GENERATORS["uuidv4"](10, seed=0)
        r = records_from_samples("uuidv4", samples, label, seed=0)
        assert r.id_type == "non-numeric"
        assert r.avg_entropy_mm is not None
        assert r.avg_entropy_plugin is not None
        assert r.estimated_keyspace_bits is None

    def test_mm_entropy_is_never_below_plugin_on_same_sample(self):
        samples, label = GENERATORS["base62_token"](8, seed=3)
        r = records_from_samples("base62_token", samples, label, seed=3)
        assert r.avg_entropy_mm >= r.avg_entropy_plugin


class TestCollect:
    def test_collect_covers_every_generator_size_and_seed(self):
        records = collect(sample_sizes=(5, 10), seeds=(0, 1))
        assert len(records) == len(GENERATORS) * 2 * 2
        schemes = {r.scheme for r in records}
        assert schemes == set(GENERATORS.keys())


class TestPersistence:
    def test_save_and_load_round_trip(self):
        records = collect(sample_sizes=(5,), seeds=(0,))
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "records.jsonl")
            save_jsonl(records, path)
            loaded = load_jsonl(path)
        assert len(loaded) == len(records)
        assert loaded[0] == records[0]


class TestWouldTrigger:
    def test_vulnerable_auto_increment_triggers_at_default_thresholds(self):
        samples, label = GENERATORS["auto_increment"](10, seed=0)
        r = records_from_samples("auto_increment", samples, label, seed=0)
        triggered, signals = would_trigger(r)
        assert triggered is True
        assert "highly_sequential" in signals

    def test_safe_uuid_does_not_trigger_at_default_thresholds(self):
        samples, label = GENERATORS["uuidv4"](20, seed=0)
        r = records_from_samples("uuidv4", samples, label, seed=0)
        triggered, _ = would_trigger(r)
        assert triggered is False

    def test_use_mm_false_falls_back_to_plugin_entropy(self):
        samples, label = GENERATORS["predictable_session_token"](10, seed=0)
        r = records_from_samples("predictable_session_token", samples, label, seed=0)
        _, signals_mm = would_trigger(r, use_mm=True)
        _, signals_plugin = would_trigger(r, use_mm=False)
        # Both should flag low_entropy here (token is very repetitive either
        # way) — this just confirms the flag actually switches which stored
        # field gets read, not that outcomes always differ.
        assert "low_entropy" in signals_mm
        assert "low_entropy" in signals_plugin


class TestConfusionAndSweep:
    def test_confusion_excludes_mixed_and_unknown(self):
        records = [
            CalibrationRecord(
                scheme="x", label="mixed", n=5, seed=0, id_type="numeric",
                sequential_score=1.0, estimated_keyspace_bits=10.0,
            ),
            CalibrationRecord(
                scheme="y", label="unknown", n=5, seed=0, id_type="numeric",
                sequential_score=1.0, estimated_keyspace_bits=10.0,
            ),
        ]
        c = confusion(records)
        assert c.tp == c.fp == c.tn == c.fn == 0
        assert c.excluded_mixed == 1
        assert c.excluded_unknown == 1

    def test_confusion_counts_tp_and_tn_on_clear_cases(self):
        records = collect(sample_sizes=(20,), seeds=(0, 1, 2))
        c = confusion(records)
        # auto_increment (vulnerable) and uuidv4 (safe) are unambiguous
        # regardless of threshold — at minimum both classes should be
        # represented once thresholds are at rule defaults.
        assert c.tp > 0
        assert c.tn > 0

    def test_sweep_raising_entropy_threshold_never_decreases_tpr(self):
        records = collect(sample_sizes=(20,), seeds=(0, 1, 2))
        rows = sweep(records, "entropy_threshold", [1.0, 2.0, 3.0, 4.0, 5.0])
        tprs = [r["tpr"] for r in rows if r["tpr"] is not None]
        # Raising the entropy threshold only ever flags MORE things as
        # low-entropy, so true-positive rate is monotonically non-decreasing.
        assert tprs == sorted(tprs)

    def test_sweep_raising_entropy_threshold_never_decreases_fpr(self):
        records = collect(sample_sizes=(20,), seeds=(0, 1, 2))
        rows = sweep(records, "entropy_threshold", [1.0, 2.0, 3.0, 4.0, 5.0])
        fprs = [r["fpr"] for r in rows if r["fpr"] is not None]
        assert fprs == sorted(fprs)


class TestDecisiveSignalCounts:
    def test_counts_only_vulnerable_records(self):
        records = collect(sample_sizes=(20,), seeds=(0,))
        counts = decisive_signal_counts(records)
        assert sum(counts.values()) > 0
        assert set(counts.keys()) <= {
            "highly_sequential", "small_keyspace", "low_entropy", "templated_id",
        }


class TestSchemeSummary:
    def test_every_scheme_with_data_appears(self):
        records = collect(sample_sizes=(20,), seeds=(0, 1))
        rows = scheme_summary(records)
        schemes = {row["scheme"] for row in rows}
        assert schemes == set(GENERATORS.keys())
        for row in rows:
            assert row["min"] <= row["median"] <= row["max"]
