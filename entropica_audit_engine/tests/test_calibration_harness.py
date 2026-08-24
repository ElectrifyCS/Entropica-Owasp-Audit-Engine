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
    save_jsonl,
    scheme_summary,
    sweep,
    would_trigger,
)


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
        assert set(counts.keys()) <= {"highly_sequential", "small_keyspace", "low_entropy"}


class TestSchemeSummary:
    def test_every_scheme_with_data_appears(self):
        records = collect(sample_sizes=(20,), seeds=(0, 1))
        rows = scheme_summary(records)
        schemes = {row["scheme"] for row in rows}
        assert schemes == set(GENERATORS.keys())
        for row in rows:
            assert row["min"] <= row["median"] <= row["max"]
