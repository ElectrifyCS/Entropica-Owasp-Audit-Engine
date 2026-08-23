"""
Unit tests for ExcessiveDataExposureRule (API3:2023).
"""

import asyncio
import uuid

import pytest

from entropica_audit_engine.rules.excessive_data import ExcessiveDataExposureRule


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def rule():
    return ExcessiveDataExposureRule()


class TestNotEnoughEvidence:
    def test_too_few_values_returns_none(self, rule):
        finding = run(rule.execute("https://api.example.com/x", sample_values=[1, 2]))
        assert finding is None


class TestNumericFieldValues:
    def test_sequential_values_flagged(self, rule):
        values = list(range(3001, 3015))
        finding = run(rule.execute("https://api.example.com/orders", sample_values=values))
        assert finding is not None
        assert "highly_sequential" in finding.metrics["triggered_by"]

    def test_small_keyspace_flagged(self, rule):
        import random
        random.seed(7)
        values = [str(random.randint(1000, 9999)) for _ in range(12)]
        finding = run(rule.execute("https://api.example.com/items", sample_values=values))
        assert finding is not None
        assert "small_keyspace" in finding.metrics["triggered_by"]
        assert "keyspace_bits_ci_95" in finding.metrics


class TestNonNumericFieldValues:
    def test_low_entropy_tokens_flagged(self, rule):
        # Highly repetitive short tokens — entropy stays low even after
        # Miller–Madow correction.
        values = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5", "aaaa6"]
        finding = run(rule.execute("https://api.example.com/profile", sample_values=values))
        assert finding is not None
        assert "low_entropy" in finding.metrics["triggered_by"]
        assert finding.metrics["estimator"] == "miller_madow"

    def test_random_uuids_not_flagged(self, rule):
        values = [str(uuid.uuid4()) for _ in range(10)]
        finding = run(rule.execute("https://api.example.com/sessions", sample_values=values))
        assert finding is None


class TestMultiField:
    def test_field_samples_aggregates_offenders(self, rule):
        field_samples = {
            "safe_uuid": [str(uuid.uuid4()) for _ in range(6)],
            "leaky_seq": list(range(100, 115)),
        }
        finding = run(
            rule.execute("https://api.example.com/mixed", field_samples=field_samples)
        )
        assert finding is not None
        assert finding.evidence["offending_field_count"] == 1
        assert "leaky_seq" in finding.evidence["fields"]
