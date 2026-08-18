"""
Unit tests for PredictableResourceIDRule (ENTROPICA API1:2023 – BOLA).

These specifically target the numeric-vs-entropy branching added to fix
two issues found during review:
  1. Per-character entropy is non-discriminating for purely-numeric IDs
     (capped at log2(10) bits regardless of true keyspace size).
  2. sequential_score used to depend on collection order, not ID value.
"""

import asyncio
import uuid

import pytest

from entropica_audit_engine.rules.bola import PredictableResourceIDRule


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def rule():
    return PredictableResourceIDRule()


class TestNotEnoughEvidence:
    def test_too_few_ids_returns_none(self, rule):
        finding = run(rule.execute("https://api.example.com/x/{id}", sample_ids=[1, 2]))
        assert finding is None


class TestNumericIDs:
    def test_sequential_ids_flagged(self, rule):
        ids = list(range(2001, 2015))
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=ids))
        assert finding is not None
        assert "highly_sequential" in finding.metrics["triggered_by"]
        assert finding.evidence["id_scheme"] == "numeric"

    def test_sequential_ids_flagged_regardless_of_collection_order(self, rule):
        shuffled = [2007, 2001, 2013, 2003, 2011, 2005, 2009, 2002, 2014, 2004, 2010, 2006, 2012, 2008]
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=shuffled))
        assert finding is not None
        assert "highly_sequential" in finding.metrics["triggered_by"]

    def test_small_keyspace_numeric_ids_flagged(self, rule):
        # Not sequential, but drawn from only ~90,000 possible values.
        import random
        random.seed(7)
        ids = [str(random.randint(10_000, 99_999)) for _ in range(12)]
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=ids))
        assert finding is not None
        assert "small_keyspace" in finding.metrics["triggered_by"]

    def test_large_keyspace_numeric_ids_not_flagged(self, rule):
        # ~9.9 billion possible values, not sequential — should clear.
        import random
        random.seed(11)
        ids = [str(random.randint(1_000_000_000, 9_999_999_999)) for _ in range(12)]
        finding = run(rule.execute("https://api.example.com/accounts/{id}", sample_ids=ids))
        assert finding is None


class TestNonNumericIDs:
    def test_random_uuids_not_flagged(self, rule):
        ids = [str(uuid.uuid4()) for _ in range(10)]
        finding = run(rule.execute("https://api.example.com/users/{id}", sample_ids=ids))
        assert finding is None

    def test_low_entropy_tokens_flagged(self, rule):
        # Short, low-alphabet, repetitive tokens.
        ids = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5"]
        finding = run(rule.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        assert finding is not None
        assert "low_entropy" in finding.metrics["triggered_by"]
        assert finding.evidence["id_scheme"] == "non-numeric"
