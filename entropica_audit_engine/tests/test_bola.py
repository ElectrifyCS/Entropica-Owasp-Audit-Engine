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


class TestEstimatorChoice:
    """
    BOLA is the rule most likely to run on small samples (n=5-50), which is
    exactly the regime where the plugin entropy estimator is negatively
    biased (see MathCore.miller_madow_entropy). These tests pin down that
    Miller-Madow is actually used by default here, not just in
    ExcessiveDataExposureRule — a prior version silently used the plugin
    estimator in this rule while the newer rule had already switched.
    """

    def test_miller_madow_is_default_and_recorded_in_metrics(self):
        rule = PredictableResourceIDRule()
        assert rule.use_miller_madow is True
        ids = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5"]
        finding = run(rule.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        assert finding is not None
        assert finding.metrics["estimator"] == "miller_madow"

    def test_miller_madow_entropy_is_not_less_than_plugin_entropy(self):
        # Miller-Madow adds a non-negative correction term, so on the same
        # small sample it should never score *below* the plugin estimate
        # (never make the rule falsely more alarmed than the biased version).
        rule_mm = PredictableResourceIDRule(use_miller_madow=True)
        rule_plugin = PredictableResourceIDRule(use_miller_madow=False)
        ids = ["ab1c9", "9fa2b", "c3d8e", "1e4f7", "b2a6d"]
        finding_mm = run(rule_mm.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        finding_plugin = run(rule_plugin.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        mm_entropy = finding_mm.metrics["avg_entropy_bits"] if finding_mm else None
        plugin_entropy = finding_plugin.metrics["avg_entropy_bits"] if finding_plugin else None
        assert mm_entropy is not None and plugin_entropy is not None
        assert mm_entropy >= plugin_entropy
        assert finding_plugin.metrics["estimator"] == "plugin"

    def test_numeric_finding_carries_keyspace_ci(self):
        # Small, tightly-clustered numeric IDs -> small_keyspace trigger.
        # The Finding must carry the 95% CI alongside the point estimate,
        # not just the bare number (see MathCore.keyspace_bits_ci).
        rule = PredictableResourceIDRule()
        ids = [1001, 1002, 1003, 1004, 1005, 1006]
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=ids))
        assert finding is not None
        assert "keyspace_bits_ci_95" in finding.metrics
        ci = finding.metrics["keyspace_bits_ci_95"]
        assert ci["lower"] <= ci["point"] <= ci["upper"]
        assert ci["point"] == finding.metrics["estimated_keyspace_bits"]
