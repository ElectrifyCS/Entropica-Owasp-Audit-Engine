"""
Tests for the explainability layer (explain.py).

These deliberately check for the presence of the actual numbers from
each Finding's metrics dict, not exact wording — the point is that the
text is a faithful, non-fabricating rendering of what's already on the
Finding, not a specific sentence shape.
"""

import asyncio

import pytest

from entropica_audit_engine.explain import explain, explain_all
from entropica_audit_engine.rules.base import Finding, Severity
from entropica_audit_engine.rules.bola import PredictableResourceIDRule
from entropica_audit_engine.rules.excessive_data import ExcessiveDataExposureRule
from entropica_audit_engine.rules.mass_assignment import MassAssignmentRule
from entropica_audit_engine.rules.resource_consumption import (
    UnrestrictedResourceConsumptionRule,
)


def run(coro):
    return asyncio.run(coro)


class TestExplainBOLA:
    def test_numeric_finding_mentions_bits_and_range(self):
        rule = PredictableResourceIDRule()
        ids = [1001, 1002, 1003, 1004, 1005, 1006]
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=ids))
        text = explain(finding)
        point = finding.metrics["estimated_keyspace_bits"]
        ci = finding.metrics["keyspace_bits_ci_95"]
        assert str(point) in text
        assert str(ci["lower"]) in text
        assert str(ci["upper"]) in text
        assert "enumerable" in text
        assert "BOLA" in text

    def test_non_numeric_finding_mentions_entropy_and_estimator(self):
        rule = PredictableResourceIDRule()
        ids = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5"]
        finding = run(rule.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        text = explain(finding)
        assert str(finding.metrics["avg_entropy_bits"]) in text
        assert "Miller" in text  # estimator == miller_madow by default
        assert "BOLA" in text

    def test_plugin_estimator_labeled_differently(self):
        rule = PredictableResourceIDRule(use_miller_madow=False)
        ids = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5"]
        finding = run(rule.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        text = explain(finding)
        assert "Miller" not in text
        assert "plugin" in text

    def test_custom_probe_rate_changes_enumeration_estimate(self):
        rule = PredictableResourceIDRule()
        ids = [1001, 1002, 1003, 1004, 1005, 1006]
        finding = run(rule.execute("https://api.example.com/orders/{id}", sample_ids=ids))
        slow_text = explain(finding, rate_rps=1.0)
        fast_text = explain(finding, rate_rps=10_000.0)
        assert slow_text != fast_text
        assert "1 req/s" in slow_text
        assert "10000 req/s" in fast_text


class TestExplainExcessiveData:
    def test_single_field_names_the_field(self):
        rule = ExcessiveDataExposureRule()
        values = [1001, 1002, 1003, 1004, 1005]
        finding = run(
            rule.execute("https://api.example.com/users", sample_values=values)
        )
        text = explain(finding)
        assert "`value`" in text

    def test_aggregate_finding_lists_every_offender(self):
        rule = ExcessiveDataExposureRule()
        field_samples = {
            "internal_id": [1001, 1002, 1003, 1004, 1005],
            "session_token": ["aaaa1", "aaaa2", "aaaa3", "aaaa4"],
            "display_name": ["Alice Smith", "Bob Jones", "Carla Diaz", "Deb Chen"],
        }
        finding = run(
            rule.execute("https://api.example.com/profile", field_samples=field_samples)
        )
        assert finding is not None
        text = explain(finding)
        assert "`internal_id`" in text
        assert "`session_token`" in text
        assert "display_name" not in text  # high-entropy names shouldn't trigger


class TestExplainResourceConsumption:
    def test_queue_overload_mentions_both_numbers(self):
        rule = UnrestrictedResourceConsumptionRule(drain_rate=5.0, queue_threshold=10.0)
        samples = [(float(i), 50.0) for i in range(10)]
        finding = run(
            rule.execute("https://api.example.com/search", rate_samples=samples)
        )
        assert finding is not None
        text = explain(finding)
        assert str(finding.metrics["max_queue_length"]) in text
        assert str(finding.metrics["queue_threshold"]) in text
        assert "rate limiting" in text


class TestExplainMassAssignment:
    def test_write_only_fields_are_named(self):
        rule = MassAssignmentRule()
        finding = run(
            rule.execute(
                "https://api.example.com/account",
                read_fields=["id", "email", "displayName"],
                write_fields=["id", "email", "displayName", "role", "accountBalance"],
            )
        )
        assert finding is not None
        # Jaccard here is 3/5 = 0.6, above the 0.5 threshold — only the
        # write_only_fields signal triggers, so the jaccard clause is
        # correctly omitted rather than mentioned as if it contributed.
        assert "low_field_overlap" not in finding.metrics["triggered_by"]
        text = explain(finding)
        assert "`role`" in text
        assert "`accountBalance`" in text

    def test_low_overlap_finding_mentions_jaccard_index(self):
        rule = MassAssignmentRule()
        finding = run(
            rule.execute(
                "https://api.example.com/account",
                read_fields=["id", "email"],
                write_fields=["role", "accountBalance", "isAdmin"],
            )
        )
        assert finding is not None
        assert "low_field_overlap" in finding.metrics["triggered_by"]
        text = explain(finding)
        assert str(finding.metrics["jaccard_index"]) in text


class TestExplainGenericFallback:
    def test_unknown_rule_id_still_produces_text(self):
        finding = Finding(
            rule_id="API9:2099",
            name="Hypothetical Future Rule",
            severity=Severity.LOW,
            description="A rule that doesn't exist yet raised this Finding.",
            metrics={"triggered_by": ["something_new"]},
        )
        text = explain(finding)
        assert text  # non-empty, doesn't raise
        assert "something_new" in text


class TestExplainAll:
    def test_explain_all_keys_by_rule_and_target(self):
        rule = MassAssignmentRule()
        finding = run(
            rule.execute(
                "https://api.example.com/account",
                read_fields=["id"],
                write_fields=["id", "role"],
            )
        )
        result = explain_all([finding])
        assert f"API6:2023:https://api.example.com/account" in result
