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


class TestEntropyClauseHonesty:
    """
    Regression test: _entropy_clause used to unconditionally claim
    "(below the X-bit threshold)" whenever a threshold value existed in
    metrics, regardless of whether entropy actually crossed it or
    contributed to the Finding. Caught by reading real explain() output
    on a templated-ID Finding, not by inspecting the code.
    """

    def test_does_not_claim_below_threshold_when_entropy_did_not_trigger(self):
        from entropica_audit_engine.rules.bola import PredictableResourceIDRule

        rule = PredictableResourceIDRule()
        # Whole-string entropy on this sample is ABOVE the 3.0 threshold
        # (the templated-ID signal is what actually fires here) - the
        # explain text must not claim entropy was "below" anything.
        ids = ["bookTitle7", "bookTitle38", "bookTitle17", "bookTitle42"]
        finding = run(rule.execute("https://api.example.com/books/{id}", sample_ids=ids))
        assert finding is not None
        assert "low_entropy" not in finding.metrics["triggered_by"]
        assert finding.metrics["avg_entropy_bits"] > finding.metrics["entropy_threshold"]
        text = explain(finding)
        assert "below the" not in text or "threshold)" not in text.split("below the")[1][:20]

    def test_does_claim_below_threshold_when_entropy_did_trigger(self):
        from entropica_audit_engine.rules.bola import PredictableResourceIDRule

        rule = PredictableResourceIDRule()
        ids = ["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5"]
        finding = run(rule.execute("https://api.example.com/sessions/{id}", sample_ids=ids))
        assert finding is not None
        assert "low_entropy" in finding.metrics["triggered_by"]
        text = explain(finding)
        assert "below the" in text


class TestExplainSSRF:
    def test_vulnerable_finding_mentions_effect_and_interventional_language(self):
        from entropica_audit_engine.rules.ssrf import SSRFDifferentialRule
        from entropica_audit_engine.worker.differential_prober import (
            collect_differential_observations,
        )
        from entropica_audit_engine.tests.fixtures.ssrf_apps import make_vulnerable_app
        import httpx

        async def _run():
            transport = httpx.ASGITransport(app=make_vulnerable_app())
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                observations = await collect_differential_observations(
                    client=client,
                    url_template="/webhook?target={value}",
                    conditions={"control": "example.com", "loopback": "127.0.0.1"},
                    samples_per_condition=10,
                )
            rule = SSRFDifferentialRule()
            return await rule.execute(
                "http://test/webhook",
                observations=observations,
                control_label="control",
                parameter_name="target",
            )

        finding = run(_run())
        assert finding is not None
        text = explain(finding)
        assert "target" in text
        assert "loopback" in text
        assert "Welch's t" in text
        assert "interventional" in text
        strongest = finding.metrics["effects"]["loopback"]
        assert f"{strongest['delta_ms']:+.1f}ms" in text


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
