"""
Unit tests for MassAssignmentRule (API6:2023) and its jaccard_index helper.
"""

import asyncio

import pytest

from entropica_audit_engine.rules.mass_assignment import (
    MassAssignmentRule,
    jaccard_index,
)


def run(coro):
    return asyncio.run(coro)


class TestJaccardIndex:
    def test_identical_sets(self):
        assert jaccard_index({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint_sets(self):
        assert jaccard_index({"a"}, {"b"}) == 0.0

    def test_both_empty(self):
        assert jaccard_index(set(), set()) == 1.0

    def test_partial_overlap(self):
        # intersection={a}, union={a,b,c} -> 1/3
        assert jaccard_index({"a", "b"}, {"a", "c"}) == pytest.approx(1 / 3)


@pytest.fixture
def rule():
    return MassAssignmentRule(extra_field_threshold=1, jaccard_threshold=0.5)


class TestNoEvidence:
    def test_no_fields_returns_none(self, rule):
        finding = run(rule.execute("https://api.example.com/users", read_fields=[], write_fields=[]))
        assert finding is None


class TestMatchedSchema:
    def test_identical_read_write_fields_not_flagged(self, rule):
        fields = ["id", "name", "email"]
        finding = run(
            rule.execute("https://api.example.com/users", read_fields=fields, write_fields=fields)
        )
        assert finding is None


class TestMassAssignmentSurface:
    def test_write_only_field_flagged(self, rule):
        read_fields = ["id", "name", "email"]
        write_fields = ["id", "name", "email", "role"]  # 'role' never comes back on read
        finding = run(
            rule.execute(
                "https://api.example.com/users",
                read_fields=read_fields,
                write_fields=write_fields,
            )
        )
        assert finding is not None
        assert "write_only_fields" in finding.metrics["triggered_by"]
        assert "role" in finding.evidence["write_only_fields"]

    def test_low_overlap_flagged_even_without_many_extra_fields(self):
        rule = MassAssignmentRule(extra_field_threshold=5, jaccard_threshold=0.5)
        read_fields = ["id", "name"]
        write_fields = ["id", "isAdmin"]  # 1 extra field, but overlap is weak (1/3)
        finding = run(
            rule.execute(
                "https://api.example.com/users",
                read_fields=read_fields,
                write_fields=write_fields,
            )
        )
        assert finding is not None
        assert "low_field_overlap" in finding.metrics["triggered_by"]
