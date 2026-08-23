"""
Unit tests for UnrestrictedResourceConsumptionRule (API4:2023).
"""

import asyncio

import pytest

from entropica_audit_engine.rules.resource_consumption import (
    UnrestrictedResourceConsumptionRule,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def rule():
    return UnrestrictedResourceConsumptionRule(
        drain_rate=10.0, queue_threshold=50.0, accel_threshold=20.0, sustained_windows=3
    )


class TestNotEnoughEvidence:
    def test_too_few_samples_returns_none(self, rule):
        finding = run(
            rule.execute("https://api.example.com/x", rate_samples=[(0.0, 5.0), (1.0, 5.0)])
        )
        assert finding is None


class TestStableTraffic:
    def test_low_steady_rate_not_flagged(self, rule):
        # Arrival rate well under drain rate the whole time -> queue stays at 0
        samples = [(float(t), 5.0) for t in range(10)]
        finding = run(rule.execute("https://api.example.com/x", rate_samples=samples))
        assert finding is None


class TestQueueOverload:
    def test_sustained_high_arrival_flags_overload(self, rule):
        # Arrival rate far exceeds drain rate (10/s) for many seconds -> queue grows unbounded
        samples = [(float(t), 100.0) for t in range(10)]
        finding = run(rule.execute("https://api.example.com/orders", rate_samples=samples))
        assert finding is not None
        assert "queue_overload" in finding.metrics["triggered_by"]
        assert finding.metrics["max_queue_length"] >= rule.queue_threshold


class TestBruteForceAcceleration:
    def test_scripted_ramp_flags_sustained_acceleration(self, rule):
        # Rate ramps quadratically as 5 + 10*t^2 -> exact 2nd derivative is
        # 20, comfortably over the rule's accel_threshold of 20.0... use a
        # slightly steeper coefficient so the discrete estimate clears it.
        samples = [(float(t), 5.0 + 15.0 * t * t) for t in range(10)]
        finding = run(rule.execute("https://api.example.com/login", rate_samples=samples))
        assert finding is not None
        assert "sustained_acceleration" in finding.metrics["triggered_by"]

    def test_single_organic_spike_not_flagged_as_brute_force(self, rule):
        # One spike then back to baseline -- acceleration isn't sustained,
        # and total arrivals never build a large enough queue either.
        samples = [
            (0.0, 5.0),
            (1.0, 5.0),
            (2.0, 5.0),
            (3.0, 40.0),  # one organic spike
            (4.0, 5.0),
            (5.0, 5.0),
            (6.0, 5.0),
        ]
        finding = run(rule.execute("https://api.example.com/x", rate_samples=samples))
        if finding is not None:
            assert "sustained_acceleration" not in finding.metrics["triggered_by"]
