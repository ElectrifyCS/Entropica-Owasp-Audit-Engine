"""
End-to-end test of the full SSRF differential-probing pipeline:
    collect_differential_observations -> SSRFDifferentialRule.execute

Run against synthetic FastAPI apps over an in-process ASGI transport
(httpx.ASGITransport) - no Docker, no real sockets, no real network.
This is the regression-fixture tier from the project's own testing
strategy (expansion notes §7): a known-vulnerable and a known-safe
target, checked before any live target (VAmPI, crAPI, staging) exists to
point at.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from entropica_audit_engine.rules.ssrf import SSRFDifferentialRule
from entropica_audit_engine.worker.differential_prober import (
    collect_differential_observations,
)
from entropica_audit_engine.tests.fixtures.ssrf_apps import make_safe_app, make_vulnerable_app

CONDITIONS = {
    "control": "example.com",
    "link_local_metadata": "169.254.169.254",
    "loopback": "127.0.0.1",
}


def run(coro):
    return asyncio.run(coro)


async def _probe_app(app, samples_per_condition: int = 10):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        observations = await collect_differential_observations(
            client=client,
            url_template="/webhook?target={value}",
            conditions=CONDITIONS,
            samples_per_condition=samples_per_condition,
        )
    rule = SSRFDifferentialRule()
    return await rule.execute(
        target_url="http://test/webhook",
        observations=observations,
        control_label="control",
        parameter_name="target",
    )


class TestSSRFFixtureEndToEnd:
    def test_vulnerable_app_is_flagged(self):
        finding = run(_probe_app(make_vulnerable_app()))
        assert finding is not None
        assert finding.rule_id == "API7:2023"
        # Both private-range conditions should show up as significant -
        # the vulnerable fixture delays for *any* private-looking target.
        assert "link_local_metadata" in finding.evidence["significant_conditions"]
        assert "loopback" in finding.evidence["significant_conditions"]
        link_local_effect = finding.metrics["effects"]["link_local_metadata"]
        assert link_local_effect["delta_ms"] > 50.0
        assert link_local_effect["p_value_two_sided"] < 0.01

    def test_safe_app_is_not_flagged(self):
        finding = run(_probe_app(make_safe_app()))
        assert finding is None

    def test_collector_produces_expected_sample_counts(self):
        async def _collect():
            transport = httpx.ASGITransport(app=make_vulnerable_app())
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await collect_differential_observations(
                    client=client,
                    url_template="/webhook?target={value}",
                    conditions=CONDITIONS,
                    samples_per_condition=7,
                )

        observations = run(_collect())
        assert set(observations.keys()) == set(CONDITIONS.keys())
        for label, samples in observations.items():
            assert len(samples) == 7
            assert all(v >= 0 for v in samples)
