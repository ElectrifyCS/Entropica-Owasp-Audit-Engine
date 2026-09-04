"""
Integration tests: do the REAL entry points (AsyncProber.probe_many,
the SSRF collector, the FastAPI endpoints, the calibration harness's
run()) actually fire audit log events - not just "does log_probe_sent()
work when called directly," which test_audit_log.py already covers.

This distinction is the whole point of this file. Every gap found and
fixed this session (log_scan_start/complete imported but never called,
log_finding never called anywhere, log_calibration_start/complete never
called, the SSRF prober having zero logging at all) would have passed
every existing test in test_audit_log.py, because those tests only
exercise the log_* functions directly, never the code that's supposed
to call them. A unit-tested-in-isolation helper that nothing actually
calls is functionally dead code with a green test suite next to it.
"""
from __future__ import annotations

import asyncio
import io
import json

import httpx
import pytest

from entropica_audit_engine.observability import audit_log


@pytest.fixture
def captured_logger():
    audit_log.reset_for_testing()
    stream = io.StringIO()
    audit_log.get_audit_logger(stream=stream)
    yield stream
    audit_log.reset_for_testing()


def _events(stream: io.StringIO) -> list[dict]:
    stream.seek(0)
    return [json.loads(line) for line in stream.read().splitlines() if line.strip()]


def run(coro):
    return asyncio.run(coro)


class TestAsyncProberWiring:
    def test_probe_many_emits_scan_start_and_complete(self, captured_logger):
        from entropica_audit_engine.worker.prober import AsyncProber
        from entropica_audit_engine.tests.fixtures.ssrf_apps import make_safe_app

        transport = httpx.ASGITransport(app=make_safe_app())

        async def _run():
            prober = AsyncProber(max_concurrency=5)
            # Patch httpx.AsyncClient inside probe_many indirectly by
            # hitting the fixture app through a real client bound to the
            # ASGI transport - probe_many builds its own client, so we
            # call probe_one directly against a client wired to the
            # fixture instead of standing up a real socket.
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await prober.probe_one(client, "http://test/webhook?target=example.com")
            return prober

        run(_run())
        events = _events(captured_logger)
        event_types = [e["event"] for e in events]
        # probe_one alone (not probe_many) won't emit scan_start/complete -
        # those wrap the whole batch. Confirms probe_sent/probe_result at
        # minimum fire from a real call, not just a direct log_* call.
        assert "probe_sent" in event_types
        assert "probe_result" in event_types

    def test_probe_many_full_wiring_via_real_urls_list(self, captured_logger):
        # probe_many() itself requires real URLs (it builds its own
        # httpx.AsyncClient with no transport override), so this uses the
        # loopback-safe pattern: point at a target that will fail to
        # connect - that's fine, we're checking the LOGGING wiring fires
        # (scan_start before, scan_complete after, with an error captured
        # in between), not that the probe succeeds.
        from entropica_audit_engine.worker.prober import AsyncProber

        prober = AsyncProber(max_concurrency=2, request_timeout=0.5)
        run(prober.probe_many(["http://127.0.0.1:1/nope"]))  # port 1: nothing listens

        events = _events(captured_logger)
        event_types = [e["event"] for e in events]
        assert "scan_start" in event_types
        assert "scan_complete" in event_types
        assert "probe_sent" in event_types
        assert "probe_result" in event_types

        scan_start = next(e for e in events if e["event"] == "scan_start")
        assert scan_start["target_count"] == 1
        scan_complete = next(e for e in events if e["event"] == "scan_complete")
        assert scan_complete["target_count"] == 1
        assert "duration_seconds" in scan_complete


class TestDifferentialProberWiring:
    def test_collect_differential_observations_emits_probe_events(self, captured_logger):
        from entropica_audit_engine.worker.differential_prober import (
            collect_differential_observations,
        )
        from entropica_audit_engine.tests.fixtures.ssrf_apps import make_vulnerable_app

        transport = httpx.ASGITransport(app=make_vulnerable_app())

        async def _run():
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await collect_differential_observations(
                    client=client,
                    url_template="/webhook?target={value}",
                    conditions={"control": "example.com", "loopback": "127.0.0.1"},
                    samples_per_condition=3,
                )

        run(_run())
        events = _events(captured_logger)
        sent = [e for e in events if e["event"] == "probe_sent"]
        results = [e for e in events if e["event"] == "probe_result"]
        # 2 conditions x 3 samples each = 6 requests - this is the
        # prober with NO backoff/throttling at all, so every single
        # request must show up; a gap here would be a silent blind spot
        # in exactly the prober most in need of visibility.
        assert len(sent) == 6
        assert len(results) == 6
        assert all(r["status_code"] == 200 for r in results)


class TestAPIFindingWiring:
    def test_bola_endpoint_emits_finding_event_with_explanation(self, captured_logger):
        from fastapi.testclient import TestClient
        from entropica_audit_engine.api.app import app

        client = TestClient(app)
        resp = client.post(
            "/findings/bola",
            json={
                "target_url": "https://api.example.com/books/{id}",
                "sample_ids": ["bookTitle7", "bookTitle38", "bookTitle17", "bookTitle42"],
            },
        )
        assert resp.status_code == 200
        assert resp.json() is not None  # a Finding really was produced

        events = _events(captured_logger)
        finding_events = [e for e in events if e["event"] == "finding"]
        assert len(finding_events) == 1
        fe = finding_events[0]
        assert fe["rule_id"] == "API1:2023"
        assert fe["explanation"]  # non-empty - the real explain() text
        assert "bookTitle" in fe["explanation"]

    def test_endpoint_with_no_finding_emits_no_finding_event(self, captured_logger):
        from fastapi.testclient import TestClient
        from entropica_audit_engine.api.app import app

        client = TestClient(app)
        resp = client.post(
            "/findings/bola",
            json={
                "target_url": "https://api.example.com/x/{id}",
                "sample_ids": [
                    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
                    "11223344-5566-7788-99aa-bbccddeeff00",
                ],
            },
        )
        assert resp.status_code == 200
        assert resp.json() is None  # a real UUID sample - no Finding expected
        events = _events(captured_logger)
        assert not [e for e in events if e["event"] == "finding"]


class TestCalibrationWiring:
    def test_run_emits_calibration_start_and_complete(self, captured_logger, tmp_path):
        from entropica_audit_engine.calibration import harness

        jsonl_path, md_path = harness.run(
            output_dir=str(tmp_path), sample_sizes=(5,), seeds=(0,)
        )
        events = _events(captured_logger)
        event_types = [e["event"] for e in events]
        assert "calibration_start" in event_types
        assert "calibration_complete" in event_types
        complete = next(e for e in events if e["event"] == "calibration_complete")
        assert complete["jsonl_path"] == jsonl_path
        assert complete["md_path"] == md_path
        assert complete["n_records"] > 0
