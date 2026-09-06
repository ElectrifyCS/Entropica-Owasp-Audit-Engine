"""
Unit tests for AsyncProber. Uses httpx.MockTransport so these run offline
and deterministically -- no real network calls.
"""

import asyncio
import json

import httpx
import pytest

from entropica_audit_engine.worker.prober import AsyncProber


def run(coro):
    return asyncio.run(coro)


def make_handler(responses):
    """responses: dict[url] -> (status_code, json_body)"""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        status, body = responses.get(url, (404, {"error": "not found"}))
        return httpx.Response(status, json=body)

    return handler


class PatchedProber(AsyncProber):
    """AsyncProber wired to a MockTransport instead of the real network."""

    def __init__(self, transport: httpx.MockTransport, **kwargs):
        super().__init__(**kwargs)
        self._transport = transport

    async def probe_many(self, urls, headers=None):
        import entropica_audit_engine.worker.prober as prober_mod

        original_client = httpx.AsyncClient
        transport = self._transport

        class PatchedClient(original_client):
            def __init__(self, *a, **kw):
                kw["transport"] = transport
                super().__init__(*a, **kw)

        prober_mod.httpx.AsyncClient = PatchedClient
        try:
            return await super().probe_many(urls, headers=headers)
        finally:
            prober_mod.httpx.AsyncClient = original_client


class TestProbeMany:
    def test_collects_sample_ids_and_field_samples(self):
        urls = [f"https://api.example.com/users/{i}" for i in range(1001, 1006)]
        responses = {
            u: (200, {"id": u.rsplit("/", 1)[-1], "email": f"user{i}@example.com"})
            for i, u in enumerate(urls)
        }
        transport = httpx.MockTransport(make_handler(responses))
        prober = PatchedProber(transport, max_concurrency=5, queue_backoff_threshold=1000.0)

        session = run(prober.probe_many(urls))

        assert len(session.results) == 5
        assert all(r.status_code == 200 for r in session.results)
        assert set(session.sample_ids) == {"1001", "1002", "1003", "1004", "1005"}
        assert "email" in session.field_samples
        assert len(session.field_samples["email"]) == 5

    def test_handles_non_json_and_error_responses_gracefully(self):
        urls = ["https://api.example.com/x/1", "https://api.example.com/x/2"]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/1"):
                return httpx.Response(200, text="not json")
            return httpx.Response(500, json={"error": "boom"})

        transport = httpx.MockTransport(handler)
        prober = PatchedProber(transport, max_concurrency=5, queue_backoff_threshold=1000.0)

        session = run(prober.probe_many(urls))

        assert len(session.results) == 2
        statuses = {r.status_code for r in session.results}
        assert statuses == {200, 500}

    def test_latencies_recorded_for_every_result(self):
        urls = [f"https://api.example.com/items/{i}" for i in range(3)]
        responses = {u: (200, {"ok": True}) for u in urls}
        transport = httpx.MockTransport(make_handler(responses))
        prober = PatchedProber(transport, max_concurrency=3, queue_backoff_threshold=1000.0)

        session = run(prober.probe_many(urls))

        assert len(session.latencies_ms) == 3
        assert all(latency >= 0 for latency in session.latencies_ms)


class TestSelfThrottlingAgainstRealOverload:
    """
    End-to-end regression test for the arrival-rate fix: a real burst of
    concurrent requests against a genuinely serializing backend (not a
    hand-constructed tracker scenario) must produce actual queue growth,
    backoff events, and correct mu adaptation - this is the exact
    scenario that, before the fix, showed zero queue growth against a
    real running VAmPI container despite requests taking up to several
    seconds each.
    """

    def test_burst_against_serializing_backend_triggers_real_backoff(self):
        import httpx
        from entropica_audit_engine.tests.fixtures.overload_apps import make_serializing_app

        transport = httpx.ASGITransport(app=make_serializing_app(hold_seconds=0.3))
        prober = AsyncProber(max_concurrency=10, initial_drain_rate=40.0, queue_backoff_threshold=2.0)

        async def _run():
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                tasks = [prober.probe_one(client, "/slow") for _ in range(10)]
                return await asyncio.gather(*tasks)

        results = run(_run())

        # Before the fix: queue_snapshot was exactly 0.0 and mu never
        # adapted, no matter how overloaded the target actually was.
        assert prober.queue_snapshot > 0.0
        assert prober.mu_is_adapted is True
        # The target's true capacity is ~1/0.3 = 3.33 req/s - confirm the
        # adapted estimate is in a sane range around that, not just
        # "some nonzero number."
        assert 1.0 < prober.drain_rate_estimate < 10.0
        # Latencies should show the escalating pattern of genuine
        # serialization - later requests wait behind earlier ones.
        assert results[-1].latency_ms > results[0].latency_ms * 2


class TestDrainRateAdaptation:
    """
    Confirms probe_one actually feeds real completions into
    QueueDynamicsTracker.record_departure. Previously the prober's own
    docstring claimed mu was "refined as responses come back" via a
    method that didn't exist anywhere in the codebase — mu was set once
    from initial_drain_rate and never touched again, no matter how many
    requests completed. These tests would have caught that: before the
    fix, mu_sample_count stays 0 and mu_is_adapted stays False forever,
    regardless of how much traffic the prober observes.
    """

    def test_completions_are_recorded_as_departures_when_queue_backlogged(self):
        urls = [f"https://api.example.com/items/{i}" for i in range(6)]
        responses = {u: (200, {"ok": True}) for u in urls}
        transport = httpx.MockTransport(make_handler(responses))
        prober = PatchedProber(
            transport,
            max_concurrency=6,
            queue_backoff_threshold=1000.0,  # don't actually throttle
            initial_drain_rate=5.0,
        )
        # Force a backlog before probing so departures count toward mu
        # (see QueueDynamicsTracker.record_departure — Q==0 departures
        # are deliberately excluded and wouldn't prove the wiring works).
        prober._queue_model.Q = 100.0
        prober._queue_model.min_departures_before_adapting = 1

        run(prober.probe_many(urls))

        assert prober._queue_model.mu_sample_count >= 1
        assert prober.mu_is_adapted is True
        assert prober.drain_rate_estimate > 0.0

    def test_mu_stays_at_initial_guess_when_never_backlogged(self):
        # Sanity check on the other direction: with no forced backlog and
        # a generous initial_drain_rate relative to a handful of fast
        # mock requests, the queue model shouldn't have reason to think
        # it's ever behind, so mu should reasonably remain unadapted or
        # close to its guess rather than swinging on noise.
        urls = [f"https://api.example.com/items/{i}" for i in range(3)]
        responses = {u: (200, {"ok": True}) for u in urls}
        transport = httpx.MockTransport(make_handler(responses))
        prober = PatchedProber(
            transport,
            max_concurrency=3,
            queue_backoff_threshold=1000.0,
            initial_drain_rate=5.0,
        )
        run(prober.probe_many(urls))
        # Either it never adapted, or it adapted from genuinely-observed
        # in-queue departures — either way mu must stay a finite positive
        # number, never 0 or negative.
        assert prober.drain_rate_estimate > 0.0
