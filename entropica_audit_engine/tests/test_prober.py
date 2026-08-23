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
