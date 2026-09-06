"""
Synthetic FastAPI apps for testing the prober's self-throttling
mechanism against realistic overload patterns - separate from
ssrf_apps.py, which is scoped to the SSRF differential-probing pipeline
specifically and shouldn't accumulate unrelated fixtures.
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI


def make_serializing_app(hold_seconds: float = 0.3) -> FastAPI:
    """
    Simulates a single-threaded backend (e.g. Werkzeug's default dev
    server, which is exactly what VAmPI runs) that processes one request
    at a time via a global lock - concurrent requests queue up and each
    one's latency grows linearly with its position in line, an
    unambiguous real-world overload signature.

    This is the regression fixture for the arrival-rate fix in
    core/queue_dynamics.py: confirmed empirically (see worker/prober.py's
    module docstring) that against a target like this, the old
    completed_count/elapsed proxy showed ZERO queue growth no matter how
    badly the target was actually overloaded, because a throughput proxy
    can't exceed the target's own true rate by construction - it was
    this exact fixture shape (reproduced against a real running VAmPI
    container first) that surfaced the bug.
    """
    app = FastAPI()
    lock = asyncio.Lock()

    @app.get("/slow")
    async def slow():
        async with lock:
            await asyncio.sleep(hold_seconds)
        return {"ok": True}

    return app
