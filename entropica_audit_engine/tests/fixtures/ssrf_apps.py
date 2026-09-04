"""
Synthetic FastAPI apps simulating a vulnerable and a safe webhook
endpoint, for exercising the full SSRF differential-probing pipeline
(collector -> CausalProbe -> SSRFDifferentialRule) without Docker or a
real network - the "known-vulnerable / known-safe regression fixture"
tier of the project's own testing strategy (expansion notes §7), applied
before any real target exists to point at.

Both apps take a `target` query param and simulate "fetching" it:

  vulnerable_app: latency genuinely depends on whether `target` looks
      like a private/link-local address - simulating a server that
      really does make a slower internal network hop for those values.
      This is the ground truth a passing test should detect.

  safe_app: latency is constant regardless of `target` - simulating a
      server that validates and rejects private ranges up front, so the
      parameter has no causal effect on observable behavior. This is the
      ground truth a passing test should NOT flag.
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI

_PRIVATE_PREFIXES = ("169.254.", "127.", "10.", "192.168.")

# Deliberately large gap (95ms) so the test is robust to normal asyncio/
# ASGI scheduling jitter while still exercising the real statistical
# pipeline, not just asserting on hardcoded sleep values.
_INTERNAL_DELAY_S = 0.10
_EXTERNAL_DELAY_S = 0.005


def make_vulnerable_app() -> FastAPI:
    app = FastAPI()

    @app.get("/webhook")
    async def webhook(target: str):
        if target.startswith(_PRIVATE_PREFIXES):
            await asyncio.sleep(_INTERNAL_DELAY_S)
        else:
            await asyncio.sleep(_EXTERNAL_DELAY_S)
        return {"fetched": target}

    return app


def make_safe_app() -> FastAPI:
    app = FastAPI()

    @app.get("/webhook")
    async def webhook(target: str):
        # Validates and rejects private ranges before doing anything
        # target-dependent - latency is the same either way.
        await asyncio.sleep(_EXTERNAL_DELAY_S)
        if target.startswith(_PRIVATE_PREFIXES):
            return {"fetched": "rejected"}
        return {"fetched": target}

    return app
