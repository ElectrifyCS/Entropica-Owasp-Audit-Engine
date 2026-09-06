"""
Watch the SSRF differential prober's self-throttling engage in real time
against your running VAmPI container.

This does NOT test for a real SSRF vulnerability - VAmPI doesn't have
one (crAPI does; that's a separate, later step). What this proves is
narrower and just as important right now: that the throttling mechanism
itself - the thing that was completely missing from this prober until
today - actually engages under real network conditions, not just an
in-process ASGI fixture with simulated delays.

Prerequisites: VAmPI running (docker start vampi), reachable at
http://localhost:5000.

Usage:
    python watch_ssrf_throttling.py
"""
import asyncio
import logging

import httpx

from entropica_audit_engine.worker.differential_prober import (
    collect_differential_observations,
)
from entropica_audit_engine.worker.prober import AsyncProber
from entropica_audit_engine.observability.audit_log import get_audit_logger

_STANDARD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}


class ReadableHandler(logging.Handler):
    """Prints each audit event as one readable line instead of raw JSON -
    this script is for watching a demo run, not feeding a log pipeline."""

    def emit(self, record: logging.LogRecord) -> None:
        event = record.getMessage()
        fields = {k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS}
        marker = "   <<<< BACKOFF" if "backoff" in event else ""
        field_str = " ".join(f"{k}={v}" for k, v in fields.items())
        print(f"[{record.levelname:7s}] {event:22s} {field_str}{marker}")


async def main():
    prober = AsyncProber(
        max_concurrency=10,
        initial_drain_rate=40.0,
        queue_backoff_threshold=2.0,
    )

    async with httpx.AsyncClient(base_url="http://localhost:5000") as client:
        print("Sending a burst of requests through the SSRF collector against real VAmPI...")
        print("(Not a real SSRF test - VAmPI has no vulnerable endpoint for this. This")
        print(" checks whether self-throttling engages under real network latency.)\n")
        await collect_differential_observations(
            client=client,
            url_template="/users/v1/{value}",
            conditions={
                "control": "name1",
                "condition_a": "name2",
                "condition_b": "admin",
            },
            samples_per_condition=10,
            prober=prober,
        )

    print(f"\nFinal modelled queue length: {prober.queue_snapshot:.2f}")
    print(f"Drain-rate estimate: {prober.drain_rate_estimate:.2f} req/s (adapted: {prober.mu_is_adapted})")


if __name__ == "__main__":
    logger = get_audit_logger()
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.addHandler(ReadableHandler())

    asyncio.run(main())
