"""
Real-time structured audit logging.

Why this exists (stated plainly, since it shapes every design choice
below): this tool doesn't just analyze data — it actively probes real
systems, and its entire safety case rests on the self-throttling queue
model in worker/prober.py actually working as designed. Without a live,
complete record of what it did, "it backs off when Q(t) crosses the
threshold" is a claim in a docstring, not something anyone can verify
while — or after — a scan runs. This module makes that record real.

That reprioritizes what matters most: a Finding is one event among
several, but the PROBER'S CONDUCT — every request sent, every backoff
decision, every drain-rate re-estimate — is the primary audit trail. If
someone asks "what exactly did this tool do to our API," this log is the
answer, not a reconstruction after the fact.

Design choices
--------------
- One JSON object per line, written to stdout by default. That's
  genuinely real-time in the sense that matters: `docker logs -f`, a
  redirected file, or a SIEM ingestion pipe all just work, no new
  infrastructure required.
- Complete, not sampled. An audit log that drops events "to reduce
  noise" defeats its own purpose — the whole point is being able to
  answer "prove you didn't do anything reckless" with the actual
  record, not a curated summary of it.
- No new dependency: stdlib `logging` + a custom formatter.
- Never imported by core/ or rules/ — logging is I/O, and both of those
  packages are deliberately I/O-free (core/) or side-effect-free
  (rules/, so they stay trivially testable without mocking a logger).
  This module is only ever called from the orchestration/I/O layer:
  worker/, api/, calibration/.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

AUDIT_LOGGER_NAME = "entropica.audit"

# Attributes every stdlib LogRecord already has — used to figure out
# which attributes on a record were added via `extra={...}` by one of
# the log_* helpers below, so the formatter can include them without
# knowing in advance what fields any given event type uses.
_BASE_LOGRECORD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
)


class JSONLFormatter(logging.Formatter):
    """
    One JSON object per line. Deliberately doesn't special-case event
    types — it serializes whatever fields a log_* call attached via
    `extra=`, so a new event type never requires a formatter change,
    only a new small helper function below.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _BASE_LOGRECORD_ATTRS and key != "event" and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_configured = False


def get_audit_logger(name: str = AUDIT_LOGGER_NAME, stream=sys.stdout) -> logging.Logger:
    """
    The shared audit logger. Configuration happens exactly once
    (idempotent) — safe to call from every module that needs it without
    risking duplicate handlers and doubled-up log lines, which is
    exactly the kind of bug that would quietly corrupt an audit trail's
    completeness guarantee if it went unnoticed.
    """
    global _configured
    logger = logging.getLogger(name)
    if not _configured:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JSONLFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        _configured = True
    return logger


def reset_for_testing() -> None:
    """Test-only: clears configuration state and handlers so a test can
    attach its own handler to a clean logger. Not for production use."""
    global _configured
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    _configured = False


# ----------------------------------------------------------------------
# Prober conduct — the primary audit trail (see module docstring)
# ----------------------------------------------------------------------
def log_probe_sent(logger: logging.Logger, target: str) -> None:
    logger.info("probe_sent", extra={"event": "probe_sent", "target": target})


def log_probe_result(
    logger: logging.Logger,
    target: str,
    status_code: Optional[int],
    latency_ms: float,
    error: Optional[str] = None,
) -> None:
    logger.info(
        "probe_result",
        extra={
            "event": "probe_result",
            "target": target,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "error": error,
        },
    )


def log_backoff_started(
    logger: logging.Logger, target: str, queue_length: float, threshold: float
) -> None:
    """
    The single most safety-critical event this module emits: the prober
    detected its own modelled queue exceeding the backoff threshold and
    is pausing rather than issuing another request. This is the log line
    that turns "it self-throttles" from a design claim into something
    with evidence behind it.
    """
    logger.warning(
        "queue_backoff_started",
        extra={
            "event": "queue_backoff_started",
            "target": target,
            "queue_length": round(queue_length, 3),
            "backoff_threshold": threshold,
        },
    )


def log_backoff_cleared(
    logger: logging.Logger, target: str, queue_length: float, wait_seconds: float
) -> None:
    logger.info(
        "queue_backoff_cleared",
        extra={
            "event": "queue_backoff_cleared",
            "target": target,
            "queue_length": round(queue_length, 3),
            "wait_seconds": round(wait_seconds, 3),
        },
    )


def log_drain_rate_adapted(
    logger: logging.Logger,
    target: str,
    previous_mu: float,
    new_mu: float,
    n_departures_observed: int,
) -> None:
    logger.info(
        "drain_rate_adapted",
        extra={
            "event": "drain_rate_adapted",
            "target": target,
            "previous_mu": round(previous_mu, 3),
            "new_mu": round(new_mu, 3),
            "n_departures_observed": n_departures_observed,
        },
    )


def log_scan_start(logger: logging.Logger, urls: Iterable[str], max_concurrency: int) -> None:
    urls = list(urls)
    logger.info(
        "scan_start",
        extra={
            "event": "scan_start",
            "target_count": len(urls),
            "targets_preview": urls[:5],
            "max_concurrency": max_concurrency,
        },
    )


def log_scan_complete(
    logger: logging.Logger,
    target_count: int,
    duration_seconds: float,
    anomaly_detected: bool,
    final_drain_rate_estimate: float,
    drain_rate_is_adapted: bool,
) -> None:
    logger.info(
        "scan_complete",
        extra={
            "event": "scan_complete",
            "target_count": target_count,
            "duration_seconds": round(duration_seconds, 3),
            "anomaly_detected": anomaly_detected,
            "final_drain_rate_estimate": round(final_drain_rate_estimate, 3),
            "drain_rate_is_adapted": drain_rate_is_adapted,
        },
    )


# ----------------------------------------------------------------------
# Findings — secondary content, but still real (see module docstring on
# why this isn't the primary event type here)
# ----------------------------------------------------------------------
def log_finding(logger: logging.Logger, finding: Any, explanation: Optional[str] = None) -> None:
    severity = getattr(finding.severity, "value", str(finding.severity))
    logger.warning(
        "finding",
        extra={
            "event": "finding",
            "rule_id": finding.rule_id,
            "severity": severity,
            "target": finding.target,
            "triggered_by": finding.metrics.get("triggered_by", []),
            "explanation": explanation,
        },
    )


# ----------------------------------------------------------------------
# Calibration runs
# ----------------------------------------------------------------------
def log_calibration_start(logger: logging.Logger, sample_sizes, seeds) -> None:
    logger.info(
        "calibration_start",
        extra={
            "event": "calibration_start",
            "sample_sizes": list(sample_sizes),
            "seeds": list(seeds),
        },
    )


def log_calibration_complete(
    logger: logging.Logger,
    jsonl_path: str,
    md_path: str,
    n_records: int,
    duration_seconds: float,
) -> None:
    logger.info(
        "calibration_complete",
        extra={
            "event": "calibration_complete",
            "jsonl_path": jsonl_path,
            "md_path": md_path,
            "n_records": n_records,
            "duration_seconds": round(duration_seconds, 3),
        },
    )
