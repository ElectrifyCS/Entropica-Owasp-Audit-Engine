"""
Tests for observability/audit_log.py.
"""
from __future__ import annotations

import io
import json
import logging

import pytest

from entropica_audit_engine.observability import audit_log


@pytest.fixture
def captured_logger():
    """A fresh audit logger writing to an in-memory stream we can parse."""
    audit_log.reset_for_testing()
    stream = io.StringIO()
    logger = audit_log.get_audit_logger(stream=stream)
    yield logger, stream
    audit_log.reset_for_testing()


def _lines(stream: io.StringIO) -> list[dict]:
    stream.seek(0)
    return [json.loads(line) for line in stream.read().splitlines() if line.strip()]


class TestLoggerSetup:
    def test_get_audit_logger_is_idempotent(self):
        audit_log.reset_for_testing()
        stream = io.StringIO()
        logger1 = audit_log.get_audit_logger(stream=stream)
        logger2 = audit_log.get_audit_logger(stream=stream)
        assert logger1 is logger2
        # Calling it twice must not attach a second handler - that would
        # silently double every log line, corrupting the audit trail's
        # completeness guarantee rather than helping it.
        assert len(logger1.handlers) == 1
        audit_log.reset_for_testing()

    def test_output_is_valid_json_lines(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_probe_sent(logger, "https://api.example.com/x/1")
        lines = _lines(stream)
        assert len(lines) == 1
        assert "timestamp" in lines[0]
        assert "event" in lines[0]


class TestProberConductEvents:
    """These are the primary content per the module's own stated purpose
    - checked more thoroughly than the secondary event types below."""

    def test_probe_sent_and_result(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_probe_sent(logger, "https://api.example.com/x/1")
        audit_log.log_probe_result(logger, "https://api.example.com/x/1", 200, 45.678)
        lines = _lines(stream)
        assert lines[0]["event"] == "probe_sent"
        assert lines[0]["target"] == "https://api.example.com/x/1"
        assert lines[1]["event"] == "probe_result"
        assert lines[1]["status_code"] == 200
        assert lines[1]["latency_ms"] == 45.68  # rounded, not silently truncated to an int

    def test_probe_result_with_error(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_probe_result(logger, "https://x/1", None, 10000.0, error="ConnectTimeout")
        line = _lines(stream)[0]
        assert line["status_code"] is None
        assert line["error"] == "ConnectTimeout"

    def test_backoff_started_is_warning_level(self, captured_logger):
        # Deliberately WARNING, not INFO - this is the safety-critical
        # event and should be distinguishable by level alone in any
        # standard log viewer/filter, not just by reading the event field.
        logger, stream = captured_logger
        audit_log.log_backoff_started(logger, "https://x/1", queue_length=25.4, threshold=20.0)
        line = _lines(stream)[0]
        assert line["level"] == "WARNING"
        assert line["event"] == "queue_backoff_started"
        assert line["queue_length"] == 25.4
        assert line["backoff_threshold"] == 20.0

    def test_backoff_cleared(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_backoff_cleared(logger, "https://x/1", queue_length=18.0, wait_seconds=1.35)
        line = _lines(stream)[0]
        assert line["event"] == "queue_backoff_cleared"
        assert line["wait_seconds"] == 1.35

    def test_drain_rate_adapted(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_drain_rate_adapted(
            logger, "https://x/1", previous_mu=5.0, new_mu=8.23, n_departures_observed=5
        )
        line = _lines(stream)[0]
        assert line["event"] == "drain_rate_adapted"
        assert line["previous_mu"] == 5.0
        assert line["new_mu"] == 8.23
        assert line["n_departures_observed"] == 5

    def test_scan_start_and_complete(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_scan_start(logger, ["https://x/1", "https://x/2"], max_concurrency=10)
        audit_log.log_scan_complete(
            logger,
            target_count=2,
            duration_seconds=3.456,
            anomaly_detected=False,
            final_drain_rate_estimate=6.1,
            drain_rate_is_adapted=True,
        )
        lines = _lines(stream)
        assert lines[0]["event"] == "scan_start"
        assert lines[0]["target_count"] == 2
        assert lines[1]["event"] == "scan_complete"
        assert lines[1]["drain_rate_is_adapted"] is True


class TestFindingEvent:
    def test_log_finding_includes_explanation(self, captured_logger):
        import asyncio
        from entropica_audit_engine.rules.bola import PredictableResourceIDRule
        from entropica_audit_engine.explain import explain

        logger, stream = captured_logger
        rule = PredictableResourceIDRule()
        finding = asyncio.run(
            rule.execute("https://x/{id}", sample_ids=["aaaa1", "aaaa2", "aaaa3", "aaaa4"])
        )
        assert finding is not None
        audit_log.log_finding(logger, finding, explanation=explain(finding))
        line = _lines(stream)[0]
        assert line["event"] == "finding"
        assert line["rule_id"] == "API1:2023"
        assert line["level"] == "WARNING"
        assert "explanation" in line and line["explanation"]


class TestCalibrationEvents:
    def test_calibration_start_and_complete(self, captured_logger):
        logger, stream = captured_logger
        audit_log.log_calibration_start(logger, sample_sizes=[5, 10], seeds=[0, 1])
        audit_log.log_calibration_complete(
            logger, jsonl_path="a.jsonl", md_path="a.md", n_records=42, duration_seconds=1.2
        )
        lines = _lines(stream)
        assert lines[0]["event"] == "calibration_start"
        assert lines[1]["n_records"] == 42
