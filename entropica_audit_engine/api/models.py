"""
Pydantic schemas for the FastAPI control plane.

These deliberately mirror the existing `Finding` dataclass and rule
`**kwargs` contracts in rules/*.py rather than inventing a parallel
shape — the API is a thin transport layer over the same engine used
by demo.py, not a second implementation of it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    rule_id: str
    name: str
    severity: str
    description: str
    recommendation: str = ""
    target: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class RuleInfo(BaseModel):
    rule_id: str
    name: str
    severity: str


# ---------------------------------------------------------------------
# Per-rule evaluation payloads (mirror each rule's execute(**kwargs))
# ---------------------------------------------------------------------
class BolaEvalRequest(BaseModel):
    target_url: str
    sample_ids: List[str]


class ExcessiveDataEvalRequest(BaseModel):
    target_url: str
    field_samples: Dict[str, List[Any]]


class ResourceConsumptionEvalRequest(BaseModel):
    target_url: str
    rate_samples: List[Tuple[float, float]]  # (timestamp, arrival_rate)


class MassAssignmentEvalRequest(BaseModel):
    target_url: str
    read_fields: List[str]
    write_fields: List[str]


# ---------------------------------------------------------------------
# Probe-driven scan: fetch real data, then auto-run the applicable rules
# ---------------------------------------------------------------------
class ScanRequest(BaseModel):
    urls: List[str]
    max_concurrency: int = 10


class ScanResult(BaseModel):
    target_urls: List[str]
    findings: List[FindingOut]
    anomaly_detected: bool
