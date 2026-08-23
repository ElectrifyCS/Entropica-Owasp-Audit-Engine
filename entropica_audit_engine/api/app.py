"""
FastAPI control plane.

Thin HTTP layer over the existing engine:
  - the rule registry (rules/registry.py) does the detection
  - the async prober (worker/prober.py) does the data collection
  - the store (api/store.py) holds results for the process lifetime

Run it with:
    uvicorn entropica_audit_engine.api.app:app --reload
"""

from __future__ import annotations

from typing import List

from fastapi import FastAPI, HTTPException

from entropica_audit_engine.rules.registry import build_default_registry
from entropica_audit_engine.rules.base import Finding
from entropica_audit_engine.worker.prober import AsyncProber

from .models import (
    BolaEvalRequest,
    ExcessiveDataEvalRequest,
    FindingOut,
    MassAssignmentEvalRequest,
    ResourceConsumptionEvalRequest,
    RuleInfo,
    ScanRequest,
    ScanResult,
)
from .store import store

app = FastAPI(
    title="Entropica Audit Engine",
    description="Control plane for the ENTROPICA API security rule engine.",
    version="0.2.0",
)

registry = build_default_registry()


def _to_finding_out(finding: Finding) -> FindingOut:
    d = finding.to_dict()
    return FindingOut(**d)


@app.get("/rules", response_model=List[RuleInfo])
async def list_rules() -> List[RuleInfo]:
    return [
        RuleInfo(rule_id=r.rule_id, name=r.name, severity=r.severity.value)
        for r in registry.all()
    ]


@app.get("/findings", response_model=List[FindingOut])
async def list_findings() -> List[FindingOut]:
    return [_to_finding_out(f) for f in store.all()]


@app.post("/findings/bola", response_model=FindingOut | None)
async def evaluate_bola(req: BolaEvalRequest):
    rule = registry.get("API1:2023")
    finding = await rule.execute(req.target_url, sample_ids=req.sample_ids)
    if finding:
        store.add(finding)
        return _to_finding_out(finding)
    return None


@app.post("/findings/excessive-data", response_model=FindingOut | None)
async def evaluate_excessive_data(req: ExcessiveDataEvalRequest):
    rule = registry.get("API3:2023")
    finding = await rule.execute(req.target_url, field_samples=req.field_samples)
    if finding:
        store.add(finding)
        return _to_finding_out(finding)
    return None


@app.post("/findings/resource-consumption", response_model=FindingOut | None)
async def evaluate_resource_consumption(req: ResourceConsumptionEvalRequest):
    rule = registry.get("API4:2023")
    finding = await rule.execute(req.target_url, rate_samples=req.rate_samples)
    if finding:
        store.add(finding)
        return _to_finding_out(finding)
    return None


@app.post("/findings/mass-assignment", response_model=FindingOut | None)
async def evaluate_mass_assignment(req: MassAssignmentEvalRequest):
    rule = registry.get("API6:2023")
    finding = await rule.execute(
        req.target_url, read_fields=req.read_fields, write_fields=req.write_fields
    )
    if finding:
        store.add(finding)
        return _to_finding_out(finding)
    return None


@app.post("/scans", response_model=ScanResult)
async def run_scan(req: ScanRequest) -> ScanResult:
    """
    Probe a list of URLs and auto-run the rules that apply to whatever
    evidence comes back (BOLA on collected IDs, API3 on collected field
    samples). Findings are persisted to the store.
    """
    if not req.urls:
        raise HTTPException(status_code=400, detail="urls must not be empty")

    prober = AsyncProber(max_concurrency=req.max_concurrency)
    session = await prober.probe_many(req.urls)

    findings: List[Finding] = []

    bola_rule = registry.get("API1:2023")
    bola_finding = await bola_rule.execute(req.urls[0], sample_ids=session.sample_ids)
    if bola_finding:
        findings.append(bola_finding)

    if session.field_samples:
        excessive_data_rule = registry.get("API3:2023")
        ed_finding = await excessive_data_rule.execute(
            req.urls[0], field_samples=session.field_samples
        )
        if ed_finding:
            findings.append(ed_finding)

    store.add_many(findings)

    return ScanResult(
        target_urls=list(req.urls),
        findings=[_to_finding_out(f) for f in findings],
        anomaly_detected=prober.anomaly_detected,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "registered_rules": registry.ids()}
