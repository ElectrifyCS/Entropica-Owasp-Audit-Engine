# Entropica — Commercial Readiness Checklist

Quick, practical list to move from research prototype → sellable product.
Items ordered by impact / dependency.

---

## 1. Core technical credibility

- [x] **Structural signal for templated IDs** (prefix + varying-suffix entropy)  
  Closed the exact blind spot real VAmPI data exposed. Metrics + explain layer + tests shipped.
- [x] **Capture methodology hygiene**  
  `scripts/capture_vampi.py` defaults to organic-only; any injection is explicitly labelled `source="injected"`. Real HTTP error bodies are surfaced (no more silent add_books failures).
- [x] **Known-vuln demonstration scaffolding**  
  `scripts/demo_known_vulns.py` proves the templated-ID signal on the real pattern and documents the live username-swap BOLA steps.
- [x] **crAPI second-target scaffolding**  
  Generators (`crapi_vehicle_id`, `crapi_report_id`) + `scripts/capture_crapi.py` organic capture scaffold.
- [ ] **Live organic capture + known-vuln end-to-end**  
  Run the scripts against a real VAmPI / crAPI instance, confirm Findings, and keep only organic-labelled records in the calibration set.
- [ ] **Threshold policy document**  
  Synthetic + real-data rationale for every default. Keep “advisory only” notes visible.
- [ ] **Regression suite that includes the real-data patterns**  
  bookTitle-style, short numeric, auto-increment, UUIDv4, organic vs injected.

## 2. Product surface

- [ ] **Persistent storage** (SQLite — store already isolated)
- [ ] **Auth on the control plane** (API-key / basic auth minimum)
- [ ] **Stable CLI + versioned HTTP API**
- [ ] **Human + machine readable reports** (lean on `explain.py`; SARIF / Markdown / PDF)
- [ ] **Safe-by-default probing** (document self-governing queue model, scope files, dry-run, permission statement)

## 3. Packaging, ops & legal

- [ ] **Proper packaging** (pyproject.toml / entry points, pinned deps)
- [ ] **Buyer-facing docs** (15-minute evaluation path)
- [ ] **LICENSE + copyright** (replace “[Your Name]” placeholder)
- [ ] **Security & privacy posture** (no secret logging, no phone-home)
- [ ] **Dependency baseline**

## 4. Commercial model & go-to-market

- [ ] **Positioning** (specialist vs broader coverage; open-core vs commercial)
- [ ] **Target buyer**
- [ ] **Differentiation paragraph**
- [ ] **Pricing sketch**
- [ ] **Support / SLA story**

## 5. Validation before first paid pilot

- [ ] External reviewer has run it against a known vulnerable app
- [ ] False-positive rate on modern UUID/token APIs documented
- [ ] Capture + calibration reproducible by someone else
- [ ] README + this checklist honest about remaining limitations

---

### Suggested next focus (after reviewing this batch)
1. Run `scripts/capture_vampi.py` (organic) and `scripts/demo_known_vulns.py` against a live instance when Docker is available.  
2. SQLite + basic auth.  
3. Write the one-paragraph differentiation statement and decide license model.

*Updated 2026-08-31 — priorities 1–4 scaffolding complete.*
