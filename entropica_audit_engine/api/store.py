"""
In-memory findings store.

Deliberately the simplest thing that works: a process-lifetime list.
This is a portfolio/research-stage control plane, not a production
service — persistence (SQLite via SQLModel is the natural next step,
matching the "roadmap" style of the rest of this project) can replace
this module without touching the API routes, since routes only ever
call add() / all() / get() below.
"""

from __future__ import annotations

from threading import Lock
from typing import List, Optional

from entropica_audit_engine.rules.base import Finding


class FindingStore:
    def __init__(self) -> None:
        self._findings: List[Finding] = []
        self._lock = Lock()

    def add(self, finding: Finding) -> Finding:
        with self._lock:
            self._findings.append(finding)
        return finding

    def add_many(self, findings: List[Finding]) -> List[Finding]:
        with self._lock:
            self._findings.extend(findings)
        return findings

    def all(self) -> List[Finding]:
        with self._lock:
            return list(self._findings)

    def by_rule(self, rule_id: str) -> List[Finding]:
        with self._lock:
            return [f for f in self._findings if f.rule_id == rule_id]

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()


# Single process-wide store, imported by app.py. Swap for a DI-provided
# instance if/when this grows multiple workers sharing one persistence layer.
store = FindingStore()
