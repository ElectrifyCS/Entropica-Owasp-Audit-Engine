"""
OWASP API1:2023 – Broken Object Level Authorization
Detects predictable / sequential resource IDs via Shannon entropy
and sequential-score heuristics.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from owasp_audit_engine.core.math_core import MathCore
from .base import BaseAuditRule, Finding, Severity


class PredictableResourceIDRule(BaseAuditRule):
    """
    Flags resource identifiers that lack sufficient randomness.

    Two signals are combined:
      1. Average Shannon entropy of the ID strings (bits/symbol)
      2. Sequential-score on numeric IDs (0–1)

    A finding is emitted when either signal crosses its threshold.
    """

    def __init__(
        self,
        entropy_threshold: float = 3.0,
        sequential_threshold: float = 0.7,
    ) -> None:
        super().__init__(
            rule_id="API1:2023",
            name="Predictable Resource IDs (BOLA)",
            severity=Severity.HIGH,
            description=(
                "Resource identifiers exhibit low entropy or strong sequential "
                "patterns, enabling Broken Object Level Authorization attacks."
            ),
            recommendation=(
                "Replace sequential or low-entropy IDs with cryptographically "
                "random UUIDs (v4) or similarly high-entropy tokens. "
                "Enforce authorization checks on every object access."
            ),
        )
        self.entropy_threshold = entropy_threshold
        self.sequential_threshold = sequential_threshold

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects `sample_ids` in kwargs (list of str | int).
        In a full engine this list would be collected by a discovery worker.
        """
        sample_ids: Sequence = kwargs.get("sample_ids") or []
        if len(sample_ids) < 3:
            # Not enough evidence yet
            return None

        # --- Entropy signal ---
        entropies = [MathCore.shannon_entropy(str(s)) for s in sample_ids]
        avg_entropy = sum(entropies) / len(entropies)
        norm_entropies = [MathCore.normalized_entropy(str(s)) for s in sample_ids]
        avg_norm = sum(norm_entropies) / len(norm_entropies)

        # --- Sequential signal ---
        seq_score = MathCore.sequential_score(sample_ids)

        low_entropy = avg_entropy < self.entropy_threshold
        highly_sequential = seq_score >= self.sequential_threshold

        if not (low_entropy or highly_sequential):
            return None

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            target=target_url,
            evidence={
                "sample_ids_preview": [str(s) for s in sample_ids[:8]],
                "sample_count": len(sample_ids),
            },
            metrics={
                "avg_entropy_bits": round(avg_entropy, 3),
                "avg_normalized_entropy": round(avg_norm, 3),
                "sequential_score": round(seq_score, 3),
                "entropy_threshold": self.entropy_threshold,
                "sequential_threshold": self.sequential_threshold,
                "triggered_by": [
                    name
                    for name, cond in [
                        ("low_entropy", low_entropy),
                        ("highly_sequential", highly_sequential),
                    ]
                    if cond
                ],
            },
        )
