"""
ENTROPICA API1:2023 – Broken Object Level Authorization
Detects predictable / sequential resource IDs via Shannon entropy
and sequential-score heuristics.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from entropica_audit_engine.core.math_core import MathCore
from .base import BaseAuditRule, Finding, Severity


class PredictableResourceIDRule(BaseAuditRule):
    """
    Flags resource identifiers that lack sufficient randomness.

    Up to three signals are combined, and which ones apply depends on the
    ID format observed:

      1. Sequential-score (0-1)         — always checked, numeric IDs only
      2. Estimated keyspace size (bits) — numeric IDs only (see below)
      3. Average Shannon entropy        — non-numeric / mixed-alphabet IDs only

    Signal 3 is deliberately NOT applied to purely-numeric ID samples.
    Per-character Shannon entropy is capped at log2(10) ≈ 3.32 bits for any
    numeric string, so a random 10-digit ID and a predictable 5-digit ID
    can both come back "low entropy" even though one has a ~9-billion-value
    keyspace and the other has ~90,000 — the signal doesn't discriminate in
    that regime. Signal 2 (estimated_keyspace_bits) answers the question
    entropy can't for numeric IDs: how large is the actual value space,
    regardless of digit-level distribution. For non-numeric tokens (UUIDs,
    base62/hex strings) the alphabet is large enough that entropy remains a
    meaningful, discriminating signal, so it's used there instead.

    A finding is emitted when any applicable signal crosses its threshold.
    """

    def __init__(
        self,
        entropy_threshold: float = 3.0,
        sequential_threshold: float = 0.7,
        keyspace_bit_threshold: float = 32.0,
    ) -> None:
        super().__init__(
            rule_id="API1:2023",
            name="Predictable Resource IDs (BOLA)",
            severity=Severity.HIGH,
            description=(
                "Resource identifiers exhibit low entropy, a small guessable "
                "keyspace, or strong sequential patterns, enabling Broken "
                "Object Level Authorization attacks."
            ),
            recommendation=(
                "Replace sequential, small-keyspace, or low-entropy IDs with "
                "cryptographically random UUIDs (v4) or similarly high-entropy "
                "tokens. Enforce authorization checks on every object access."
            ),
        )
        self.entropy_threshold = entropy_threshold
        self.sequential_threshold = sequential_threshold
        # 32 bits (~4.3B values) is a conservative cutoff: comfortably
        # enumerable by a scripted client within realistic API rate limits.
        # Security-token guidance (e.g. UUIDv4's ~122 bits) aims far higher;
        # this threshold is tunable per the sensitivity of the resource.
        self.keyspace_bit_threshold = keyspace_bit_threshold

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects `sample_ids` in kwargs (list of str | int).
        In a full engine this list would be collected by a discovery worker.
        """
        sample_ids: Sequence = kwargs.get("sample_ids") or []
        if len(sample_ids) < 3:
            # Not enough evidence yet
            return None

        seq_score = MathCore.sequential_score(sample_ids)
        highly_sequential = seq_score >= self.sequential_threshold

        numeric = MathCore.parse_numeric_ids(sample_ids)
        metrics: dict = {
            "sequential_score": round(seq_score, 3),
            "sequential_threshold": self.sequential_threshold,
        }
        triggered_by = []
        if highly_sequential:
            triggered_by.append("highly_sequential")

        if numeric is not None:
            # --- Numeric ID scheme: keyspace-size signal, entropy skipped ---
            est_bits = MathCore.estimated_keyspace_bits(sample_ids)
            small_keyspace = est_bits is not None and est_bits < self.keyspace_bit_threshold
            metrics["estimated_keyspace_bits"] = round(est_bits, 2) if est_bits is not None else None
            metrics["keyspace_bit_threshold"] = self.keyspace_bit_threshold
            if small_keyspace:
                triggered_by.append("small_keyspace")
            triggered = highly_sequential or small_keyspace
        else:
            # --- Non-numeric / mixed-alphabet ID scheme: entropy signal ---
            entropies = [MathCore.shannon_entropy(str(s)) for s in sample_ids]
            avg_entropy = sum(entropies) / len(entropies)
            norm_entropies = [MathCore.normalized_entropy(str(s)) for s in sample_ids]
            avg_norm = sum(norm_entropies) / len(norm_entropies)
            low_entropy = avg_entropy < self.entropy_threshold
            metrics["avg_entropy_bits"] = round(avg_entropy, 3)
            metrics["avg_normalized_entropy"] = round(avg_norm, 3)
            metrics["entropy_threshold"] = self.entropy_threshold
            if low_entropy:
                triggered_by.append("low_entropy")
            triggered = highly_sequential or low_entropy

        if not triggered:
            return None

        metrics["triggered_by"] = triggered_by

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
                "id_scheme": "numeric" if numeric is not None else "non-numeric",
            },
            metrics=metrics,
        )
