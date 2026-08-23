"""
ENTROPICA API3:2023 – Excessive Data Exposure / Mass Assignment signals

Detects response fields (or request bodies) that exhibit unexpectedly
low entropy or that leak sensitive-looking keys.  Pure mathematical
signals only — no string pattern matching for “password”, “ssn”, etc.
Those heuristics can be layered later; the core remains information-
theoretic.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from entropica_audit_engine.core.math_core import MathCore
from .base import BaseAuditRule, Finding, Severity


class ExcessiveDataExposureRule(BaseAuditRule):
    """
    Flags response field *values* that lack sufficient randomness or
    that form a suspiciously small keyspace when numeric.

    Typical use
    -----------
    A discovery worker collects, for a given endpoint, the set of JSON
    keys that appear across many responses together with sample values
    for each key.  This rule is then invoked once per key (or once for
    the whole field set) with those sample values.

    Signals (same triad as BOLA, applied to field values)
    ----------------------------------------------------
    1. Sequential score          – numeric values that look auto-incremented
    2. Estimated keyspace bits   – numeric values drawn from a tiny range
    3. Shannon / Miller–Madow entropy – non-numeric values that are
       repetitive or low-alphabet

    A finding is raised when any applicable signal crosses its threshold.
    All raw metrics travel with the Finding so the result stays explainable.
    """

    def __init__(
        self,
        entropy_threshold: float = 2.5,
        sequential_threshold: float = 0.7,
        keyspace_bit_threshold: float = 24.0,
        use_miller_madow: bool = True,
    ) -> None:
        super().__init__(
            rule_id="API3:2023",
            name="Excessive Data Exposure (field entropy)",
            severity=Severity.MEDIUM,
            description=(
                "Response (or request) field values exhibit low entropy, "
                "a small guessable keyspace, or strong sequential patterns. "
                "This can indicate over-exposure of internal identifiers, "
                "predictable tokens, or mass-assignment surfaces."
            ),
            recommendation=(
                "Return only the fields the client actually needs.  Replace "
                "sequential or low-entropy internal IDs with high-entropy "
                "opaque tokens.  Enforce an explicit allow-list of writable "
                "fields on every write endpoint (mass-assignment defence)."
            ),
        )
        self.entropy_threshold = entropy_threshold
        self.sequential_threshold = sequential_threshold
        self.keyspace_bit_threshold = keyspace_bit_threshold
        self.use_miller_madow = use_miller_madow

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects one of:

        • sample_values : Sequence  – values observed for a single field
        • field_samples : Dict[str, Sequence] – map field-name → values

        When field_samples is supplied the rule evaluates every field and
        returns a single Finding that aggregates the worst offenders
        (or None if nothing triggers).
        """
        field_samples: Optional[Dict[str, Sequence]] = kwargs.get("field_samples")
        sample_values: Sequence = kwargs.get("sample_values") or []

        if field_samples:
            return await self._evaluate_many(target_url, field_samples)
        if sample_values:
            return await self._evaluate_one(target_url, "value", sample_values)
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _evaluate_one(
        self,
        target_url: str,
        field_name: str,
        values: Sequence,
    ) -> Optional[Finding]:
        if len(values) < 3:
            return None

        seq_score = MathCore.sequential_score(values)
        highly_sequential = seq_score >= self.sequential_threshold

        numeric = MathCore.parse_numeric_ids(values)
        metrics: dict = {
            "field": field_name,
            "sequential_score": round(seq_score, 3),
            "sequential_threshold": self.sequential_threshold,
        }
        triggered_by: List[str] = []

        if highly_sequential:
            triggered_by.append("highly_sequential")

        if numeric is not None:
            est_bits = MathCore.estimated_keyspace_bits(values)
            small_keyspace = (
                est_bits is not None and est_bits < self.keyspace_bit_threshold
            )
            metrics["estimated_keyspace_bits"] = (
                round(est_bits, 2) if est_bits is not None else None
            )
            metrics["keyspace_bit_threshold"] = self.keyspace_bit_threshold

            # Optional confidence interval
            ci = MathCore.keyspace_bits_ci(values)
            if ci is not None:
                point, lo, hi = ci
                metrics["keyspace_bits_ci_95"] = {
                    "point": round(point, 2),
                    "lower": round(lo, 2),
                    "upper": round(hi, 2),
                }

            if small_keyspace:
                triggered_by.append("small_keyspace")
            triggered = highly_sequential or small_keyspace
        else:
            # Non-numeric: entropy signal (optionally Miller–Madow)
            if self.use_miller_madow:
                entropies = [MathCore.miller_madow_entropy(str(v)) for v in values]
            else:
                entropies = [MathCore.shannon_entropy(str(v)) for v in values]
            avg_entropy = sum(entropies) / len(entropies)
            norm_entropies = [MathCore.normalized_entropy(str(v)) for v in values]
            avg_norm = sum(norm_entropies) / len(norm_entropies)

            low_entropy = avg_entropy < self.entropy_threshold
            metrics["avg_entropy_bits"] = round(avg_entropy, 3)
            metrics["avg_normalized_entropy"] = round(avg_norm, 3)
            metrics["entropy_threshold"] = self.entropy_threshold
            metrics["estimator"] = (
                "miller_madow" if self.use_miller_madow else "plugin"
            )

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
                "field": field_name,
                "sample_preview": [str(v) for v in values[:6]],
                "sample_count": len(values),
                "value_scheme": "numeric" if numeric is not None else "non-numeric",
            },
            metrics=metrics,
        )

    async def _evaluate_many(
        self,
        target_url: str,
        field_samples: Dict[str, Sequence],
    ) -> Optional[Finding]:
        """
        Evaluate every field; return a composite Finding if any field
        triggers.  The metrics dictionary lists all offending fields.
        """
        offenders: List[dict] = []
        for name, values in field_samples.items():
            finding = await self._evaluate_one(target_url, name, values)
            if finding is not None:
                offenders.append(
                    {
                        "field": name,
                        "metrics": finding.metrics,
                        "evidence": finding.evidence,
                    }
                )

        if not offenders:
            return None

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            target=target_url,
            evidence={
                "offending_field_count": len(offenders),
                "fields": [o["field"] for o in offenders],
            },
            metrics={
                "offenders": offenders,
            },
        )
