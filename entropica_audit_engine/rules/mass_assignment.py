"""
ENTROPICA API6:2023 – Mass Assignment

Every other rule in this package measures the *randomness* of a value
(entropy, keyspace, sequential score). Mass assignment is a different
shape of problem: it's not about how random a field's value is, it's
about whether a field should be settable at all. The math here is set
theory, not information theory — deliberately, to keep the same
"pure mathematical signals, no string pattern matching for field names
like 'role' or 'isAdmin'" philosophy as excessive_data.py: the rule
doesn't need to know what a field is called to flag a structural
mismatch between what the API exposes and what it accepts.

Definitions
-----------
Let R be the set of field names observed in *read* responses (GET) for
a resource, and W be the set of field names accepted without rejection
in *write* requests (POST/PUT/PATCH) for the same resource.

    extra = W \\ R      — fields a client can set but can never read back.
                          These are the highest-risk fields: if a field
                          isn't even exposed on read, its presence in the
                          writable set is very unlikely to be intentional
                          client-facing design.

    J(R, W) = |R ∩ W| / |R ∪ W|      (Jaccard index, standard set-similarity
                                       measure: 1.0 = identical sets, 0.0 =
                                       disjoint)

A low Jaccard index paired with a non-empty `extra` set is the core
signal: the writable surface and the readable surface don't line up,
which is exactly the structural shape of a mass-assignment vulnerability
(e.g. a `role` or `accountBalance` field silently accepted by the write
endpoint despite never appearing in any read response).
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Set

from .base import BaseAuditRule, Finding, Severity


def jaccard_index(a: Set[str], b: Set[str]) -> float:
    """
    J(A, B) = |A ∩ B| / |A ∪ B|

    Standard set-similarity coefficient. 1.0 when the sets are identical,
    0.0 when they share nothing. Undefined (returned as 1.0, i.e. "no
    mismatch to report") when both sets are empty — there's no evidence
    of a mismatch if there's no evidence at all.
    """
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


class MassAssignmentRule(BaseAuditRule):
    """
    Flags a structural mismatch between the fields a resource exposes on
    read and the fields it accepts on write.

    A finding is raised when EITHER:
      1. `extra` (write-only fields, never visible on read) is non-empty
         and its size crosses `extra_field_threshold`, OR
      2. The Jaccard index between read-fields and write-fields falls
         below `jaccard_threshold`, indicating the two surfaces have
         drifted apart structurally even if `extra` alone is small.
    """

    def __init__(
        self,
        extra_field_threshold: int = 1,
        jaccard_threshold: float = 0.5,
    ) -> None:
        super().__init__(
            rule_id="API6:2023",
            name="Mass Assignment (read/write field mismatch)",
            severity=Severity.HIGH,
            description=(
                "One or more fields are accepted by write requests but "
                "never appear in read responses for the same resource, "
                "or the writable and readable field sets otherwise diverge "
                "structurally. This is the shape of a mass-assignment "
                "surface: internal or privileged fields settable by a "
                "client that has no way to see them."
            ),
            recommendation=(
                "Enforce an explicit allow-list of writable fields on "
                "every write endpoint, independent of what the read "
                "endpoint happens to expose. Never infer a writable "
                "schema from an ORM model or database row directly."
            ),
        )
        self.extra_field_threshold = extra_field_threshold
        self.jaccard_threshold = jaccard_threshold

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects:
          read_fields  : Sequence[str] — field names observed in GET responses
          write_fields : Sequence[str] — field names accepted (not rejected)
                         by POST/PUT/PATCH requests for the same resource
        """
        read_fields: Sequence[str] = kwargs.get("read_fields") or []
        write_fields: Sequence[str] = kwargs.get("write_fields") or []

        if not read_fields and not write_fields:
            return None

        r: Set[str] = set(read_fields)
        w: Set[str] = set(write_fields)

        extra = w - r
        j = jaccard_index(r, w)

        triggered_by: List[str] = []
        if len(extra) >= self.extra_field_threshold:
            triggered_by.append("write_only_fields")
        if j < self.jaccard_threshold:
            triggered_by.append("low_field_overlap")

        if not triggered_by:
            return None

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            target=target_url,
            evidence={
                "read_field_count": len(r),
                "write_field_count": len(w),
                "write_only_fields": sorted(extra),
            },
            metrics={
                "jaccard_index": round(j, 3),
                "jaccard_threshold": self.jaccard_threshold,
                "extra_field_count": len(extra),
                "extra_field_threshold": self.extra_field_threshold,
                "triggered_by": triggered_by,
            },
        )
