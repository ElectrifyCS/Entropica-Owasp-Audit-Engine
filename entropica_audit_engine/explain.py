"""
ENTROPICA Explainability Layer (project notes, section 6)

A pure presentation layer that turns a Finding's metrics dictionary into
a short, human-readable rationale a security engineer can hand to a
product owner without translating bits and z-scores themselves.

Guiding constraint: this module contains NO detection logic. Every
number in the output text already exists on the Finding; this file only
formats it. If a Finding doesn't carry a number (e.g. a rule that hasn't
been backported to compute a CI), the explanation degrades gracefully
by omitting that clause rather than inventing a value.

Because every rule's metrics dict has its own shape (see rules/bola.py,
rules/excessive_data.py, rules/resource_consumption.py,
rules/mass_assignment.py), explanation is dispatched per rule_id. A rule
not explicitly handled here still gets a readable (if generic) sentence
via `_explain_generic`, rather than a blank string — adding a new rule
should never silently produce unexplained Findings.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

from .rules.base import Finding

# Assumed probing rate used only to translate a keyspace size into a
# human "how long to enumerate" estimate. This is explicitly an
# assumption, not a measured value — it's surfaced in the text itself
# so nobody mistakes it for something the engine observed.
DEFAULT_PROBE_RATE_RPS = 20.0


# ----------------------------------------------------------------------
# Formatting helpers
# ----------------------------------------------------------------------
def _human_count(n: float) -> str:
    """Render a value count with the precision the number deserves."""
    if n < 1000:
        return f"{n:,.0f}"
    if n < 1_000_000:
        return f"{n / 1000:,.1f}K".replace(".0K", "K")
    if n < 1_000_000_000:
        return f"{n / 1_000_000:,.1f}M".replace(".0M", "M")
    return f"{n / 1_000_000_000:,.1f}B".replace(".0B", "B")


def _human_duration(seconds: float) -> str:
    """Render a duration the way an engineer would say it out loud."""
    if seconds < 1:
        return "under a second"
    if seconds < 60:
        return f"about {seconds:.0f} seconds"
    if seconds < 3600:
        return f"about {seconds / 60:.0f} minutes"
    if seconds < 86400:
        hours = seconds / 3600
        return "well under an hour" if hours < 1.5 else f"about {hours:.0f} hours"
    if seconds < 86400 * 30:
        return f"about {seconds / 86400:.0f} days"
    if seconds < 86400 * 365:
        return f"about {seconds / (86400 * 30):.0f} months"
    return f"about {seconds / (86400 * 365):.1f} years"


def _keyspace_clause(metrics: dict, rate_rps: float) -> Optional[str]:
    """
    Shared by every rule that surfaces estimated_keyspace_bits +
    keyspace_bits_ci_95 (BOLA, Excessive Data Exposure). Returns None if
    the Finding doesn't carry these keys — callers must handle that by
    omitting the clause, not by fabricating one.
    """
    ci = metrics.get("keyspace_bits_ci_95")
    point = metrics.get("estimated_keyspace_bits")
    if point is None:
        return None

    if ci is not None:
        lo, hi = ci["lower"], ci["upper"]
        values_lo, values_hi = 2 ** lo, 2 ** hi
        range_txt = (
            f"Estimated keyspace \u2248 {point} bits (95% CI {lo}\u2013{hi}). "
            f"Roughly {_human_count(values_lo)}\u2013{_human_count(values_hi)} values."
        )
    else:
        range_txt = f"Estimated keyspace \u2248 {point} bits (point estimate only, no CI on this Finding)."

    values_point = 2 ** point
    seconds = values_point / rate_rps if rate_rps > 0 else float("inf")
    enum_txt = (
        f"At {rate_rps:.0f} req/s this space is enumerable in "
        f"{_human_duration(seconds)}."
    )
    return f"{range_txt} {enum_txt}"


def _entropy_clause(metrics: dict) -> Optional[str]:
    """Shared by BOLA and Excessive Data Exposure's non-numeric branch."""
    avg_bits = metrics.get("avg_entropy_bits")
    if avg_bits is None:
        return None
    estimator = metrics.get("estimator", "plugin")
    threshold = metrics.get("entropy_threshold")
    norm = metrics.get("avg_normalized_entropy")
    estimator_txt = "bias-corrected Miller\u2013Madow" if estimator == "miller_madow" else "plugin"
    pct = f", {norm * 100:.0f}% of the maximum for the observed alphabet" if norm is not None else ""
    thr_txt = f" (below the {threshold}-bit threshold)" if threshold is not None else ""
    return (
        f"Average entropy \u2248 {avg_bits} bits per symbol ({estimator_txt} "
        f"estimator){pct}{thr_txt}."
    )


def _sequential_clause(metrics: dict) -> Optional[str]:
    score = metrics.get("sequential_score")
    if score is None:
        return None
    threshold = metrics.get("sequential_threshold")
    flagged = "highly_sequential" in metrics.get("triggered_by", [])
    if not flagged and threshold is not None and score < threshold:
        return None  # not a contributing signal; don't clutter the text
    return f"Combined with a sequential score of {score} (threshold {threshold})." if threshold is not None else None


# ----------------------------------------------------------------------
# Per-rule explainers
# ----------------------------------------------------------------------
def _explain_bola(finding: Finding, rate_rps: float) -> str:
    m = finding.metrics
    parts = []
    scheme = finding.evidence.get("id_scheme", "unknown")
    if scheme == "numeric":
        clause = _keyspace_clause(m, rate_rps)
        if clause:
            parts.append(clause)
    else:
        clause = _entropy_clause(m)
        if clause:
            parts.append(clause)

    seq_clause = _sequential_clause(m)
    if seq_clause:
        parts.append(seq_clause)

    verdict = (
        "This is a high-confidence predictable-ID (BOLA) surface."
        if len(m.get("triggered_by", [])) > 1
        else "This is enough on its own to flag a predictable-ID (BOLA) risk."
    )
    parts.append(verdict)
    return " ".join(parts)


def _explain_excessive_data_field(field_metrics: dict, field_name: str, rate_rps: float) -> str:
    parts = [f"Field `{field_name}`:"]
    keyspace_clause = _keyspace_clause(field_metrics, rate_rps)
    entropy_clause = _entropy_clause(field_metrics)
    if keyspace_clause:
        parts.append(keyspace_clause)
    if entropy_clause:
        parts.append(entropy_clause)
    seq_clause = _sequential_clause(field_metrics)
    if seq_clause:
        parts.append(seq_clause)
    return " ".join(parts)


def _explain_excessive_data(finding: Finding, rate_rps: float) -> str:
    m = finding.metrics
    if "offenders" in m:
        # Aggregate finding across many fields (_evaluate_many).
        offenders = m["offenders"]
        names = ", ".join(f"`{o['field']}`" for o in offenders)
        header = (
            f"{len(offenders)} field(s) show excessive-exposure signals: {names}."
        )
        details = [
            _explain_excessive_data_field(o["metrics"], o["field"], rate_rps)
            for o in offenders
        ]
        return header + " " + " ".join(details)

    # Single-field finding (_evaluate_one).
    field_name = m.get("field", "value")
    return _explain_excessive_data_field(m, field_name, rate_rps)


def _explain_resource_consumption(finding: Finding, rate_rps: float) -> str:
    m = finding.metrics
    parts = []
    triggered = m.get("triggered_by", [])
    if "queue_overload" in triggered:
        parts.append(
            f"Modelled queue length reached {m.get('max_queue_length')} against a "
            f"threshold of {m.get('queue_threshold')} \u2014 arrivals sustained a rate "
            "above the endpoint's estimated drain capacity."
        )
    if "sustained_acceleration" in triggered:
        parts.append(
            f"Request rate showed sustained positive acceleration above "
            f"{m.get('accel_threshold')} for {m.get('sustained_windows')} consecutive "
            "windows \u2014 a pattern consistent with a scripted ramp rather than "
            "organic traffic growth."
        )
    parts.append(
        "This indicates the endpoint lacks effective rate limiting against "
        "unrestricted resource consumption."
    )
    return " ".join(parts)


def _explain_mass_assignment(finding: Finding, rate_rps: float) -> str:
    m = finding.metrics
    e = finding.evidence
    parts = []
    write_only = e.get("write_only_fields", [])
    if write_only:
        field_list = ", ".join(f"`{f}`" for f in write_only)
        plural = "s are" if len(write_only) != 1 else " is"
        parts.append(
            f"{len(write_only)} field{plural} accepted on write but never appear "
            f"in any read response: {field_list}. A field a client can set but "
            "never observe reading back is very unlikely to be intentional "
            "client-facing design."
        )
    j = m.get("jaccard_index")
    thr = m.get("jaccard_threshold")
    if j is not None and "low_field_overlap" in m.get("triggered_by", []):
        parts.append(
            f"Read/write field overlap (Jaccard index) is {j}, below the {thr} "
            "threshold \u2014 the writable and readable surfaces have diverged "
            "structurally."
        )
    return " ".join(parts) if parts else "Read and write field sets diverge structurally."


def _explain_generic(finding: Finding, rate_rps: float) -> str:
    """
    Fallback for any rule_id not explicitly handled above. Keeps the
    layer total: a new rule added later still produces readable text
    instead of a blank explanation, using whatever metrics it happens
    to carry.
    """
    triggered = finding.metrics.get("triggered_by")
    trig_txt = f" Triggered by: {', '.join(triggered)}." if triggered else ""
    return f"{finding.description}{trig_txt}"


_EXPLAINERS: Dict[str, Callable[[Finding, float], str]] = {
    "API1:2023": _explain_bola,
    "API3:2023": _explain_excessive_data,
    "API4:2023": _explain_resource_consumption,
    "API6:2023": _explain_mass_assignment,
}


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def explain(finding: Finding, rate_rps: float = DEFAULT_PROBE_RATE_RPS) -> str:
    """
    Render a Finding's metrics as a short, human-readable rationale.

    `rate_rps` is only used for the keyspace enumeration-time estimate
    (BOLA / Excessive Data Exposure numeric branches) and is stated
    explicitly in the output text since it's an assumption, not
    something the engine measured.
    """
    handler = _EXPLAINERS.get(finding.rule_id, _explain_generic)
    return handler(finding, rate_rps)


def explain_all(findings, rate_rps: float = DEFAULT_PROBE_RATE_RPS) -> Dict[str, str]:
    """Convenience: explain a list of Findings, keyed by rule_id + target."""
    return {f"{f.rule_id}:{f.target}": explain(f, rate_rps) for f in findings}
