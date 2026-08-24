"""
Calibration harness (project notes, section 1 — "Real-world Calibration",
MANDATORY).

Scope of this module, stated plainly
-------------------------------------
This harness fully implements the "Synthetic but realistic generators"
bullet from the notes' Sources list. It does NOT implement the other
listed sources: OWASP crAPI / VAmPI, public APIs, or staging environments
you control — those need live network access this environment doesn't
have. Running `python -m entropica_audit_engine.calibration.harness`
gives you a real, honest calibration pass against synthetic data — not a
substitute for the real-traffic pass the notes call MANDATORY.

The record format below is deliberately generator-agnostic: `collect()`
builds CalibrationRecords from the synthetic generators, but
`records_from_samples()` builds the exact same record shape from any
(samples, label) pair you hand it — including real captures from crAPI,
VAmPI, or a staging target. Point it at real data later and everything
downstream (the sweeps, the report) works unchanged. Appending real
records to the same JSONL file the synthetic pass writes is the intended
way to close that gap, not a rewrite of this module.

Why raw MathCore, not the rules
--------------------------------
Rule.execute() returns None when nothing crosses today's threshold,
which throws away the metric value for every non-triggering sample —
exactly the data a threshold sweep needs. This harness calls MathCore
directly and stores the raw numbers; "would this trigger" is then a
pure function of (record, threshold) computed after the fact, so a
sweep never re-runs a generator or a rule.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from entropica_audit_engine.core.math_core import MathCore

from .generators import GENERATORS, GeneratorResult

DEFAULT_SAMPLE_SIZES: Tuple[int, ...] = (5, 10, 20, 50, 100)
DEFAULT_SEEDS: Tuple[int, ...] = (0, 1, 2)

# Mirrors PredictableResourceIDRule's constructor defaults (rules/bola.py).
# Kept as a separate constant rather than importing the rule, so this
# module never depends on rules/ — calibration must stay usable even if
# a rule's constructor signature changes.
RULE_DEFAULTS = {
    "entropy_threshold": 3.0,
    "sequential_threshold": 0.7,
    "keyspace_bit_threshold": 32.0,
}


# ----------------------------------------------------------------------
# Record schema
# ----------------------------------------------------------------------
@dataclass
class CalibrationRecord:
    """
    One (scheme, n, seed) observation. Every field is either an input
    (scheme, label, n, seed) or a number MathCore actually computed —
    nothing here is a rule's yes/no decision. Ground truth (`label`) is
    "safe" / "vulnerable" / "mixed" (see generators.py for what each
    means); for real captures rather than synthetic generators, use
    "unknown" if there's no ground truth yet — sweeps and confusion
    counts exclude anything that isn't exactly "safe" or "vulnerable".
    """

    scheme: str
    label: str
    n: int
    seed: int
    id_type: str  # "numeric" | "non-numeric"
    sequential_score: float
    estimated_keyspace_bits: Optional[float] = None
    keyspace_ci_lower: Optional[float] = None
    keyspace_ci_upper: Optional[float] = None
    avg_entropy_plugin: Optional[float] = None
    avg_entropy_mm: Optional[float] = None
    avg_normalized_entropy: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CalibrationRecord":
        return cls(**d)


def records_from_samples(
    scheme: str, samples: Sequence, label: str, seed: int
) -> CalibrationRecord:
    """
    Build a CalibrationRecord from any sample list — synthetic or real.
    This is the one place raw samples get turned into stored metrics;
    everything downstream only ever touches the record, never the
    samples themselves (real captures may be sensitive; the record
    intentionally does not retain the raw values).
    """
    n = len(samples)
    seq_score = MathCore.sequential_score(samples)
    numeric = MathCore.parse_numeric_ids(samples)

    if numeric is not None:
        est_bits = MathCore.estimated_keyspace_bits(samples)
        ci = MathCore.keyspace_bits_ci(samples)
        lo, hi = (ci[1], ci[2]) if ci is not None else (None, None)
        return CalibrationRecord(
            scheme=scheme,
            label=label,
            n=n,
            seed=seed,
            id_type="numeric",
            sequential_score=seq_score,
            estimated_keyspace_bits=est_bits,
            keyspace_ci_lower=lo,
            keyspace_ci_upper=hi,
        )

    plugin = [MathCore.shannon_entropy(str(s)) for s in samples]
    mm = [MathCore.miller_madow_entropy(str(s)) for s in samples]
    norm = [MathCore.normalized_entropy(str(s)) for s in samples]
    return CalibrationRecord(
        scheme=scheme,
        label=label,
        n=n,
        seed=seed,
        id_type="non-numeric",
        sequential_score=seq_score,
        avg_entropy_plugin=sum(plugin) / len(plugin),
        avg_entropy_mm=sum(mm) / len(mm),
        avg_normalized_entropy=sum(norm) / len(norm),
    )


def collect(
    sample_sizes: Sequence[int] = DEFAULT_SAMPLE_SIZES,
    seeds: Sequence[int] = DEFAULT_SEEDS,
    generators: Dict[str, callable] = GENERATORS,
) -> List[CalibrationRecord]:
    """Run every registered generator at every (size, seed) pair."""
    records: List[CalibrationRecord] = []
    for scheme, gen in generators.items():
        for n in sample_sizes:
            for seed in seeds:
                samples, label = gen(n, seed=seed)
                records.append(records_from_samples(scheme, samples, label, seed))
    return records


# ----------------------------------------------------------------------
# Persistence — JSON Lines (project notes: "JSON or simple tables")
# ----------------------------------------------------------------------
def save_jsonl(records: Iterable[CalibrationRecord], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for r in records:
            f.write(json.dumps(r.to_dict()) + "\n")


def load_jsonl(path: str) -> List[CalibrationRecord]:
    records = []
    with Path(path).open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(CalibrationRecord.from_dict(json.loads(line)))
    return records


# ----------------------------------------------------------------------
# Decision logic mirrored from PredictableResourceIDRule, applied to
# stored records instead of live samples — this is what makes a sweep
# possible without re-running anything.
# ----------------------------------------------------------------------
def would_trigger(
    r: CalibrationRecord,
    entropy_threshold: float = RULE_DEFAULTS["entropy_threshold"],
    sequential_threshold: float = RULE_DEFAULTS["sequential_threshold"],
    keyspace_bit_threshold: float = RULE_DEFAULTS["keyspace_bit_threshold"],
    use_mm: bool = True,
) -> Tuple[bool, List[str]]:
    triggered_by: List[str] = []
    if r.sequential_score >= sequential_threshold:
        triggered_by.append("highly_sequential")

    if r.id_type == "numeric":
        if (
            r.estimated_keyspace_bits is not None
            and r.estimated_keyspace_bits < keyspace_bit_threshold
        ):
            triggered_by.append("small_keyspace")
    else:
        entropy = r.avg_entropy_mm if use_mm else r.avg_entropy_plugin
        if entropy is not None and entropy < entropy_threshold:
            triggered_by.append("low_entropy")

    return (len(triggered_by) > 0, triggered_by)


# ----------------------------------------------------------------------
# Confusion counts + sweeps
# ----------------------------------------------------------------------
@dataclass
class ConfusionCounts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    excluded_mixed: int = 0
    excluded_unknown: int = 0

    @property
    def tpr(self) -> Optional[float]:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def fpr(self) -> Optional[float]:
        denom = self.fp + self.tn
        return self.fp / denom if denom else None

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def youden_j(self) -> Optional[float]:
        """TPR - FPR. Simple, standard threshold-quality summary; not
        the only reasonable criterion (a precision-focused reading of
        the same sweep can pick a different threshold) — surfaced as
        one signal for a human to weigh, not an automatic answer."""
        if self.tpr is None or self.fpr is None:
            return None
        return self.tpr - self.fpr


def confusion(
    records: Sequence[CalibrationRecord], **threshold_kwargs
) -> ConfusionCounts:
    c = ConfusionCounts()
    for r in records:
        if r.label == "mixed":
            c.excluded_mixed += 1
            continue
        if r.label not in ("safe", "vulnerable"):
            c.excluded_unknown += 1
            continue
        triggered, _ = would_trigger(r, **threshold_kwargs)
        positive = r.label == "vulnerable"
        if positive and triggered:
            c.tp += 1
        elif positive and not triggered:
            c.fn += 1
        elif not positive and triggered:
            c.fp += 1
        else:
            c.tn += 1
    return c


def sweep(
    records: Sequence[CalibrationRecord],
    param: str,
    values: Sequence[float],
    **fixed_kwargs,
) -> List[dict]:
    """
    Sweep one threshold parameter (must be a keyword `would_trigger`
    accepts: entropy_threshold, sequential_threshold, or
    keyspace_bit_threshold) across `values`, holding the others at
    RULE_DEFAULTS unless overridden in `fixed_kwargs`.
    """
    rows = []
    base = dict(RULE_DEFAULTS)
    base.update(fixed_kwargs)
    for v in values:
        kwargs = dict(base)
        kwargs[param] = v
        c = confusion(records, **kwargs)
        rows.append(
            {
                param: v,
                "tp": c.tp,
                "fp": c.fp,
                "tn": c.tn,
                "fn": c.fn,
                "tpr": c.tpr,
                "fpr": c.fpr,
                "precision": c.precision,
                "youden_j": c.youden_j,
            }
        )
    return rows


def best_by_youden(rows: List[dict], param: str) -> Optional[dict]:
    """Row with the highest Youden's J (ties broken by lower FPR).
    Returns None if every row has an undefined J (e.g. no data for
    one class in this record set)."""
    candidates = [r for r in rows if r["youden_j"] is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (r["youden_j"], -r["fpr"]))


# ----------------------------------------------------------------------
# Decisive-signal counts (notes: "which signal is decisive most often")
# ----------------------------------------------------------------------
def decisive_signal_counts(
    records: Sequence[CalibrationRecord], **threshold_kwargs
) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in records:
        if r.label != "vulnerable":
            continue
        _, triggered_by = would_trigger(r, **threshold_kwargs)
        for signal in triggered_by:
            counts[signal] = counts.get(signal, 0) + 1
    return counts


# ----------------------------------------------------------------------
# Per-scheme summary stats (stand-in for full histograms/CDFs — see
# module docstring; a plotting pass can build on these same records)
# ----------------------------------------------------------------------
def scheme_summary(records: Sequence[CalibrationRecord]) -> List[dict]:
    by_scheme: Dict[str, List[CalibrationRecord]] = {}
    for r in records:
        by_scheme.setdefault(r.scheme, []).append(r)

    rows = []
    for scheme, recs in sorted(by_scheme.items()):
        label = recs[0].label
        id_type = recs[0].id_type
        if id_type == "numeric":
            vals = [r.estimated_keyspace_bits for r in recs if r.estimated_keyspace_bits is not None]
            metric_name = "keyspace_bits"
        else:
            vals = [r.avg_entropy_mm for r in recs if r.avg_entropy_mm is not None]
            metric_name = "entropy_bits_mm"
        if not vals:
            continue
        vals_sorted = sorted(vals)
        rows.append(
            {
                "scheme": scheme,
                "label": label,
                "id_type": id_type,
                "metric": metric_name,
                "n_records": len(vals),
                "min": round(min(vals_sorted), 2),
                "median": round(statistics.median(vals_sorted), 2),
                "mean": round(sum(vals_sorted) / len(vals_sorted), 2),
                "p95": round(vals_sorted[int(0.95 * (len(vals_sorted) - 1))], 2),
                "max": round(max(vals_sorted), 2),
            }
        )
    return rows


# ----------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------
def render_markdown(
    records: Sequence[CalibrationRecord],
    entropy_sweep_values: Sequence[float] = (1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0),
    keyspace_sweep_values: Sequence[float] = (8, 12, 16, 20, 24, 28, 32, 36, 40),
) -> str:
    lines: List[str] = []
    lines.append("# ENTROPICA Calibration Report (synthetic pass)")
    lines.append("")
    lines.append(
        "**Scope**: synthetic generators only (see `calibration/generators.py`). "
        "This is NOT the real/realistic-traffic pass the project notes call "
        "MANDATORY (OWASP crAPI, VAmPI, public APIs, staging) — that still "
        "needs to be run separately, from an environment with network access "
        "to those targets, and appended to this same record format."
    )
    lines.append("")
    lines.append(f"Total records: {len(records)}")
    labels = {}
    for r in records:
        labels[r.label] = labels.get(r.label, 0) + 1
    lines.append(f"By label: {labels}")
    lines.append("")

    lines.append("## Per-scheme summary (at rule-default thresholds' native units)")
    lines.append("")
    lines.append("| scheme | label | id_type | metric | n | min | median | mean | p95 | max |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for row in scheme_summary(records):
        lines.append(
            f"| {row['scheme']} | {row['label']} | {row['id_type']} | {row['metric']} "
            f"| {row['n_records']} | {row['min']} | {row['median']} | {row['mean']} "
            f"| {row['p95']} | {row['max']} |"
        )
    lines.append("")

    entropy_rows = sweep(records, "entropy_threshold", entropy_sweep_values)
    lines.append("## Entropy threshold sweep (non-numeric schemes)")
    lines.append("")
    lines.append("| entropy_threshold | tp | fp | tn | fn | tpr | fpr | precision | youden_j |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for row in entropy_rows:
        lines.append(
            f"| {row['entropy_threshold']} | {row['tp']} | {row['fp']} | {row['tn']} "
            f"| {row['fn']} | {_fmt(row['tpr'])} | {_fmt(row['fpr'])} "
            f"| {_fmt(row['precision'])} | {_fmt(row['youden_j'])} |"
        )
    best_entropy = best_by_youden(entropy_rows, "entropy_threshold")
    lines.append("")
    if best_entropy:
        lines.append(
            f"Highest Youden's J on this synthetic set: "
            f"`entropy_threshold={best_entropy['entropy_threshold']}` "
            f"(current rule default: {RULE_DEFAULTS['entropy_threshold']}). "
            "Advisory only — not applied automatically."
        )
    lines.append("")

    keyspace_rows = sweep(records, "keyspace_bit_threshold", keyspace_sweep_values)
    lines.append("## Keyspace-bits threshold sweep (numeric schemes)")
    lines.append("")
    lines.append("| keyspace_bit_threshold | tp | fp | tn | fn | tpr | fpr | precision | youden_j |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for row in keyspace_rows:
        lines.append(
            f"| {row['keyspace_bit_threshold']} | {row['tp']} | {row['fp']} | {row['tn']} "
            f"| {row['fn']} | {_fmt(row['tpr'])} | {_fmt(row['fpr'])} "
            f"| {_fmt(row['precision'])} | {_fmt(row['youden_j'])} |"
        )
    best_keyspace = best_by_youden(keyspace_rows, "keyspace_bit_threshold")
    lines.append("")
    if best_keyspace:
        lines.append(
            f"Highest Youden's J on this synthetic set: "
            f"`keyspace_bit_threshold={best_keyspace['keyspace_bit_threshold']}` "
            f"(current rule default: {RULE_DEFAULTS['keyspace_bit_threshold']}). "
            "Advisory only — not applied automatically."
        )
    lines.append("")

    decisive = decisive_signal_counts(records)
    lines.append("## Decisive-signal counts (among vulnerable-labeled records, at rule defaults)")
    lines.append("")
    for signal, count in sorted(decisive.items(), key=lambda kv: -kv[1]):
        lines.append(f"- `{signal}`: {count}")
    lines.append("")

    mm_deltas = [
        r.avg_entropy_mm - r.avg_entropy_plugin
        for r in records
        if r.avg_entropy_mm is not None and r.avg_entropy_plugin is not None
    ]
    if mm_deltas:
        lines.append("## Miller-Madow correction size (mean bits added vs. plugin estimator)")
        lines.append("")
        lines.append(f"Mean: {sum(mm_deltas) / len(mm_deltas):.4f} bits over {len(mm_deltas)} records.")
        small_n = [r for r in records if r.n <= 10 and r.avg_entropy_mm is not None]
        if small_n:
            small_deltas = [r.avg_entropy_mm - r.avg_entropy_plugin for r in small_n]
            lines.append(
                f"At n<=10 specifically: mean {sum(small_deltas) / len(small_deltas):.4f} bits "
                f"over {len(small_deltas)} records — the small-sample regime section 2.1 "
                "of the notes calls out as where the correction matters most."
            )
        lines.append("")

    return "\n".join(lines)


def _fmt(x: Optional[float]) -> str:
    return "-" if x is None else f"{x:.3f}"


# ----------------------------------------------------------------------
# CLI entrypoint
# ----------------------------------------------------------------------
def run(
    output_dir: str = "calibration_output",
    sample_sizes: Sequence[int] = DEFAULT_SAMPLE_SIZES,
    seeds: Sequence[int] = DEFAULT_SEEDS,
) -> Tuple[str, str]:
    """Collect, save records + render report. Returns (jsonl_path, md_path)."""
    records = collect(sample_sizes=sample_sizes, seeds=seeds)
    out = Path(output_dir)
    jsonl_path = str(out / "calibration_records.jsonl")
    md_path = str(out / "calibration_report.md")
    save_jsonl(records, jsonl_path)
    Path(md_path).parent.mkdir(parents=True, exist_ok=True)
    Path(md_path).write_text(render_markdown(records))
    return jsonl_path, md_path


if __name__ == "__main__":
    jsonl_path, md_path = run()
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {md_path}")
