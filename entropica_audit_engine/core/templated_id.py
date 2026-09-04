"""
Shared templated-ID structural signal — measurement and decision, kept
deliberately separate, and deliberately shared between rules/bola.py and
calibration/harness.py rather than implemented twice.

Why shared: the decomposition + numeric-vs-non-numeric-suffix routing
logic is the part that's actually easy to get subtly wrong (it already
has been, twice, earlier this session — a whole-string-entropy version
that missed the bookTitle pattern, then a character-entropy-on-suffix
version that measured the wrong quantity for numeric suffixes). A third
independent copy inside the calibration harness would be a third place
that exact bug could reappear without the other two knowing. One shared
implementation means a fix here is a fix everywhere it's used.

Why two functions, not one: mirrors the split every other MathCore
primitive already uses (estimated_keyspace_bits, sequential_score return
bare numbers; the *caller* decides what counts as "too small"):

  measure_templated_id() — pure measurement. No threshold, no boolean
      verdict. Given thresholds live in two different places with two
      different jobs (a rule's fixed config vs. a calibration sweep
      trying many threshold values against the same stored data), baking
      a threshold into the measurement would make the calibration sweep
      pointless — it needs the raw numbers so it can compare against
      *many* threshold values after the fact, not one baked-in verdict.

  templated_id_triggered() — the threshold comparison, factored out
      separately so it's one small, easily-inspected piece of logic
      instead of being retyped by hand in two files.

Both take thresholds as explicit arguments rather than reading from any
instance/config state, so this module has no hidden dependencies and no
I/O — same "pure function of (data, thresholds)" property calibration's
own would_trigger() already relies on.
"""

from __future__ import annotations

from typing import Optional, Sequence, Union

from .math_core import MathCore


def measure_templated_id(
    sample_ids: Sequence[Union[str, int]],
    min_prefix_len: int = 3,
    min_fixed_fraction: float = 0.3,
    use_miller_madow: bool = True,
) -> dict:
    """
    Decompose a sample into a shared prefix + varying suffix, and
    measure the suffix with whichever tool actually fits its shape:
    keyspace_bits_ci (with its confidence interval) if the suffix is
    numeric, entropy-on-the-suffix-only if it isn't. No threshold
    judgment - see module docstring.

    Returns:
        common_prefix: str
        prefix_length: int
        avg_fixed_fraction: float
        has_template: bool - purely structural (prefix_length >=
            min_prefix_len and avg_fixed_fraction >= min_fixed_fraction).
            NOT a vulnerability judgment - a long, coincidentally-shared
            prefix on otherwise-random tokens isn't itself a finding.
        suffix_kind: Optional[str] - "numeric", "non-numeric", or None
            if has_template is False.
        suffix_keyspace_bits: Optional[float]
        suffix_keyspace_bits_ci_95: Optional[dict] - {point, lower, upper}
        suffix_sequential_score: Optional[float]
        suffix_entropy_bits: Optional[float]
    """
    decomp = MathCore.decompose_template(sample_ids)
    result: dict = {
        "common_prefix": decomp["common_prefix"],
        "prefix_length": decomp["prefix_length"],
        "avg_fixed_fraction": decomp["avg_fixed_fraction"],
        "has_template": (
            decomp["prefix_length"] >= min_prefix_len
            and decomp["avg_fixed_fraction"] >= min_fixed_fraction
        ),
        "suffix_kind": None,
        "suffix_keyspace_bits": None,
        "suffix_keyspace_bits_ci_95": None,
        "suffix_sequential_score": None,
        "suffix_entropy_bits": None,
    }
    if not result["has_template"]:
        return result

    if decomp["suffixes_numeric"] is not None and len(decomp["suffixes_numeric"]) >= 3:
        result["suffix_kind"] = "numeric"
        numeric = decomp["suffixes_numeric"]
        suf_bits = MathCore.estimated_keyspace_bits(numeric)
        suf_ci = MathCore.keyspace_bits_ci(numeric)
        suf_seq = MathCore.sequential_score(numeric)
        result["suffix_keyspace_bits"] = round(suf_bits, 2) if suf_bits is not None else None
        if suf_ci is not None:
            point, lo, hi = suf_ci
            result["suffix_keyspace_bits_ci_95"] = {
                "point": round(point, 2), "lower": round(lo, 2), "upper": round(hi, 2),
            }
        result["suffix_sequential_score"] = round(suf_seq, 3)
    else:
        result["suffix_kind"] = "non-numeric"
        entropy_fn = MathCore.miller_madow_entropy if use_miller_madow else MathCore.shannon_entropy
        suf_entropies = [entropy_fn(s) for s in decomp["suffixes"] if s]
        if suf_entropies:
            result["suffix_entropy_bits"] = round(sum(suf_entropies) / len(suf_entropies), 3)

    return result


def templated_id_triggered(
    measured: dict,
    entropy_threshold: float,
    sequential_threshold: float,
    keyspace_bit_threshold: float,
) -> bool:
    """
    The threshold comparison, kept separate from measurement (see module
    docstring). Reuses the SAME three thresholds already exposed on
    PredictableResourceIDRule for plain numeric/non-numeric IDs - there
    is no fourth, separately-calibrated threshold for the templated
    case; a templated numeric suffix is judged exactly like a plain
    numeric ID would be, a templated non-numeric suffix exactly like a
    plain non-numeric ID would be.
    """
    if not measured.get("has_template"):
        return False
    if measured["suffix_kind"] == "numeric":
        bits = measured.get("suffix_keyspace_bits")
        seq = measured.get("suffix_sequential_score")
        small_keyspace = bits is not None and bits < keyspace_bit_threshold
        highly_sequential = seq is not None and seq >= sequential_threshold
        return small_keyspace or highly_sequential
    if measured["suffix_kind"] == "non-numeric":
        ent = measured.get("suffix_entropy_bits")
        return ent is not None and ent < entropy_threshold
    return False
