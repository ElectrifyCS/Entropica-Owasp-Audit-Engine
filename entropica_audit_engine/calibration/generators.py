"""
Synthetic ID generators for the calibration harness (project notes,
section 1, "Sources").

Every generator returns (samples, label) where label is one of:

  "safe"       — a properly-designed ID scheme; a well-calibrated rule
                 should NOT flag it (a true negative if flagged = FP).
  "vulnerable" — a genuinely weak ID scheme; a well-calibrated rule
                 SHOULD flag it (a true positive if flagged = TP).
  "mixed"      — a real-world scheme with partial predictability
                 (snowflake IDs, ULIDs) that doesn't cleanly belong in
                 either bucket. Excluded from the strict TP/FP/FN/TN
                 sweep and reported on separately — labeling these as
                 a hard safe/vulnerable binary would itself be a
                 numerical-honesty violation of the kind these notes
                 are about avoiding.

The notes' own generator list (UUIDv4, ULID, snowflake, auto-increment,
short tokens, base62) covers only ONE label per ID scheme (numeric IDs
are all "vulnerable" or "mixed"; non-numeric IDs are all "safe" or
"mixed"). A threshold sweep needs a negative example in each branch to
compute a real false-positive rate, so two generators are added beyond
the notes' list: `large_random_int` (a safe numeric ID) and
`predictable_session_token` (a vulnerable non-numeric ID). Both are
realistic, common real-world patterns, not synthetic edge cases invented
just to pad the dataset.

All generators are seeded for reproducibility — calibration numbers
that change on every run because of unseeded randomness would defeat
the purpose of writing them down.
"""

from __future__ import annotations

import random
import string
import uuid
from typing import Callable, Dict, List, Tuple

Sample = object  # int or str
GeneratorResult = Tuple[List[Sample], str]  # (samples, label)


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


# ----------------------------------------------------------------------
# Numeric — vulnerable
# ----------------------------------------------------------------------
def generate_auto_increment(n: int, seed: int = 0) -> GeneratorResult:
    """Classic auto-increment primary key. Textbook BOLA target."""
    r = _rng(seed)
    start = r.randint(1000, 50000)
    return [start + i for i in range(n)], "vulnerable"


def generate_short_numeric_token(n: int, seed: int = 0, digits: int = 4) -> GeneratorResult:
    """Small fixed-width numeric token (e.g. a 4-digit invite/reset code)."""
    r = _rng(seed)
    lo, hi = 10 ** (digits - 1), 10 ** digits - 1
    return [r.randint(lo, hi) for _ in range(n)], "vulnerable"


# ----------------------------------------------------------------------
# Numeric — safe
# ----------------------------------------------------------------------
def generate_large_random_int(n: int, seed: int = 0, bits: int = 60) -> GeneratorResult:
    """
    A numeric ID drawn uniformly from a genuinely large keyspace (e.g. a
    properly randomized 64-bit-ish integer ID, not a database
    auto-increment). Added beyond the notes' generator list: without a
    safe numeric example, the keyspace-threshold sweep has no negative
    class to measure a false-positive rate against.
    """
    r = _rng(seed)
    upper = 2 ** bits
    return [r.randint(0, upper) for _ in range(n)], "safe"


# ----------------------------------------------------------------------
# Numeric — mixed (partial predictability)
# ----------------------------------------------------------------------
def generate_snowflake_like(n: int, seed: int = 0) -> GeneratorResult:
    """
    Twitter-snowflake-style ID: (timestamp_ms << 22) | (machine_id << 12)
    | sequence. Monotonically increasing over time and small-stepped
    within the same millisecond, but with a genuinely large total
    keyspace. Real systems use these; whether they should count as
    "predictable" is exactly the kind of judgment call calibration data
    is for, not a coin flip made once in a docstring.
    """
    r = _rng(seed)
    machine_id = r.randint(0, 31)
    seq = r.randint(0, 100)
    # A plausible-looking ms-epoch value drawn from the seeded RNG rather
    # than time.time(): the class of ID (small-stepped, time-ordered) is
    # what matters for calibration, not that it lines up with the actual
    # wall clock. Using real time here silently broke the "seeded for
    # reproducibility" guarantee this module's docstring promises — two
    # `collect()` passes a moment apart produced different records.
    base_ms = r.randint(10 ** 12, 10 ** 13)
    ids = []
    for i in range(n):
        ms = base_ms + (i // 4)  # a few IDs share each millisecond
        seq = (seq + 1) % 4096
        ids.append((ms << 22) | (machine_id << 12) | seq)
    return ids, "mixed"


# ----------------------------------------------------------------------
# Non-numeric — safe
# ----------------------------------------------------------------------
def generate_uuidv4(n: int, seed: int = 0) -> GeneratorResult:
    r = _rng(seed)
    # uuid.uuid4() uses os.urandom internally and ignores a Random
    # instance, so build v4-shaped UUIDs from the seeded RNG directly
    # for reproducibility.
    ids = []
    for _ in range(n):
        raw = r.getrandbits(128)
        ids.append(str(uuid.UUID(int=raw, version=4)))
    return ids, "safe"


def generate_base62_token(n: int, seed: int = 0, length: int = 12) -> GeneratorResult:
    r = _rng(seed)
    alphabet = string.ascii_letters + string.digits  # 62 symbols
    return ["".join(r.choices(alphabet, k=length)) for _ in range(n)], "safe"


def generate_hex_token(n: int, seed: int = 0, length: int = 32) -> GeneratorResult:
    r = _rng(seed)
    return [f"{r.getrandbits(length * 4):0{length}x}" for _ in range(n)], "safe"


# ----------------------------------------------------------------------
# Non-numeric — mixed
# ----------------------------------------------------------------------
def generate_ulid_like(n: int, seed: int = 0) -> GeneratorResult:
    """
    ULID: a 48-bit timestamp prefix (lexicographically sortable, and
    therefore partially predictable in time) followed by 80 bits of
    randomness. Higher entropy than a snowflake ID but not the pure
    randomness of a UUIDv4 — another real "mixed" case.
    """
    r = _rng(seed)
    crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    # See generate_snowflake_like: seeded, not wall-clock, so this
    # generator is actually reproducible rather than only appearing to be
    # (the old version passed test_reproducible_given_same_seed only
    # because both calls in that test land in the same millisecond).
    base_ms = r.randint(10 ** 12, 10 ** 13)
    ids = []
    for i in range(n):
        ms = base_ms + i
        ts_part = "".join(crockford[(ms >> (5 * k)) % 32] for k in reversed(range(10)))
        rand_part = "".join(r.choices(crockford, k=16))
        ids.append(ts_part + rand_part)
    return ids, "mixed"


# ----------------------------------------------------------------------
# Non-numeric — vulnerable
# ----------------------------------------------------------------------
def generate_predictable_session_token(n: int, seed: int = 0) -> GeneratorResult:
    """
    A low-alphabet, structurally repetitive token — e.g. a hand-rolled
    "session_<counter>" scheme. Added beyond the notes' generator list:
    without a vulnerable non-numeric example, the entropy-threshold
    sweep has no positive class to measure a true-positive rate against.
    """
    r = _rng(seed)
    start = r.randint(1, 500)
    return [f"sess{start + i:05d}" for i in range(n)], "vulnerable"


# ----------------------------------------------------------------------
# crAPI-oriented (Priority 4 — second target scaffolding)
# ----------------------------------------------------------------------
def generate_crapi_vehicle_id(n: int, seed: int = 0) -> GeneratorResult:
    """
    Numeric-ish vehicle / order IDs in the style commonly seen in crAPI
    demos (small sequential or near-sequential integers).  Labelled
    vulnerable so the keyspace + sequential signals have a second-target
    positive class beyond the generic auto_increment generator.
    """
    r = _rng(seed)
    start = r.randint(100, 900)
    return [start + i for i in range(n)], "vulnerable"


def generate_crapi_report_id(n: int, seed: int = 0) -> GeneratorResult:
    """
    Short alphanumeric report identifiers sometimes observed in crAPI-
    style apps.  Low alphabet + short length → entropy signal should fire.
    """
    r = _rng(seed)
    alphabet = string.ascii_lowercase + string.digits
    # Deliberately short and partially patterned
    return [f"rpt{r.randint(10, 99)}{r.choice(alphabet)}" for _ in range(n)], "vulnerable"


# ----------------------------------------------------------------------
# Templated-ID structural signal (core/templated_id.py) — a fixed prefix
# wrapped around a varying suffix. Without these, none of the other nine
# generators exercise this signal at all, so its sweep would have an
# empty confusion matrix — a sweep with nothing to sweep against isn't a
# real calibration pass.
# ----------------------------------------------------------------------
def generate_templated_numeric_suffix_small(n: int, seed: int = 0) -> GeneratorResult:
    """
    Fixed prefix + small numeric suffix (e.g. "bookTitle7") — the exact
    real-data pattern that motivated this signal (a live VAmPI capture
    of book titles, see calibration_output/calibration_report.md).
    Vulnerable: the suffix's true keyspace is small regardless of how
    the whole string's character entropy looks.
    """
    r = _rng(seed)
    lo, hi = r.randint(1, 20), r.randint(30, 90)
    return [f"resourceItem{r.randint(lo, hi)}" for _ in range(n)], "vulnerable"


def generate_templated_numeric_suffix_large(n: int, seed: int = 0) -> GeneratorResult:
    """
    Fixed prefix + genuinely large numeric suffix (~43 true bits) — the
    negative control this signal needs: a real template shape whose
    varying part is NOT actually guessable, so the sweep has something
    to compute a false-positive rate against, not just a positive class.

    Prefix is deliberately longer than a short "txn-" would be: a large
    enough numeric suffix to clear the keyspace threshold needs enough
    digits that a short prefix would fail the fixed-fraction gate
    (avg_fixed_fraction >= 0.3) before the keyspace signal is even
    reached — found by actually running this generator through the
    harness, not assumed.
    """
    r = _rng(seed)
    return [f"transaction-record-{r.randint(0, 2**43):014d}" for _ in range(n)], "safe"


def generate_templated_enum_suffix(n: int, seed: int = 0) -> GeneratorResult:
    """
    Fixed prefix + a small closed set of non-numeric suffixes (e.g.
    environment names) — exercises the OTHER branch of the templated
    signal (suffix entropy, not suffix keyspace), which none of the
    other vulnerable generators touch. A handful of possible suffixes
    is genuinely enumerable regardless of how diverse each individual
    suffix's characters look.
    """
    r = _rng(seed)
    suffixes = ["prod", "stag", "test", "perf", "beta"]
    return [f"session-{r.choice(suffixes)}" for _ in range(n)], "vulnerable"


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------
GENERATORS: Dict[str, Callable[..., GeneratorResult]] = {
    "auto_increment": generate_auto_increment,
    "short_numeric_token": generate_short_numeric_token,
    "large_random_int": generate_large_random_int,
    "snowflake_like": generate_snowflake_like,
    "uuidv4": generate_uuidv4,
    "base62_token": generate_base62_token,
    "hex_token": generate_hex_token,
    "ulid_like": generate_ulid_like,
    "predictable_session_token": generate_predictable_session_token,
    # Priority 4 — crAPI second-target scaffolding
    "crapi_vehicle_id": generate_crapi_vehicle_id,
    "crapi_report_id": generate_crapi_report_id,
    # Templated-ID structural signal
    "templated_numeric_suffix_small": generate_templated_numeric_suffix_small,
    "templated_numeric_suffix_large": generate_templated_numeric_suffix_large,
    "templated_enum_suffix": generate_templated_enum_suffix,
}
