# ENTROPICA Calibration Report (synthetic pass)

**Scope**: synthetic generators only (see `calibration/generators.py`). This is NOT the real/realistic-traffic pass the project notes call MANDATORY (OWASP crAPI, VAmPI, public APIs, staging) — that still needs to be run separately, from an environment with network access to those targets, and appended to this same record format.

Total records: 135
By label: {'vulnerable': 45, 'safe': 60, 'mixed': 30}

## Per-scheme summary (at rule-default thresholds' native units)

| scheme | label | id_type | metric | n | min | median | mean | p95 | max |
|---|---|---|---|---|---|---|---|---|---|
| auto_increment | vulnerable | numeric | keyspace_bits | 15 | 2.58 | 4.39 | 4.55 | 6.66 | 6.66 |
| base62_token | safe | non-numeric | entropy_bits_mm | 15 | 3.87 | 4.03 | 4.02 | 4.06 | 4.11 |
| hex_token | safe | non-numeric | entropy_bits_mm | 15 | 3.84 | 3.9 | 3.9 | 3.97 | 4.0 |
| large_random_int | safe | numeric | keyspace_bits | 15 | 59.69 | 60.02 | 60.04 | 60.3 | 60.42 |
| predictable_session_token | vulnerable | non-numeric | entropy_bits_mm | 15 | 2.35 | 2.63 | 2.56 | 2.7 | 2.72 |
| short_numeric_token | vulnerable | numeric | keyspace_bits | 15 | 12.67 | 13.16 | 13.14 | 13.38 | 13.5 |
| snowflake_like | mixed | numeric | keyspace_bits | 15 | 22.58 | 24.14 | 24.46 | 26.61 | 26.61 |
| ulid_like | mixed | non-numeric | entropy_bits_mm | 15 | 4.49 | 4.56 | 4.57 | 4.62 | 4.65 |
| uuidv4 | safe | non-numeric | entropy_bits_mm | 15 | 3.95 | 3.98 | 3.99 | 4.03 | 4.07 |

## Entropy threshold sweep (non-numeric schemes)

| entropy_threshold | tp | fp | tn | fn | tpr | fpr | precision | youden_j |
|---|---|---|---|---|---|---|---|---|
| 1.5 | 30 | 0 | 60 | 15 | 0.667 | 0.000 | 1.000 | 0.667 |
| 2.0 | 30 | 0 | 60 | 15 | 0.667 | 0.000 | 1.000 | 0.667 |
| 2.5 | 34 | 0 | 60 | 11 | 0.756 | 0.000 | 1.000 | 0.756 |
| 3.0 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 3.5 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 4.0 | 45 | 31 | 29 | 0 | 1.000 | 0.517 | 0.592 | 0.483 |
| 4.5 | 45 | 45 | 15 | 0 | 1.000 | 0.750 | 0.500 | 0.250 |
| 5.0 | 45 | 45 | 15 | 0 | 1.000 | 0.750 | 0.500 | 0.250 |

Highest Youden's J on this synthetic set: `entropy_threshold=3.0` (current rule default: 3.0). Advisory only — not applied automatically.

## Keyspace-bits threshold sweep (numeric schemes)

| keyspace_bit_threshold | tp | fp | tn | fn | tpr | fpr | precision | youden_j |
|---|---|---|---|---|---|---|---|---|
| 8 | 30 | 0 | 60 | 15 | 0.667 | 0.000 | 1.000 | 0.667 |
| 12 | 30 | 0 | 60 | 15 | 0.667 | 0.000 | 1.000 | 0.667 |
| 16 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 20 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 24 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 28 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 32 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 36 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 40 | 45 | 0 | 60 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |

Highest Youden's J on this synthetic set: `keyspace_bit_threshold=16` (current rule default: 32.0). Advisory only — not applied automatically.

## Decisive-signal counts (among vulnerable-labeled records, at rule defaults)

- `small_keyspace`: 30
- `highly_sequential`: 15
- `low_entropy`: 15

## Miller-Madow correction size (mean bits added vs. plugin estimator)

Mean: 0.4008 bits over 75 records.
At n<=10 specifically: mean 0.4041 bits over 30 records — the small-sample regime section 2.1 of the notes calls out as where the correction matters most.
