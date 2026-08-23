"""
Quick demo — run from the project root:

    python -m entropica_audit_engine.demo
"""

from __future__ import annotations

import asyncio
from entropica_audit_engine.rules.registry import build_default_registry
from entropica_audit_engine.core.welford import WelfordTracker, EWMAAnomalyTracker
from entropica_audit_engine.core.queue_dynamics import QueueDynamicsTracker, AccelerationTracker
from entropica_audit_engine.core.math_core import MathCore


async def demo_bola():
    print("=" * 60)
    print("1. Predictable Resource ID (BOLA) check")
    print("=" * 60)

    registry = build_default_registry()
    rule = registry.get("API1:2023")

    async def run(label: str, sample_ids):
        finding = await rule.execute(
            target_url="https://api.example.com/users/{id}",
            sample_ids=sample_ids,
        )
        if finding:
            print(f"🚨 {label}: finding raised — {finding.metrics}")
        else:
            print(f"✅ {label}: no finding")

    # Classic auto-increment IDs, collected out of creation order
    sequential_shuffled = [1005, 1001, 1009, 1003, 1007, 1002, 1010, 1004, 1006, 1008, 1011]
    await run("Sequential IDs (collected out of order)", sequential_shuffled)

    # High-entropy UUIDs
    import uuid
    random_ids = [str(uuid.uuid4()) for _ in range(10)]
    await run("Random UUIDs", random_ids)

    # Small numeric keyspace
    import random as _random
    _random.seed(7)
    small_keyspace = [str(_random.randint(10_000, 99_999)) for _ in range(12)]
    await run("Small-keyspace random numeric IDs (5-digit)", small_keyspace)

    # Large numeric keyspace
    _random.seed(11)
    large_keyspace = [str(_random.randint(1_000_000_000, 9_999_999_999)) for _ in range(12)]
    await run("Large-keyspace random numeric IDs (10-digit)", large_keyspace)


async def demo_excessive_data():
    print("\n" + "=" * 60)
    print("2. Excessive Data Exposure (field entropy)")
    print("=" * 60)

    registry = build_default_registry()
    rule = registry.get("API3:2023")

    # Low-entropy internal tokens
    finding = await rule.execute(
        target_url="https://api.example.com/profile",
        sample_values=["aaaa1", "aaaa2", "aaaa3", "aaaa4", "aaaa5", "aaaa6"],
    )
    if finding:
        print(f"🚨 Low-entropy tokens: {finding.metrics}")
    else:
        print("✅ Low-entropy tokens: no finding (unexpected)")

    # Sequential internal IDs leaking in a response field
    finding = await rule.execute(
        target_url="https://api.example.com/orders",
        sample_values=list(range(5001, 5015)),
    )
    if finding:
        print(f"🚨 Sequential field values: {finding.metrics}")
    else:
        print("✅ Sequential field values: no finding (unexpected)")

    # High-entropy values should clear
    import uuid
    finding = await rule.execute(
        target_url="https://api.example.com/sessions",
        sample_values=[str(uuid.uuid4()) for _ in range(8)],
    )
    if finding:
        print(f"🚨 Random UUIDs (should NOT trigger): {finding.metrics}")
    else:
        print("✅ Random UUIDs: no finding")


def demo_welford_and_ewma():
    print("\n" + "=" * 60)
    print("3. Streaming latency anomaly (Welford + EWMA)")
    print("=" * 60)

    welford = WelfordTracker()
    ewma = EWMAAnomalyTracker(lambda_=0.25, threshold=2.0, min_count=4)

    # Baseline then a sustained elevation (not just a single spike)
    latencies = [42, 45, 41, 44, 43, 40, 46, 120, 130, 125, 140, 135]
    for i, lat in enumerate(latencies, 1):
        z = welford.update(float(lat))
        s = ewma.update(z)
        flag_w = " ← |Z|>3" if welford.is_anomaly() else ""
        flag_e = " ← EWMA ALARM" if ewma.is_anomaly() else ""
        print(
            f"  sample {i:2d}: {lat:5.1f} ms   z={z:6.2f}   "
            f"EWMA={s:5.2f}{flag_w}{flag_e}"
        )


def demo_queue():
    print("\n" + "=" * 60)
    print("4. Queue dynamics + acceleration (API4)")
    print("=" * 60)

    q = QueueDynamicsTracker(drain_rate=15.0)
    acc = AccelerationTracker()

    timeline = [
        (0.0, 5.0),
        (1.0, 8.0),
        (2.0, 20.0),
        (3.0, 45.0),
        (4.0, 90.0),
        (5.0, 170.0),
        (6.0, 310.0),
    ]
    for t, rate in timeline:
        queue_len = q.update(t, rate)
        vel, accel = acc.update(t, rate)
        overloaded = "OVERLOADED" if q.is_overloaded(30) else ""
        brute = "BRUTE-FORCE? (sustained)" if acc.is_brute_force(accel_threshold=15, sustained=3) else ""
        print(
            f"  t={t:.1f}s  λ={rate:6.1f}/s  Q={queue_len:6.1f}  "
            f"R'={vel:7.1f}  R''={accel:7.1f}  {overloaded} {brute}"
        )


def demo_math_extras():
    print("\n" + "=" * 60)
    print("5. Math extras — Miller–Madow & keyspace CI")
    print("=" * 60)

    # Bias correction illustration
    repetitive = "aaaaabaaaa"
    h_plugin = MathCore.shannon_entropy(repetitive)
    h_mm = MathCore.miller_madow_entropy(repetitive)
    print(f"  Sample '{repetitive}'")
    print(f"    Plugin entropy     : {h_plugin:.4f} bits")
    print(f"    Miller–Madow       : {h_mm:.4f} bits  (bias-corrected)")

    # Keyspace CI
    import random
    random.seed(42)
    ids = [random.randint(10_000, 99_999) for _ in range(15)]
    point = MathCore.estimated_keyspace_bits(ids)
    ci = MathCore.keyspace_bits_ci(ids, confidence=0.95)
    print(f"\n  5-digit numeric sample (n={len(ids)})")
    print(f"    Point estimate     : {point:.2f} bits")
    if ci:
        _, lo, hi = ci
        print(f"    95 % CI            : [{lo:.2f}, {hi:.2f}] bits")


async def main():
    await demo_bola()
    await demo_excessive_data()
    demo_welford_and_ewma()
    demo_queue()
    demo_math_extras()
    print("\n✅ Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
