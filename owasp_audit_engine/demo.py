"""
Quick demo — run from the project root:

    python -m owasp_audit_engine.demo
"""

from __future__ import annotations

import asyncio
from owasp_audit_engine.rules.registry import build_default_registry
from owasp_audit_engine.core.welford import WelfordTracker
from owasp_audit_engine.core.queue_dynamics import QueueDynamicsTracker, AccelerationTracker


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

    # Classic auto-increment IDs, collected out of creation order (e.g. a
    # paginated listing that doesn't return rows sorted by ID). Sequential
    # scoring is order-independent now, so this is still caught.
    sequential_shuffled = [1005, 1001, 1009, 1003, 1007, 1002, 1010, 1004, 1006, 1008, 1011]
    await run("Sequential IDs (collected out of order)", sequential_shuffled)

    # High-entropy UUIDs — large alphabet, entropy signal applies and
    # correctly finds nothing.
    import uuid
    random_ids = [str(uuid.uuid4()) for _ in range(10)]
    await run("Random UUIDs", random_ids)

    # Small numeric keyspace: NOT sequential, NOT low per-character entropy
    # in the old sense — but only ~90,000 possible values. This is exactly
    # the case the old entropy-only check missed.
    import random as _random
    _random.seed(7)
    small_keyspace = [str(_random.randint(10_000, 99_999)) for _ in range(12)]
    await run("Small-keyspace random numeric IDs (5-digit)", small_keyspace)

    # Large numeric keyspace: also non-sequential, and this time genuinely
    # hard to guess (~9 billion values). The old entropy signal flagged
    # this as a false positive because ANY numeric string is capped at
    # log2(10) bits/char; the keyspace-size signal correctly clears it.
    _random.seed(11)
    large_keyspace = [str(_random.randint(1_000_000_000, 9_999_999_999)) for _ in range(12)]
    await run("Large-keyspace random numeric IDs (10-digit)", large_keyspace)


def demo_welford():
    print("\n" + "=" * 60)
    print("2. Streaming latency anomaly (Welford)")
    print("=" * 60)

    tracker = WelfordTracker()
    latencies = [42, 45, 41, 44, 43, 40, 46, 200]  # last one is a spike
    for i, lat in enumerate(latencies, 1):
        z = tracker.update(float(lat))
        flag = " ← ANOMALY" if tracker.is_anomaly() else ""
        print(f"  sample {i:2d}: {lat:5.1f} ms   z={z:6.2f}{flag}")


def demo_queue():
    print("\n" + "=" * 60)
    print("3. Queue dynamics + acceleration (API4)")
    print("=" * 60)

    q = QueueDynamicsTracker(drain_rate=15.0)
    acc = AccelerationTracker()

    # Simulated attack: arrival rate ramps up hard and KEEPS ramping.
    # is_brute_force now requires `sustained` consecutive accelerating
    # windows (default 3), not just one spike — a single fast jump can be
    # organic (e.g. a marketing link going out); several windows of
    # sustained positive acceleration back-to-back is a much stronger
    # automation signal.
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


async def main():
    await demo_bola()
    demo_welford()
    demo_queue()
    print("\n✅ Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
