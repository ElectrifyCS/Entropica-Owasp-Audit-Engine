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

    # Simulate sequential numeric IDs harvested from an API
    sequential_ids = list(range(1001, 1012))
    finding = await rule.execute(
        target_url="https://api.example.com/users/{id}",
        sample_ids=sequential_ids,
    )

    if finding:
        print("🚨 Finding raised:")
        print(f"   Rule      : {finding.rule_id} – {finding.name}")
        print(f"   Severity  : {finding.severity.value}")
        print(f"   Metrics   : {finding.metrics}")
        print(f"   Evidence  : {finding.evidence}")
    else:
        print("✅ No finding (IDs look random enough)")

    # Now try high-entropy IDs
    import uuid
    random_ids = [str(uuid.uuid4()) for _ in range(10)]
    finding2 = await rule.execute(
        target_url="https://api.example.com/users/{id}",
        sample_ids=random_ids,
    )
    print("\nHigh-entropy UUIDs →", "no finding" if finding2 is None else "unexpected finding")


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

    # Simulated attack: arrival rate ramps up hard
    timeline = [
        (0.0, 5.0),
        (1.0, 8.0),
        (2.0, 20.0),
        (3.0, 45.0),
        (4.0, 90.0),
    ]
    for t, rate in timeline:
        queue_len = q.update(t, rate)
        vel, accel = acc.update(t, rate)
        overloaded = "OVERLOADED" if q.is_overloaded(30) else ""
        brute = "BRUTE-FORCE?" if acc.is_brute_force(accel_threshold=15) else ""
        print(
            f"  t={t:.1f}s  λ={rate:5.1f}/s  Q={queue_len:6.1f}  "
            f"R'={vel:7.1f}  R''={accel:7.1f}  {overloaded} {brute}"
        )


async def main():
    await demo_bola()
    demo_welford()
    demo_queue()
    print("\n✅ Demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
