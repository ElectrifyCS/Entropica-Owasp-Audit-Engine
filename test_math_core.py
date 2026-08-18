"""
Unit tests for the pure math core.
Run with:  python -m pytest owasp_audit_engine/tests/ -v
"""

import math
import pytest

from owasp_audit_engine.core.math_core import MathCore
from owasp_audit_engine.core.welford import WelfordTracker
from owasp_audit_engine.core.queue_dynamics import QueueDynamicsTracker, AccelerationTracker


class TestShannonEntropy:
    def test_empty(self):
        assert MathCore.shannon_entropy("") == 0.0
        assert MathCore.shannon_entropy([]) == 0.0

    def test_single_symbol(self):
        assert MathCore.shannon_entropy("aaaa") == 0.0

    def test_uniform(self):
        # 4 distinct symbols equally likely → 2 bits
        data = "abcd"
        assert math.isclose(MathCore.shannon_entropy(data), 2.0)

    def test_predictable_ids(self):
        # Sequential-looking IDs should have low entropy
        ids = ["1001", "1002", "1003", "1004", "1005"]
        avg = sum(MathCore.shannon_entropy(s) for s in ids) / len(ids)
        assert avg < 3.0

    def test_uuid_like(self):
        # High entropy
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert MathCore.shannon_entropy(uuid) > 3.5


class TestSequentialScore:
    def test_perfect_sequence(self):
        assert MathCore.sequential_score([1, 2, 3, 4, 5]) == 1.0
        assert MathCore.sequential_score(["10", "11", "12", "13"]) == 1.0

    def test_non_numeric(self):
        assert MathCore.sequential_score(["abc", "def"]) == 0.0

    def test_randomish(self):
        score = MathCore.sequential_score([17, 42, 3, 99, 8])
        assert score < 0.5


class TestWelford:
    def test_constant_stream(self):
        w = WelfordTracker()
        for _ in range(20):
            z = w.update(5.0)
        assert w.mean == 5.0
        assert w.std_dev == 0.0
        assert z == 0.0  # or very close after the 1e-9 guard

    def test_anomaly_detection(self):
        w = WelfordTracker()
        # Build a stable baseline so std is small
        for v in [10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.3, 10.0, 9.95, 10.05]:
            w.update(v)
        # Large spike
        z = w.update(50.0)
        assert abs(z) > 3.0
        assert w.is_anomaly()


class TestQueueDynamics:
    def test_accumulation(self):
        q = QueueDynamicsTracker(drain_rate=5.0)
        # Arrival faster than drain
        q.update(0.0, lambda_rate=20.0)
        q.update(1.0, lambda_rate=20.0)
        assert q.Q > 0
        assert q.is_overloaded(threshold=10.0)

    def test_drain(self):
        q = QueueDynamicsTracker(drain_rate=10.0)
        q.update(0.0, 5.0)
        q.update(1.0, 5.0)  # arrival < drain → queue stays 0
        assert q.Q == 0.0


class TestAcceleration:
    def test_rising_rate(self):
        acc = AccelerationTracker(window=5)
        # Simulated accelerating traffic
        for t, r in [(0, 1), (1, 3), (2, 8), (3, 20)]:
            v, a = acc.update(t, r)
        assert acc.acceleration > 0
