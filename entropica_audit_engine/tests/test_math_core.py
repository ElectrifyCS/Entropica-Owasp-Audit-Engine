"""
Unit tests for the pure math core.
Run with:  python -m pytest entropica_audit_engine/tests/ -v
"""

import math
import pytest

from entropica_audit_engine.core.math_core import MathCore
from entropica_audit_engine.core.welford import WelfordTracker
from entropica_audit_engine.core.queue_dynamics import QueueDynamicsTracker, AccelerationTracker


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

    def test_order_independent(self):
        # Same underlying ID space (1001-1010, an obvious auto-increment
        # range), just encountered in a different order — e.g. a paginated
        # listing that doesn't return rows sorted by ID. The score must not
        # depend on collection order, only on the ID values themselves.
        in_order = list(range(1001, 1011))
        shuffled = [1006, 1002, 1009, 1001, 1010, 1005, 1008, 1003, 1007, 1004]
        assert MathCore.sequential_score(in_order) == 1.0
        assert MathCore.sequential_score(shuffled) == 1.0


class TestEstimatedKeyspaceBits:
    def test_non_numeric_returns_none(self):
        assert MathCore.estimated_keyspace_bits(["abc", "def", "ghi"]) is None

    def test_too_few_samples_returns_none(self):
        assert MathCore.estimated_keyspace_bits([100, 200]) is None

    def test_small_keyspace_flagged_low(self):
        # 5-digit IDs: true keyspace is at most ~10^5, should read well
        # under the default 32-bit "brute-forceable" threshold.
        ids = [52445, 29772, 61750, 95319, 16328, 19494, 80239]
        bits = MathCore.estimated_keyspace_bits(ids)
        assert bits is not None
        assert bits < 20.0

    def test_large_keyspace_reads_high(self):
        # 10-digit IDs: ~9.9 x 10^9 possible values, should read well
        # above the default 32-bit threshold even from a small sample.
        ids = [7294919105, 3522798642, 7493598146, 4405809747, 5699224467]
        bits = MathCore.estimated_keyspace_bits(ids)
        assert bits is not None
        assert bits > 30.0

    def test_identical_ids_returns_zero(self):
        assert MathCore.estimated_keyspace_bits([5, 5, 5]) == 0.0


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


class TestOnlineDrainRateEstimation:
    """
    Section 3 of the project notes ("Adaptive Service Rate μ"): μ should
    be discovered from observed departures while the queue is non-empty,
    not held fixed at the constructor's initial guess forever.
    """

    def test_mu_unchanged_before_min_samples(self):
        q = QueueDynamicsTracker(drain_rate=10.0, min_departures_before_adapting=5)
        q.update(0.0, lambda_rate=50.0)
        q.update(1.0, lambda_rate=50.0)  # two calls needed: first only seeds last_t
        assert q.Q > 0
        # Only 2 in-queue departures — below the min sample count.
        q.record_departure(1.1)
        q.record_departure(1.2)
        assert q.mu == 10.0
        assert q.mu_is_adapted is False

    def test_mu_adapts_after_min_samples_while_queue_nonempty(self):
        q = QueueDynamicsTracker(
            drain_rate=10.0, mu_learning_rate=0.5, min_departures_before_adapting=3
        )
        q.update(0.0, lambda_rate=50.0)
        q.update(1.0, lambda_rate=50.0)  # force Q > 0 so departures count
        assert q.Q > 0
        # Departures every 0.5s -> true rate is 2 req/s, far from the
        # initial guess of 10.0.
        t = 1.0
        for _ in range(6):
            t += 0.5
            q.record_departure(t)
        assert q.mu_is_adapted is True
        assert q.mu != 10.0
        assert q.mu == pytest.approx(2.0, rel=0.3)

    def test_departures_while_queue_empty_do_not_move_mu(self):
        # Q starts at 0 and nothing forces it up — departures here reflect
        # arrival spacing, not server capacity, and must NOT be used.
        q = QueueDynamicsTracker(
            drain_rate=10.0, mu_learning_rate=0.5, min_departures_before_adapting=2
        )
        assert q.Q == 0.0
        t = 0.0
        for _ in range(6):
            t += 0.01  # very fast departures, would imply ~100 req/s if used
            q.record_departure(t)
        assert q.mu == 10.0  # untouched
        assert q.mu_sample_count == 0

    def test_mu_floored_above_zero(self):
        q = QueueDynamicsTracker(
            drain_rate=10.0, mu_learning_rate=1.0, min_departures_before_adapting=1
        )
        q.update(0.0, lambda_rate=50.0)
        q.update(1.0, lambda_rate=50.0)
        assert q.Q > 0
        q.record_departure(1.0)
        # Enormous gap -> tiny instantaneous rate; must not collapse to
        # ~0 (which would make Q grow without bound regardless of λ).
        q.record_departure(10_000.0)
        assert q.mu > 0.0

    def test_reset_restores_initial_mu_and_adaptation_state(self):
        q = QueueDynamicsTracker(drain_rate=7.5, mu_learning_rate=0.5, min_departures_before_adapting=2)
        q.update(0.0, lambda_rate=50.0)
        q.update(1.0, lambda_rate=50.0)
        t = 1.0
        for _ in range(5):
            t += 0.5
            q.record_departure(t)
        assert q.mu != 7.5
        q.reset()
        assert q.mu == 7.5
        assert q.mu_is_adapted is False
        assert q.mu_sample_count == 0


class TestAcceleration:
    def test_rising_rate(self):
        acc = AccelerationTracker(window=5)
        # Simulated accelerating traffic
        for t, r in [(0, 1), (1, 3), (2, 8), (3, 20)]:
            v, a = acc.update(t, r)
        assert acc.acceleration > 0

    def test_single_spike_not_sustained(self):
        # One big jump, then acceleration settles back down. A single
        # spike shouldn't read as "sustained" brute-force acceleration.
        acc = AccelerationTracker(window=6)
        for t, r in [(0, 5), (1, 6), (2, 40), (3, 42), (4, 44), (5, 46)]:
            acc.update(t, r)
        assert not acc.is_brute_force(accel_threshold=15, sustained=3)

    def test_sustained_ramp_flagged(self):
        # Acceleration stays elevated across several consecutive windows —
        # the pattern a scripted ramp-up actually produces.
        acc = AccelerationTracker(window=8)
        for t, r in [(0, 5), (1, 8), (2, 20), (3, 45), (4, 90), (5, 170), (6, 310)]:
            acc.update(t, r)
        assert acc.is_brute_force(accel_threshold=15, sustained=3)

    def test_insufficient_history_not_flagged(self):
        acc = AccelerationTracker(window=5)
        acc.update(0, 5)
        acc.update(1, 50)
        assert not acc.is_brute_force(accel_threshold=15, sustained=3)
