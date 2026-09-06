"""
Unit tests for core/queue_dynamics.py's arrival-rate tracking
(record_arrival / current_arrival_rate).

This is the fix for a real, structural bug found by testing the SSRF
prober against a real running VAmPI container: the original design
estimated the arrival rate lambda(t) as completed_count/elapsed_time -
i.e. observed THROUGHPUT, not actual arrival demand. A throughput
number can never exceed the target's true drain rate by construction
(the target itself produced it), so comparing it against an assumed mu
could only ever reveal the initial guess was wrong, never that arrivals
were genuinely outpacing departures - the exact condition this whole
model exists to detect.

These tests check the FIXED mechanism directly, isolated from asyncio/
HTTP plumbing, so the core rate math can be verified with exact,
hand-computable values.
"""
from __future__ import annotations

import pytest

from entropica_audit_engine.core.queue_dynamics import QueueDynamicsTracker


class TestArrivalRateBasics:
    def test_no_arrivals_is_zero_rate(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        assert tracker.current_arrival_rate(now=10.0) == 0.0

    def test_single_arrival_treated_as_one_per_window(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        tracker.record_arrival(t=0.0)
        # Not 0 - the very first request of a burst must be visible,
        # not invisible until a second one arrives.
        assert tracker.current_arrival_rate(now=0.0) == pytest.approx(0.5, abs=1e-9)

    def test_simultaneous_burst_reads_as_very_high_rate(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        # 10 arrivals at effectively the same instant - a true burst.
        for _ in range(10):
            tracker.record_arrival(t=5.0)
        rate = tracker.current_arrival_rate(now=5.0)
        assert rate > 1000  # floored span (1e-3) -> reads as very high, not infinite/undefined

    def test_evenly_spaced_arrivals_give_expected_rate(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=10.0)
        # One arrival every 0.5s for 2 seconds -> 5 arrivals, spanning 2.0s
        for i in range(5):
            tracker.record_arrival(t=i * 0.5)
        # n=5, span = now - oldest = 2.0 - 0.0 = 2.0 -> rate = 5/2.0 = 2.5/s
        assert tracker.current_arrival_rate(now=2.0) == pytest.approx(2.5, abs=1e-9)


class TestArrivalRateDecay:
    """
    The exact bug found tonight: rate must decay as real time passes
    with no new arrivals, not stay frozen at a stale burst-time value.
    A version of this method that only pruned inside record_arrival()
    (not against the current `now` on every read) would fail every test
    in this class - the rate would stay stuck at its burst-time value
    forever once arrivals stopped, causing Q to grow without bound even
    after real demand had genuinely ended.
    """

    def test_rate_decays_as_window_ages_past_a_burst(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        for _ in range(10):
            tracker.record_arrival(t=0.0)
        rate_immediately_after = tracker.current_arrival_rate(now=0.0)
        rate_after_one_second = tracker.current_arrival_rate(now=1.0)
        rate_after_window_passes = tracker.current_arrival_rate(now=3.0)

        assert rate_immediately_after > rate_after_one_second
        # Once `now` is past arrival_window_seconds since the burst,
        # every arrival has aged out - rate must return to exactly 0,
        # not stay elevated.
        assert rate_after_window_passes == 0.0

    def test_repeated_reads_with_no_new_arrivals_keep_decaying_not_frozen(self):
        # This is the literal regression case: poll current_arrival_rate
        # repeatedly (as the backoff loop does) with NO new record_arrival
        # calls in between, and confirm it keeps decaying rather than
        # returning the same stale number forever.
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        for _ in range(5):
            tracker.record_arrival(t=0.0)

        readings = [tracker.current_arrival_rate(now=t) for t in (0.0, 0.5, 1.0, 1.5, 2.0, 2.5)]
        # Strictly non-increasing, and must reach 0 once the window fully passes.
        for a, b in zip(readings, readings[1:]):
            assert b <= a
        assert readings[-1] == 0.0

    def test_old_arrivals_pruned_do_not_affect_a_later_fresh_burst(self):
        tracker = QueueDynamicsTracker(arrival_window_seconds=2.0)
        for _ in range(20):
            tracker.record_arrival(t=0.0)  # a big early burst
        # Long gap - the old burst should be completely irrelevant now.
        tracker.record_arrival(t=100.0)
        rate = tracker.current_arrival_rate(now=100.0)
        # Only the single fresh arrival should count; the 20 stale ones
        # must not still be inflating this.
        assert rate == pytest.approx(0.5, abs=1e-9)


class TestArrivalRateFeedsQueueGrowthCorrectly:
    """
    Confirms the fixed arrival rate actually produces the right Q(t)
    behavior when fed through update() - not just that the rate number
    itself looks right in isolation.
    """

    def test_burst_against_slow_drain_grows_queue(self):
        tracker = QueueDynamicsTracker(drain_rate=5.0, arrival_window_seconds=2.0)
        # update() advances Q using a time delta (dt) from its OWN prior
        # call - there's no dt on a tracker's literal first-ever call, so
        # priming it once first matches how the real prober actually uses
        # this (update() called repeatedly across many requests over a
        # tracker's life), not a single call on a brand-new instance.
        tracker.update(t=0.0, lambda_rate=0.0)

        # A burst of 10 arrivals essentially at once, against an assumed
        # drain rate of only 5/s - Q must grow, not stay at 0.
        for _ in range(10):
            tracker.record_arrival(t=0.0)
        rate = tracker.current_arrival_rate(now=0.01)
        q = tracker.update(t=0.01, lambda_rate=rate)
        assert q > 0.0

    def test_throughput_based_proxy_would_have_shown_zero_growth(self):
        # Documents WHY the old design was broken, as an executable
        # comparison rather than just a comment: under the old
        # completed_count/elapsed proxy, with 0 completions so far
        # (a burst that hasn't finished yet), the "arrival rate" would
        # have been computed as 0/elapsed = 0 - meaning update() would
        # be called with lambda_rate=0, which can only ever DRAIN Q,
        # never grow it, regardless of how many requests just arrived.
        tracker = QueueDynamicsTracker(drain_rate=5.0)
        old_broken_rate = 0 / 0.01  # completed_count=0 / elapsed=0.01s
        q = tracker.update(t=0.01, lambda_rate=old_broken_rate)
        assert q == 0.0  # the bug: a real burst, modeled as zero arrivals
