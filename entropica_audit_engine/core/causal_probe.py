"""
Interventional (not correlational) detection of parameter-dependent
behavior — the general primitive behind SSRF-style differential probing
(expansion notes §5.2; first-principles notes §1.3).

Pure statistics: no I/O. Feed it outcome measurements however they were
obtained; it never issues requests itself — that split matches the
"pure math first" guiding principle (core/ stays free of I/O, HTTP, and
heuristics), and it means the same primitive can back any rule that
suspects a parameter causally influences downstream behavior, not only
an SSRF-specific one.

Mathematical foundations (first principles)
--------------------------------------------
Claim: if varying a parameter (e.g. a host/URL field) under experimenter
control produces a measurable, reproducible change in an observed
outcome (latency, response size, a numeric status-derived signal) while
everything else is held constant, the outcome is causally downstream of
that parameter — Pearl-style interventional evidence (do(X=x) changes
Y). That's a categorically stronger claim than input and output merely
being correlated in observational data, and unlike the BOLA/resource-
consumption rules it needs no calibrated threshold to be *true* — an
effect either survives the intervention or it doesn't.

CausalProbe formalizes "measurable, reproducible" as: is the difference
between an intervention condition's mean and the control condition's
mean larger than sampling noise alone would explain, given each
condition's own observed variance? That's Welch's t-test — the standard
two-sample test for unequal variances — computed on streaming Welford
trackers (one per condition), so no raw sample ever needs to be stored,
consistent with the "streaming/online by default" principle.

Welch's t-statistic:
    t = (x̄_cond − x̄_ctrl) / √(s²_cond/n_cond + s²_ctrl/n_ctrl)

Welch–Satterthwaite degrees of freedom (accounts for unequal variance
and sample size between conditions, rather than assuming a pooled
variance that would understate uncertainty when they differ):
    df = (s²_cond/n_cond + s²_ctrl/n_ctrl)²
         / [ (s²_cond/n_cond)²/(n_cond−1) + (s²_ctrl/n_ctrl)²/(n_ctrl−1) ]

Two-sided p-value from the Student's t distribution, via the standard
identity relating it to the regularized incomplete beta function
(Abramowitz & Stegun 26.7.1; Numerical Recipes §6.4):
    p = I_x(df/2, 1/2),   x = df / (df + t²)

No SciPy dependency: the regularized incomplete beta function is
implemented below from its continued-fraction expansion (the same
algorithm SciPy itself uses under the hood), using only math.lgamma
from the standard library — consistent with the rest of core/, which
derives its own distributional math (Miller-Madow, the Beta(n−1,2)
keyspace variance) rather than importing a stats package.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Optional

from entropica_audit_engine.core.welford import WelfordTracker


# ----------------------------------------------------------------------
# Regularized incomplete beta function I_x(a, b) — continued fraction
# (Numerical Recipes §6.4, Lentz's method). Needed to get an exact
# Student's-t p-value without a SciPy dependency. General-purpose:
# reusable anywhere else in the project that needs a Beta-distribution
# tail probability, not just here.
# ----------------------------------------------------------------------
_FPMIN = 1e-300
_MAX_ITER = 200
_EPS = 3e-12


def _betacf(a: float, b: float, x: float) -> float:
    """Continued-fraction evaluation used by regularized_incomplete_beta.
    Not meant to be called directly."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _FPMIN:
        d = _FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, _MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        h *= d * c

        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return h


def regularized_incomplete_beta(x: float, a: float, b: float) -> float:
    """
    I_x(a, b): the regularized incomplete beta function, for x in [0, 1],
    a, b > 0. Used here for an exact Student's-t p-value; general enough
    to reuse anywhere else a Beta-distribution CDF is needed (e.g. an
    exact-tail-probability version of the keyspace CI in math_core.py,
    which currently uses a normal approximation on the log-bits scale).
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_bt = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log(1.0 - x)
    )
    bt = math.exp(ln_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def student_t_two_sided_p(t: float, df: float) -> float:
    """
    P(|T| >= |t|) for T ~ Student's t with `df` degrees of freedom.
    Standard identity (Abramowitz & Stegun 26.7.1):
        p = I_x(df/2, 1/2),   x = df / (df + t^2)
    """
    if df <= 0:
        return 1.0
    x = df / (df + t * t)
    return regularized_incomplete_beta(x, df / 2.0, 0.5)


@dataclass(frozen=True)
class CausalEffect:
    """Result of comparing one condition against the control condition."""
    condition: str
    n_control: int
    n_condition: int
    control_mean: float
    condition_mean: float
    delta: float
    welch_t: float
    approx_df: float
    p_value_two_sided: float
    significant: bool  # p_value_two_sided < alpha, given both n's met min_samples


class CausalProbe:
    """
    Interventional comparison of one or more named conditions against a
    control condition, using Welch's t-test on streaming per-condition
    statistics.

    Usage
    -----
        probe = CausalProbe(control_label="baseline")
        probe.observe("baseline", latency_ms)        # repeat per sample
        probe.observe("internal_host", latency_ms)   # repeat per sample
        effect = probe.effect("internal_host")
        if effect and effect.significant:
            ...

    This class does not send requests and knows nothing about HTTP or
    what a "host parameter" is — it only knows how to tell whether two
    labeled streams of numbers differ by more than their own noise would
    explain. That separation is deliberate: a thin, reusable core/
    primitive rather than an SSRF-specific rule, matching the project's
    own design rule that "new rules should be thin consumers of existing
    core primitives."
    """

    def __init__(
        self,
        control_label: str = "control",
        alpha: float = 0.05,
        min_samples: int = 5,
    ) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if min_samples < 2:
            raise ValueError("min_samples must be >= 2 (need variance)")
        self.control_label = control_label
        self.alpha = alpha
        self.min_samples = min_samples
        self._trackers: Dict[str, WelfordTracker] = {}

    def _tracker(self, condition: str) -> WelfordTracker:
        if condition not in self._trackers:
            self._trackers[condition] = WelfordTracker()
        return self._trackers[condition]

    def observe(self, condition: str, value: float) -> None:
        """Record one observation (e.g. latency_ms, response byte count)
        under a named condition — the control label or any intervention
        label."""
        self._tracker(condition).update(value)

    def n(self, condition: str) -> int:
        """Observation count for a condition (0 if never observed)."""
        tracker = self._trackers.get(condition)
        return tracker.count if tracker else 0

    def effect(self, condition: str) -> Optional[CausalEffect]:
        """
        Compare `condition` against the control condition. Returns None
        if either condition has fewer than `min_samples` observations —
        not enough to say anything honest about variance, let alone a
        difference in means — or if `condition` IS the control label.
        """
        if condition == self.control_label:
            return None
        ctrl = self._trackers.get(self.control_label)
        cond = self._trackers.get(condition)
        if ctrl is None or cond is None:
            return None
        if ctrl.count < self.min_samples or cond.count < self.min_samples:
            return None

        n1, n2 = ctrl.count, cond.count
        var1 = ctrl.std_dev ** 2
        var2 = cond.std_dev ** 2
        se_sq = var1 / n1 + var2 / n2

        if se_sq <= 0.0:
            # Both conditions perfectly constant and numerically
            # identical — a real (if unusual) case, not an error. t is
            # undefined for a zero denominator; report "no detectable
            # difference" rather than dividing by zero or crashing.
            t = 0.0
            df = float(n1 + n2 - 2)
            p = 1.0
        else:
            t = (cond.mean - ctrl.mean) / math.sqrt(se_sq)
            denom = 0.0
            if n1 > 1:
                denom += (var1 / n1) ** 2 / (n1 - 1)
            if n2 > 1:
                denom += (var2 / n2) ** 2 / (n2 - 1)
            df = (se_sq ** 2) / denom if denom > 0 else float(n1 + n2 - 2)
            p = student_t_two_sided_p(t, df)

        return CausalEffect(
            condition=condition,
            n_control=n1,
            n_condition=n2,
            control_mean=ctrl.mean,
            condition_mean=cond.mean,
            delta=cond.mean - ctrl.mean,
            welch_t=t,
            approx_df=df,
            p_value_two_sided=p,
            significant=(p < self.alpha),
        )

    def all_effects(self) -> Dict[str, CausalEffect]:
        """Effect for every observed non-control condition that has
        enough samples to be evaluated."""
        out: Dict[str, CausalEffect] = {}
        for label in self._trackers:
            if label == self.control_label:
                continue
            eff = self.effect(label)
            if eff is not None:
                out[label] = eff
        return out
