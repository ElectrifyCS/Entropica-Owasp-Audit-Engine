"""
ENTROPICA API7:2023 - Server Side Request Forgery (differential/causal probing)

First-principles notes §1.3: this is the deductive rule with the strongest
epistemic footing in the project and, until now, the least implementation
behind it. The claim isn't "this URL parameter looks suspicious" (a
resemblance heuristic); it's an interventional one — varying the parameter
under experimenter control and observing whether the outcome changes by
more than sampling noise explains is direct causal evidence that the
server's behavior is downstream of that parameter, exactly the shape of
evidence a controlled experiment gives you rather than passive observation.

All the actual statistics live in core/causal_probe.py (Welch's t-test on
streaming Welford trackers). This rule is deliberately thin — it only
decides what counts as "significant enough to report" from CausalProbe's
output, matching the same split every other rule uses (see
resource_consumption.py: no I/O here, just judgment on pre-collected data).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from entropica_audit_engine.core.causal_probe import CausalProbe, CausalEffect
from .base import BaseAuditRule, Finding, Severity


class SSRFDifferentialRule(BaseAuditRule):
    """
    Judges whether varying a parameter (typically a host/URL field) causes
    a statistically significant change in observed latency, holding
    everything else constant.

    Does not send any requests itself. Expects `observations`: a mapping
    from condition label to a list of numeric outcome measurements
    (latency_ms is the natural choice, since server-side network calls to
    unreachable/internal/slow hosts show up there most reliably; response
    size or a numeric status-derived signal would also work through the
    same CausalProbe machinery). One of the labels must be the control
    condition — a host known/assumed not to trigger any suspicious
    downstream behavior.
    """

    def __init__(
        self,
        alpha: float = 0.05,
        min_samples: int = 5,
        min_effect_ms: float = 50.0,
    ) -> None:
        super().__init__(
            rule_id="API7:2023",
            name="Server-Side Request Forgery (differential probing)",
            severity=Severity.HIGH,
            description=(
                "Varying a request parameter produced a statistically "
                "significant change in server response behavior relative "
                "to a control value, consistent with the server making a "
                "downstream network call whose destination is influenced "
                "by attacker-controlled input."
            ),
            recommendation=(
                "Validate and allow-list any user-supplied value used to "
                "construct a server-side request (URL, hostname, IP). "
                "Block requests to link-local, loopback, and private "
                "address ranges (e.g. 169.254.0.0/16, 127.0.0.0/8, "
                "10.0.0.0/8) at the network layer, not just in application "
                "code."
            ),
        )
        self.alpha = alpha
        self.min_samples = min_samples
        # A statistically significant but tiny (e.g. 1ms) difference is a
        # real effect but not necessarily a security-relevant one; this
        # keeps the rule from firing on noise that happens to be
        # significant purely because n is large. Statistical significance
        # answers "is there an effect"; this answers "is it big enough to
        # matter" - two different questions, deliberately not conflated.
        self.min_effect_ms = min_effect_ms

    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Expects:
          observations: Dict[str, List[float]] - condition label -> outcome
              samples (e.g. latency_ms). Must include the control label.
          control_label: str, default "control".
          parameter_name: str, default "url" - just for the Finding's
              evidence/description, purely descriptive.
        """
        observations: Mapping[str, List[float]] = kwargs.get("observations") or {}
        control_label: str = kwargs.get("control_label", "control")
        parameter_name: str = kwargs.get("parameter_name", "url")

        if control_label not in observations:
            return None

        probe = CausalProbe(
            control_label=control_label,
            alpha=self.alpha,
            min_samples=self.min_samples,
        )
        for label, samples in observations.items():
            for value in samples:
                probe.observe(label, value)

        effects = probe.all_effects()
        significant: Dict[str, CausalEffect] = {
            label: eff
            for label, eff in effects.items()
            if eff.significant and abs(eff.delta) >= self.min_effect_ms
        }

        if not significant:
            return None

        strongest_label, strongest = max(
            significant.items(), key=lambda item: abs(item[1].delta)
        )

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            description=self.description,
            recommendation=self.recommendation,
            target=target_url,
            evidence={
                "parameter_name": parameter_name,
                "control_label": control_label,
                "strongest_condition": strongest_label,
                "conditions_tested": list(observations.keys()),
                "significant_conditions": list(significant.keys()),
            },
            metrics={
                "min_effect_ms": self.min_effect_ms,
                "alpha": self.alpha,
                "effects": {
                    label: {
                        "delta_ms": round(eff.delta, 3),
                        "welch_t": round(eff.welch_t, 3),
                        "approx_df": round(eff.approx_df, 2),
                        "p_value_two_sided": eff.p_value_two_sided,
                        "n_control": eff.n_control,
                        "n_condition": eff.n_condition,
                    }
                    for label, eff in effects.items()
                },
            },
        )
