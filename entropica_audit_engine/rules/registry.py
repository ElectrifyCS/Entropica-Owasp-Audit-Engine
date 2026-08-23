"""
Simple plugin registry for audit rules.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Type

from .base import BaseAuditRule


class RuleRegistry:
    """Collects and instantiates registered rules."""

    def __init__(self) -> None:
        self._rules: Dict[str, BaseAuditRule] = {}

    def register(self, rule: BaseAuditRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule {rule.rule_id} already registered")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> BaseAuditRule:
        return self._rules[rule_id]

    def all(self) -> List[BaseAuditRule]:
        return list(self._rules.values())

    def ids(self) -> List[str]:
        return list(self._rules.keys())

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules


def build_default_registry() -> RuleRegistry:
    """Factory that loads the built-in rules."""
    from .bola import PredictableResourceIDRule
    from .excessive_data import ExcessiveDataExposureRule
    from .resource_consumption import UnrestrictedResourceConsumptionRule
    from .mass_assignment import MassAssignmentRule

    registry = RuleRegistry()
    registry.register(PredictableResourceIDRule())
    registry.register(ExcessiveDataExposureRule())
    registry.register(UnrestrictedResourceConsumptionRule())
    registry.register(MassAssignmentRule())
    return registry
