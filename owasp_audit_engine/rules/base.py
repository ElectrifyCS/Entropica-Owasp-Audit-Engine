"""
Base contract for every audit rule + the Finding schema.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """
    Standard result returned by every rule.
    Keep this schema stable — the API and workers depend on it.
    """
    rule_id: str
    name: str
    severity: Severity
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class BaseAuditRule(ABC):
    """
    Strategy interface. Every concrete rule must implement `execute`.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        description: str = "",
        recommendation: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description
        self.recommendation = recommendation

    @abstractmethod
    async def execute(self, target_url: str, **kwargs: Any) -> Optional[Finding]:
        """
        Run the check against the target.
        Return a Finding if the issue is present, otherwise None.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.rule_id}>"
