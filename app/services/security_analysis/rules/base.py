from abc import ABC, abstractmethod
from typing import Any

from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import AnalysisCandidate, EvidenceStrength, FindingStatus
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec


class AnalysisRule(ABC):
    """Abstract base class for evidence analysis rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier."""
        pass

    @abstractmethod
    def evaluate(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> AnalysisCandidate | None:
        """Evaluates execution evidence and produces a candidate finding or None."""
        pass
