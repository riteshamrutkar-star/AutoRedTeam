from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from app.schemas.execution import ExecutionResult
from app.schemas.finding import FindingStatus, SecurityFinding
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec


class SessionStatus(str, Enum):
    """Explicit session state machine states."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AdaptiveAction(str, Enum):
    """Adaptive decision action types."""

    STOP = "STOP"
    CONFIRM = "CONFIRM"
    EXPLORE = "EXPLORE"
    REFINE = "REFINE"


class AdaptiveBudget(BaseModel):
    """Resource constraints enforcing bounded session execution."""

    max_iterations: int = 5
    max_executions: int = 10
    max_generated_tests: int = 10
    max_runtime_seconds: int = 120
    max_followups_per_finding: int = 2


class DecisionProvenance(BaseModel):
    """Detailed metadata tracing decision rationale, information gain, and LLM origin."""

    evidence_gap: str | None = None
    selected_candidate: str | None = None
    rationale: str
    information_gain: float = 0.0
    provider: str | None = None
    model: str | None = None
    prompt_version: str | None = None


class AdaptiveDecision(BaseModel):
    """Structured decision output produced by AdaptiveDecisionEngine."""

    action: AdaptiveAction
    rationale: str
    confidence: float = 0.0
    candidate_template_ids: list[str] = Field(default_factory=list)
    parent_finding_id: str | None = None
    evidence_gap: str | None = None
    provenance: DecisionProvenance | None = None
    stop_reason: str | None = None


class AdaptiveIteration(BaseModel):
    """Trace container for a single step in an adaptive session."""

    iteration_number: int
    parent_execution_id: str | None = None
    parent_finding_id: str | None = None
    decision: AdaptiveDecision
    selected_template_id: str | None = None
    generated_test_id: str | None = None
    execution_id: str | None = None
    finding_status: FindingStatus | None = None
    rationale: str


class CreateAdaptiveSessionRequest(BaseModel):
    """Request payload to initialize an adaptive testing session."""

    target_id: str
    spec: NormalizedApiSpec
    initial_test_template_ids: list[str] = Field(default_factory=list)
    budget: AdaptiveBudget | None = None


class RunSessionRequest(BaseModel):
    """Request payload to run bounded iterations on an adaptive session."""

    max_steps_this_call: int = Field(default=5, ge=1, le=20)


class AdaptiveSession(BaseModel):
    """Session state model storing locked target, spec, history, findings, and budget."""

    session_id: str
    target_id: str
    spec: NormalizedApiSpec
    status: SessionStatus = SessionStatus.CREATED
    started_at: str
    completed_at: str | None = None
    current_iteration: int = 0
    budget: AdaptiveBudget
    iterations: list[AdaptiveIteration] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    executed_signatures: list[str] = Field(default_factory=list)
    stop_reason: str | None = None
