from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from app.schemas.generated_test import GeneratedSecurityTest


class ExecutionStatus(str, Enum):
    """Explicit status representation for test execution lifecycle."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"


class PolicyDecision(BaseModel):
    """Safety evaluation policy result."""

    allowed: bool
    reason: str
    rule_violated: str | None = None


class RegisteredTarget(BaseModel):
    """Controlled evaluation target registered in AutoRedTeam's allowlist."""

    target_id: str
    name: str
    description: str
    target_type: str  # e.g., "vampi", "juice-shop", "dvwa", "test-harness"
    base_url: str
    enabled: bool = True
    environment: str = "local"
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    )
    auth_symbolic_map: dict[str, str] = Field(default_factory=dict)


class ExecutionOptions(BaseModel):
    """Configurable execution parameters."""

    timeout_seconds: int = 10
    max_response_bytes: int = 1048576
    follow_redirects: bool = False


class ExecutionRequest(BaseModel):
    """Request payload for executing a single GeneratedSecurityTest."""

    target_id: str
    generated_test: GeneratedSecurityTest
    options: ExecutionOptions | None = None


class RequestEvidence(BaseModel):
    """Structured evidence of outgoing HTTP request with sensitive data redacted."""

    method: str
    target_id: str
    path: str
    query_parameters: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any | None = None
    auth_state: str | None = None


class ResponseEvidence(BaseModel):
    """Structured evidence of received HTTP response with body size caps."""

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_size: int = 0
    duration_ms: float = 0.0
    final_url_host: str | None = None
    truncated: bool = False


class ExecutionResult(BaseModel):
    """Standardized result container returned by execution engine."""

    __test__ = False

    execution_id: str
    target_id: str
    generated_test_id: str
    status: ExecutionStatus
    started_at: str
    completed_at: str
    duration_ms: float
    request_evidence: RequestEvidence | None = None
    response_evidence: ResponseEvidence | None = None
    policy_decision: PolicyDecision
    error: str | None = None
