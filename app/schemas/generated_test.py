from typing import Any
from pydantic import BaseModel, Field

from app.schemas.security_test import (
    ApplicableTestResult,
    EvidenceRequirements,
    ExpectedBehavior,
    MutationType,
    TargetLocation,
)
from app.schemas.spec import NormalizedApiSpec

PROMPT_VERSION = "SECURITY_TEST_GENERATION_PROMPT_V1"
SCHEMA_VERSION = "GENERATED_TEST_SCHEMA_V1"


class InputMutation(BaseModel):
    """Specific input mutation generated for a target element."""

    location: TargetLocation
    target: str
    original_schema: dict[str, Any] | None = None
    mutation_type: MutationType
    generated_value: Any | None = None
    rationale: str
    constraints_respected: bool = True


class RequestPlan(BaseModel):
    """Declarative HTTP request specification to be constructed by future executor."""

    http_method: str
    path: str
    query_parameters: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    request_body: Any | None = None
    auth_state: str | None = None


class GenerationMetadata(BaseModel):
    """Experiment and model metadata for test generation reproducibility."""

    provider: str
    model: str
    prompt_version: str = PROMPT_VERSION
    schema_version: str = SCHEMA_VERSION
    generation_timestamp: str
    template_id: str


class GeneratedSecurityTest(BaseModel):
    """Instantiated concrete security test plan produced by LLM reasoning."""

    __test__ = False

    generated_test_id: str
    instance_id: str
    template_id: str
    endpoint_target: str
    http_method: str
    rationale: str
    test_objective: str
    request_plan: RequestPlan
    input_mutations: list[InputMutation] = Field(default_factory=list)
    authentication_context: str | None = None
    expected_behavior: ExpectedBehavior
    evidence_requirements: EvidenceRequirements
    prerequisites: list[str] = Field(default_factory=list)
    generation_metadata: GenerationMetadata
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Model-reported generation confidence score (0.0 to 1.0), NOT vulnerability probability.",
    )


class FailedGenerationResult(BaseModel):
    """Structured failure result when an LLM generation candidate fails validation."""

    __test__ = False

    instance_id: str
    template_id: str
    endpoint_target: str
    http_method: str
    failure_type: str
    reason: str
    raw_output: str | None = None


class GenerateSecurityTestsRequest(BaseModel):
    """Request payload for LLM security test generation."""

    spec: NormalizedApiSpec
    applicable_tests: list[ApplicableTestResult] = Field(default_factory=list)


class GenerateSecurityTestsResponse(BaseModel):
    """Response container for generated security test results."""

    generated_tests: list[GeneratedSecurityTest] = Field(default_factory=list)
    failed_generations: list[FailedGenerationResult] = Field(default_factory=list)
    total_requested: int = 0
    total_generated: int = 0
    total_failed: int = 0
