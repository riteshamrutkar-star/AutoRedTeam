from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class SecurityTestCategory(str, Enum):
    """Generic functional categories for API security tests."""

    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    INJECTION = "INJECTION"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    HTTP_METHOD = "HTTP_METHOD"
    RATE_LIMITING = "RATE_LIMITING"
    API_BEHAVIOR = "API_BEHAVIOR"
    CONFIGURATION = "CONFIGURATION"
    RESOURCE_CONTROL = "RESOURCE_CONTROL"


class TargetLocation(str, Enum):
    """Target parameter/payload location."""

    PATH = "PATH"
    QUERY = "QUERY"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    REQUEST_BODY = "REQUEST_BODY"
    AUTHENTICATION = "AUTHENTICATION"
    ENDPOINT = "ENDPOINT"


class Priority(str, Enum):
    """Baseline catalogue priority metadata."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    """Baseline potential impact metadata."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StrategyType(str, Enum):
    """Abstract security test strategy types."""

    VALUE_SUBSTITUTION = "VALUE_SUBSTITUTION"
    VALUE_OMISSION = "VALUE_OMISSION"
    TYPE_MUTATION = "TYPE_MUTATION"
    BOUNDARY_MUTATION = "BOUNDARY_MUTATION"
    AUTH_STATE_CHANGE = "AUTH_STATE_CHANGE"
    IDENTIFIER_SUBSTITUTION = "IDENTIFIER_SUBSTITUTION"
    METHOD_CHANGE = "METHOD_CHANGE"
    FIELD_ADDITION = "FIELD_ADDITION"
    FIELD_REMOVAL = "FIELD_REMOVAL"
    FIELD_MODIFICATION = "FIELD_MODIFICATION"
    REPETITION = "REPETITION"
    MALFORMED_INPUT = "MALFORMED_INPUT"


class MutationType(str, Enum):
    """Abstract mutation definitions."""

    SUBSTITUTE = "SUBSTITUTE"
    OMIT = "OMIT"
    MUTATE_TYPE = "MUTATE_TYPE"
    BOUNDARY_MIN = "BOUNDARY_MIN"
    BOUNDARY_MAX = "BOUNDARY_MAX"
    OVERSIZED = "OVERSIZED"
    UNAUTHORIZED_TOKEN = "UNAUTHORIZED_TOKEN"
    EXPIRED_TOKEN = "EXPIRED_TOKEN"
    INVALID_TOKEN = "INVALID_TOKEN"
    OTHER_USER_ID = "OTHER_USER_ID"
    UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    UNEXPECTED_FIELD = "UNEXPECTED_FIELD"
    BURST_SEQUENCE = "BURST_SEQUENCE"


class PrerequisiteRequirement(BaseModel):
    """Declarative prerequisite flags for catalogue test template applicability."""

    requires_auth_declared: bool = False
    requires_path_params: bool = False
    requires_query_params: bool = False
    requires_request_body: bool = False
    requires_schema_constraints: bool = False
    requires_identifier_candidate: bool = False


class TestTarget(BaseModel):
    """Specific target element of an API endpoint."""

    __test__ = False

    path: str
    http_method: str
    target_location: TargetLocation
    parameter_name: str | None = None
    field_path: str | None = None
    auth_context: str | None = None


class TestStrategy(BaseModel):
    """Abstract test strategy definition."""

    __test__ = False

    strategy_type: StrategyType
    mutation_type: MutationType
    rationale: str
    constraints: dict[str, Any] = Field(default_factory=dict)
    expected_observation: str


class InputSpecification(BaseModel):
    """Intended input mutation specification without payload strings."""

    target_element: str
    mutation_description: str
    source_description: str | None = None
    purpose: str


class ExpectedBehavior(BaseModel):
    """Security behavior expected from the API endpoint under test."""

    description: str
    expected_status_codes: list[int] = Field(default_factory=list)
    should_reject: bool = True
    security_goal: str


class EvidenceRequirements(BaseModel):
    """Declarative evidence criteria for execution inspection."""

    status_code: bool = True
    response_headers: bool = True
    response_body: bool = True
    response_size: bool = False
    response_time: bool = False
    redirect_information: bool = False
    comparison_context: str | None = None


class TestTemplate(BaseModel):
    """Catalogue-level immutable security test template."""

    __test__ = False

    template_id: str
    name: str
    description: str
    category: SecurityTestCategory
    subcategory: str
    prerequisites: PrerequisiteRequirement
    strategy: TestStrategy
    input_spec_template: InputSpecification
    expected_behavior: ExpectedBehavior
    evidence_requirements: EvidenceRequirements
    baseline_priority: Priority
    baseline_risk_level: RiskLevel
    tags: list[str] = Field(default_factory=list)


class ApplicableTestResult(BaseModel):
    """Endpoint-specific instantiated test case result produced by ApplicabilityEngine."""

    instance_id: str
    template_id: str
    name: str
    category: SecurityTestCategory
    subcategory: str
    target: TestTarget
    strategy: TestStrategy
    input_spec: InputSpecification
    expected_behavior: ExpectedBehavior
    evidence_requirements: EvidenceRequirements
    priority: Priority
    risk_level: RiskLevel
    applicability_reasons: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
