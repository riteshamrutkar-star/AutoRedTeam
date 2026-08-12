from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from app.schemas.execution import ExecutionResult
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec


class FindingStatus(str, Enum):
    """Explicit evaluation state for security analysis results."""

    NEGATIVE = "NEGATIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"


class SeverityLevel(str, Enum):
    """Controlled severity levels describing security impact."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceStrength(str, Enum):
    """Structured strength indicator for supporting execution evidence."""

    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class OWASPMapping(BaseModel):
    """OWASP API Security Top 10 mapping information."""

    taxonomy: str = "OWASP_API_TOP_10_2023"
    category_id: str  # e.g., "API1:2023"
    category_name: str  # e.g., "Broken Object Level Authorization"
    rationale: str
    secondary_categories: list[str] = Field(default_factory=list)


class ConfidenceFactors(BaseModel):
    """Structured breakdown of factors contributing to classification confidence score."""

    evidence_strength: EvidenceStrength
    behavior_consistency: float  # 0.0 - 1.0
    test_specificity: float      # 0.0 - 1.0
    expected_behavior_match: float # 0.0 - 1.0
    ambiguity_penalty: float      # 0.0 - 1.0
    overall_score: float         # 0.0 - 1.0


class FindingEvidence(BaseModel):
    """Structured evidence backing a security finding decision."""

    execution_id: str
    status_code: int | None = None
    request_summary: dict[str, Any] = Field(default_factory=dict)
    response_summary: dict[str, Any] = Field(default_factory=dict)
    expected_status_codes: list[int] = Field(default_factory=list)
    observed_indicators: list[str] = Field(default_factory=list)


class AnalysisCandidate(BaseModel):
    """Internal candidate finding produced by rule evaluation before resolution."""

    status: FindingStatus
    template_id: str
    primary_owasp_id: str | None = None
    title: str
    description: str
    evidence_strength: EvidenceStrength
    observed_indicators: list[str] = Field(default_factory=list)
    detection_reason: str
    confidence_inputs: dict[str, float] = Field(default_factory=dict)


class AnalyzeExecutionRequest(BaseModel):
    """API Request wrapper for analyzing an execution result."""

    generated_test: GeneratedSecurityTest
    execution_result: ExecutionResult
    spec: NormalizedApiSpec | None = None


class SecurityFinding(BaseModel):
    """Machine-readable security finding output."""

    finding_id: str
    execution_id: str
    generated_test_id: str
    template_id: str
    target_id: str
    endpoint: str
    http_method: str
    status: FindingStatus
    title: str
    description: str
    category: str
    owasp: OWASPMapping
    severity: SeverityLevel
    severity_rationale: str
    confidence: float
    confidence_factors: ConfidenceFactors
    evidence: FindingEvidence
    detection_reason: str
    remediation_guidance: str
    classifier_version: str = "v1"
