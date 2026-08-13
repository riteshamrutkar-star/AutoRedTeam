from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from app.schemas.adaptive import AdaptiveSession
from app.schemas.execution import ExecutionResult
from app.schemas.finding import SecurityFinding
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec


class EvaluationStrategy(str, Enum):
    """Execution strategy evaluated."""

    STATIC = "STATIC"
    ADAPTIVE = "ADAPTIVE"
    BASELINE = "BASELINE"
    CATALOGUE_ONLY = "CATALOGUE_ONLY"


class MatchStatus(str, Enum):
    """Ground-truth matching classification."""

    KNOWN_MATCH = "KNOWN_MATCH"
    UNMATCHED = "UNMATCHED"
    KNOWN_MISS = "KNOWN_MISS"


class MetricStatus(str, Enum):
    """Status indicating whether a metric was computed, undefined, or not applicable."""

    COMPUTED = "COMPUTED"
    UNDEFINED = "UNDEFINED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MetricValue(BaseModel):
    """Typed container for calculated scalar metrics with explicit status handling."""

    value: float | int | None = None
    status: MetricStatus = MetricStatus.COMPUTED
    reason: str | None = None


class GroundTruthFinding(BaseModel):
    """Representation of a known vulnerability in a target environment."""

    ground_truth_id: str
    target_id: str
    vulnerability_identifier: str
    title: str
    description: str | None = None
    owasp_category: str | None = None
    severity: str | None = None
    endpoint: str
    method: str
    aliases: list[str] = Field(default_factory=list)


class GroundTruthDataset(BaseModel):
    """Ground-truth evaluation dataset container."""

    target_id: str
    scope_complete: bool = True
    vulnerabilities: list[GroundTruthFinding] = Field(default_factory=list)


class BaselineFinding(BaseModel):
    """Normalized finding structure produced by external baseline scanners."""

    finding_id: str
    title: str
    endpoint: str
    method: str
    category: str | None = None
    severity: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BaselineRun(BaseModel):
    """Import container for normalized external baseline tool results."""

    tool_name: str
    tool_version: str | None = None
    target_id: str
    findings: list[BaselineFinding] = Field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoverageItem(BaseModel):
    """Spec-relative coverage score exposing numerator, denominator, percentage, and status."""

    numerator: int
    denominator: int
    percentage: float | None = None
    status: MetricStatus = MetricStatus.COMPUTED
    reason: str | None = None


class CoverageMetrics(BaseModel):
    """Coverage metrics across endpoints, methods, parameters, fields, templates, and categories."""

    endpoint_coverage: CoverageItem
    method_coverage: CoverageItem
    parameter_coverage: CoverageItem
    body_field_coverage: CoverageItem
    template_coverage: CoverageItem
    category_coverage: CoverageItem


class MatchResult(BaseModel):
    """Trace result mapping a reported finding to ground truth."""

    finding_id: str
    ground_truth_id: str | None = None
    match_status: MatchStatus
    confidence: float = 1.0
    reason: str | None = None


class DiscoveryMetrics(BaseModel):
    """Vulnerability discovery statistics and accuracy metrics."""

    known_vulnerabilities_total: int
    unique_vulnerabilities_discovered: int
    discovery_rate: MetricValue
    true_positives: int
    false_positives: int
    false_negatives: int
    suspected_count: int
    inconclusive_count: int
    precision: MetricValue
    recall: MetricValue


class FalsePositiveMetrics(BaseModel):
    """False-positive counts and rates over eligible CONFIRMED findings."""

    false_positive_count: int
    eligible_confirmed_findings: int
    false_positive_rate: MetricValue


class TimingMetrics(BaseModel):
    """Time-to-first-vulnerability and duration statistics."""

    time_to_first_vulnerability_ms: MetricValue
    time_to_first_vulnerability_sec: MetricValue
    time_to_first_known_vulnerability_ms: MetricValue
    total_duration_sec: MetricValue


class AdaptiveEfficiencyMetrics(BaseModel):
    """Efficiency metrics specific to adaptive testing strategies."""

    followup_tests_count: MetricValue
    followup_rate: MetricValue
    confirmation_efficiency: MetricValue
    tests_per_vulnerability: MetricValue
    redundant_attempts_count: MetricValue
    redundant_test_rate: MetricValue


class ExecutionEfficiencyMetrics(BaseModel):
    """Execution status breakdown and request efficiency metrics."""

    total_generated: int
    total_executed: int
    successful_count: int
    blocked_count: int
    failed_count: int
    timed_out_count: int
    avg_duration_ms: MetricValue
    requests_per_finding: MetricValue
    requests_per_known_vulnerability: MetricValue


class ComparisonMetricItem(BaseModel):
    """Side-by-side metric comparison entry between two runs."""

    metric_name: str
    run_a_value: float | int | None = None
    run_b_value: float | int | None = None
    absolute_difference: float | int | None = None
    relative_difference: float | None = None
    status: MetricStatus = MetricStatus.COMPUTED
    reason: str | None = None


class RunComparison(BaseModel):
    """Side-by-side comparison container between two evaluation runs."""

    run_a_name: str
    run_b_name: str
    metrics_comparison: list[ComparisonMetricItem] = Field(default_factory=list)


class EvaluationInput(BaseModel):
    """Input payload containing recorded artifacts to evaluate."""

    run_name: str = "Evaluation Run"
    strategy: EvaluationStrategy = EvaluationStrategy.STATIC
    target_id: str
    normalized_spec: NormalizedApiSpec
    execution_results: list[ExecutionResult] = Field(default_factory=list)
    generated_tests: list[GeneratedSecurityTest] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    adaptive_session: AdaptiveSession | None = None
    ground_truth: GroundTruthDataset | None = None
    baseline_run: BaselineRun | None = None


class EvaluationResult(BaseModel):
    """Complete machine-readable evaluation report."""

    evaluation_id: str
    evaluation_version: str = "v1"
    run_name: str
    strategy: EvaluationStrategy
    target_id: str
    started_at: str
    completed_at: str
    coverage: CoverageMetrics
    discovery: DiscoveryMetrics
    false_positives: FalsePositiveMetrics
    timing: TimingMetrics
    adaptive_efficiency: AdaptiveEfficiencyMetrics
    execution_efficiency: ExecutionEfficiencyMetrics
    matches: list[MatchResult] = Field(default_factory=list)
