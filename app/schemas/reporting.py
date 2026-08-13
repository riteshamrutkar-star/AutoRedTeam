from typing import Any
from pydantic import BaseModel, Field

from app.schemas.evaluation import (
    AdaptiveEfficiencyMetrics,
    ComparisonMetricItem,
    CoverageItem,
    EvaluationStrategy,
    ExecutionEfficiencyMetrics,
    MetricStatus,
    MetricValue,
)


class DashboardSummary(BaseModel):
    """View model for top-level dashboard KPI cards and evaluation context."""

    evaluation_id: str
    run_name: str
    strategy: EvaluationStrategy
    target_id: str
    started_at: str
    completed_at: str
    evaluation_version: str

    # Spec Context
    spec_title: str | None = None
    spec_version: str | None = None
    endpoints_total: int = 0

    # Key Performance Indicators
    known_vulnerabilities_total: int = 0
    confirmed_findings_count: int = 0
    suspected_findings_count: int = 0
    inconclusive_findings_count: int = 0
    critical_high_count: int = 0

    discovery_rate: MetricValue
    false_positive_rate: MetricValue
    endpoint_coverage: MetricValue
    time_to_first_vulnerability_ms: MetricValue
    time_to_first_known_vulnerability_ms: MetricValue
    total_executions: int = 0


class FindingView(BaseModel):
    """View model for individual security finding entries."""

    finding_id: str
    status: str
    severity: str
    confidence_score: float
    owasp_category_id: str
    owasp_category_name: str
    target_id: str
    endpoint: str
    http_method: str
    title: str
    description: str
    detection_reason: str
    remediation_guidance: str

    # Evidence details
    expected_behavior: str
    observed_behavior: str
    raw_evidence_summary: str


class CoverageView(BaseModel):
    """View model for API coverage metrics across dimensions."""

    endpoint_coverage: CoverageItem
    method_coverage: CoverageItem
    parameter_coverage: CoverageItem
    body_field_coverage: CoverageItem
    template_coverage: CoverageItem
    category_coverage: CoverageItem


class OWASPCategorySummary(BaseModel):
    """View model for OWASP Top 10 category metrics."""

    category_id: str
    category_name: str
    has_active_detection_rule: bool
    findings_count: int = 0
    confirmed_count: int = 0
    suspected_count: int = 0
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    status_label: str = "No findings detected"


class OWASPSummaryView(BaseModel):
    """View model for complete OWASP taxonomy breakdown."""

    taxonomy_version: str = "2023"
    active_rules_count: int = 4
    categories: list[OWASPCategorySummary] = Field(default_factory=list)


class AdaptiveTraceItemView(BaseModel):
    """View model for a single adaptive decision step."""

    iteration: int
    action: str
    target_endpoint: str
    http_method: str
    selected_template_id: str | None = None
    information_gain_score: float = 0.0
    rationale: str
    finding_status: str | None = None
    stop_reason: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None


class AdaptiveTraceView(BaseModel):
    """View model for adaptive session trace timeline."""

    session_id: str
    target_id: str
    status: str
    total_iterations: int = 0
    total_executions: int = 0
    followup_tests_count: int = 0
    stop_reason: str | None = None
    trace: list[AdaptiveTraceItemView] = Field(default_factory=list)
    efficiency: AdaptiveEfficiencyMetrics


class ComparisonView(BaseModel):
    """View model for side-by-side strategy comparison."""

    run_a_name: str
    run_b_name: str
    target_id: str
    metrics: list[ComparisonMetricItem] = Field(default_factory=list)


class ExportPayload(BaseModel):
    """Complete research export payload for JSON downloads."""

    evaluation_id: str
    evaluation_version: str
    run_name: str
    strategy: EvaluationStrategy
    target_id: str
    timestamp: str
    summary: DashboardSummary
    findings: list[FindingView]
    coverage: CoverageView
    owasp_summary: OWASPSummaryView
    adaptive_trace: AdaptiveTraceView | None = None
    comparison: ComparisonView | None = None
    execution_efficiency: ExecutionEfficiencyMetrics
