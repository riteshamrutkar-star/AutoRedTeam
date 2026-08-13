from app.schemas.evaluation import EvaluationInput, EvaluationResult, MetricValue
from app.schemas.finding import FindingStatus, SeverityLevel
from app.schemas.reporting import DashboardSummary


def build_dashboard_summary(
    result: EvaluationResult,
    input_data: EvaluationInput | None = None,
) -> DashboardSummary:
    """Builds DashboardSummary view model from EvaluationResult and optional EvaluationInput."""

    spec_title = None
    spec_version = None
    endpoints_total = result.coverage.endpoint_coverage.denominator

    if input_data and input_data.normalized_spec:
        spec_title = input_data.normalized_spec.metadata.title
        spec_version = input_data.normalized_spec.metadata.version
        endpoints_total = len(input_data.normalized_spec.endpoints)

    findings = input_data.findings if input_data else []
    confirmed = sum(1 for f in findings if f.status == FindingStatus.CONFIRMED)
    suspected = sum(1 for f in findings if f.status == FindingStatus.SUSPECTED)
    inconclusive = sum(1 for f in findings if f.status == FindingStatus.INCONCLUSIVE)

    crit_high = sum(
        1
        for f in findings
        if f.status == FindingStatus.CONFIRMED and f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    )

    return DashboardSummary(
        evaluation_id=result.evaluation_id,
        run_name=result.run_name,
        strategy=result.strategy,
        target_id=result.target_id,
        started_at=result.started_at,
        completed_at=result.completed_at,
        evaluation_version=result.evaluation_version,
        spec_title=spec_title,
        spec_version=spec_version,
        endpoints_total=endpoints_total,
        known_vulnerabilities_total=result.discovery.known_vulnerabilities_total,
        confirmed_findings_count=confirmed,
        suspected_findings_count=suspected,
        inconclusive_findings_count=inconclusive,
        critical_high_count=crit_high,
        discovery_rate=result.discovery.discovery_rate,
        false_positive_rate=result.false_positives.false_positive_rate,
        endpoint_coverage=MetricValue(
            value=result.coverage.endpoint_coverage.percentage,
            status=result.coverage.endpoint_coverage.status,
            reason=result.coverage.endpoint_coverage.reason,
        ),
        time_to_first_vulnerability_ms=result.timing.time_to_first_vulnerability_ms,
        time_to_first_known_vulnerability_ms=result.timing.time_to_first_known_vulnerability_ms,
        total_executions=result.execution_efficiency.total_executed,
    )
