import csv
from io import StringIO

from app.schemas.evaluation import EvaluationInput, EvaluationResult
from app.schemas.reporting import ExportPayload, FindingView
from app.services.reporting.adaptive import build_adaptive_trace_view
from app.services.reporting.comparison import build_comparison_view
from app.services.reporting.dashboard import build_dashboard_summary
from app.services.reporting.findings import build_finding_views
from app.services.reporting.metrics import build_coverage_view, build_owasp_summary_view


def build_export_payload(
    result: EvaluationResult,
    input_data: EvaluationInput | None = None,
    comparison_result: EvaluationResult | None = None,
) -> ExportPayload:
    """Builds complete ExportPayload JSON object for research reporting."""

    summary = build_dashboard_summary(result, input_data)
    findings = input_data.findings if input_data else []
    finding_views = build_finding_views(findings)
    coverage_view = build_coverage_view(result)
    owasp_view = build_owasp_summary_view(findings)

    adaptive_view = None
    if input_data and input_data.adaptive_session:
        adaptive_view = build_adaptive_trace_view(result, input_data.adaptive_session)

    comp_view = None
    if comparison_result:
        comp_view = build_comparison_view(result, comparison_result)

    return ExportPayload(
        evaluation_id=result.evaluation_id,
        evaluation_version=result.evaluation_version,
        run_name=result.run_name,
        strategy=result.strategy,
        target_id=result.target_id,
        timestamp=result.completed_at,
        summary=summary,
        findings=finding_views,
        coverage=coverage_view,
        owasp_summary=owasp_view,
        adaptive_trace=adaptive_view,
        comparison=comp_view,
        execution_efficiency=result.execution_efficiency,
    )


def generate_csv_export(findings: list[FindingView]) -> str:
    """Generates tabular CSV export string for security findings."""

    output = StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow([
        "finding_id",
        "status",
        "severity",
        "confidence_score",
        "owasp_category_id",
        "owasp_category_name",
        "target_id",
        "endpoint",
        "http_method",
        "title",
    ])

    for f in findings:
        writer.writerow([
            f.finding_id,
            f.status,
            f.severity,
            f.confidence_score,
            f.owasp_category_id,
            f.owasp_category_name,
            f.target_id,
            f.endpoint,
            f.http_method,
            f.title,
        ])

    return output.getvalue()
