from app.schemas.evaluation import EvaluationResult
from app.schemas.finding import FindingStatus, SecurityFinding
from app.schemas.reporting import CoverageView, OWASPCategorySummary, OWASPSummaryView
from app.services.security_analysis.owasp_mapper import ACTIVE_DETECTION_CATEGORIES, OWASP_API_TOP_10_2023


def build_coverage_view(result: EvaluationResult) -> CoverageView:
    """Builds CoverageView view model from EvaluationResult."""
    return CoverageView(
        endpoint_coverage=result.coverage.endpoint_coverage,
        method_coverage=result.coverage.method_coverage,
        parameter_coverage=result.coverage.parameter_coverage,
        body_field_coverage=result.coverage.body_field_coverage,
        template_coverage=result.coverage.template_coverage,
        category_coverage=result.coverage.category_coverage,
    )


def build_owasp_summary_view(findings: list[SecurityFinding]) -> OWASPSummaryView:
    """Builds OWASPSummaryView distinguishing active detection categories from registered-only categories."""

    categories: list[OWASPCategorySummary] = []

    for cat_id, cat_info in OWASP_API_TOP_10_2023.items():
        is_active = cat_id in ACTIVE_DETECTION_CATEGORIES
        cat_findings = [f for f in findings if f.owasp.category_id == cat_id]

        confirmed = sum(1 for f in cat_findings if f.status == FindingStatus.CONFIRMED)
        suspected = sum(1 for f in cat_findings if f.status == FindingStatus.SUSPECTED)

        sev_dist: dict[str, int] = {}
        for f in cat_findings:
            sev_str = f.severity.value
            sev_dist[sev_str] = sev_dist.get(sev_str, 0) + 1

        if confirmed > 0:
            status_label = f"{confirmed} Confirmed Finding(s)"
        elif suspected > 0:
            status_label = f"{suspected} Suspected Finding(s)"
        elif is_active:
            status_label = "No active findings detected (Active rule)"
        else:
            status_label = "No active detection rule implemented (Registered taxonomy)"

        cat_summary = OWASPCategorySummary(
            category_id=cat_id,
            category_name=cat_info["name"],
            has_active_detection_rule=is_active,
            findings_count=len(cat_findings),
            confirmed_count=confirmed,
            suspected_count=suspected,
            severity_distribution=sev_dist,
            status_label=status_label,
        )
        categories.append(cat_summary)

    return OWASPSummaryView(
        taxonomy_version="2023",
        active_rules_count=len(ACTIVE_DETECTION_CATEGORIES),
        categories=categories,
    )
