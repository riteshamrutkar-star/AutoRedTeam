from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.schemas.evaluation import EvaluationInput, EvaluationResult, EvaluationStrategy
from app.schemas.manifest import ResearchManifest
from app.schemas.reporting import (
    AdaptiveTraceView,
    ComparisonView,
    CoverageView,
    DashboardSummary,
    ExportPayload,
    FindingView,
)
from app.services.evaluation.comparison import IncompatibleComparisonError
from app.services.evaluation.engine import EvaluationEngine
from app.services.reporting.adaptive import build_adaptive_trace_view
from app.services.reporting.comparison import build_comparison_view
from app.services.reporting.dashboard import build_dashboard_summary
from app.services.reporting.export import build_export_payload, generate_csv_export
from app.services.reporting.findings import build_finding_views
from app.services.reporting.manifest import build_research_manifest
from app.services.reporting.metrics import build_coverage_view
from app.services.reporting.store import evaluation_store

router = APIRouter(tags=["Reporting & Research Dashboard"])


def _ensure_active_context() -> tuple[EvaluationInput, EvaluationResult]:
    """Ensures an active evaluation context exists in the store, initializing fallback if empty."""
    active_res = evaluation_store.get_active_result()
    active_inp = evaluation_store.get_active_input()

    if active_res and active_inp:
        return active_inp, active_res

    # Create empty default fallback for fresh server startup
    spec_path = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures" / "petstore_openapi.yaml"
    spec = None
    if spec_path.exists():
        from app.services.openapi.loader import load_spec_from_bytes
        from app.services.openapi.normalizer import normalize_openapi_spec
        from app.services.openapi.resolver import resolve_local_references
        from app.services.openapi.validator import validate_openapi_spec
        raw = load_spec_from_bytes(spec_path.read_bytes(), filename="petstore_openapi.yaml")
        validate_openapi_spec(raw)
        spec = normalize_openapi_spec(resolve_local_references(raw))

    fallback_input = EvaluationInput(
        run_name="Initial Evaluation Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=spec,
    )
    engine = EvaluationEngine()
    fallback_res = engine.evaluate(fallback_input)

    evaluation_store.set_active(fallback_input, fallback_res)
    return fallback_input, fallback_res


@router.post(
    "/reporting/context",
    response_model=DashboardSummary,
    status_code=status.HTTP_200_OK,
    summary="Set active evaluation run context for reporting",
    description="Loads testing artifacts into the in-memory reporting store and computes evaluation metrics.",
)
def set_reporting_context(input_data: EvaluationInput) -> DashboardSummary:
    """Sets the current evaluation context."""
    engine = EvaluationEngine()
    result = engine.evaluate(input_data)
    evaluation_store.set_active(input_data, result)
    return build_dashboard_summary(result, input_data)


@router.get(
    "/reporting/summary",
    response_model=DashboardSummary,
    summary="Get active dashboard executive KPI summary",
    description="Returns top-level KPI metrics, spec metadata, and target context.",
)
def get_dashboard_summary() -> DashboardSummary:
    """Returns active dashboard summary view model."""
    inp, res = _ensure_active_context()
    return build_dashboard_summary(res, inp)


@router.get(
    "/reporting/findings",
    response_model=list[FindingView],
    summary="Get filterable security findings list",
    description="Returns security findings with expected vs observed evidence. Supports presentation-level filtering.",
)
def get_findings_list(
    status_filter: str | None = Query(default=None, description="Filter by status (CONFIRMED, SUSPECTED, INCONCLUSIVE)"),
    severity_filter: str | None = Query(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    owasp_filter: str | None = Query(default=None, description="Filter by OWASP Category ID (e.g. API1:2023)"),
) -> list[FindingView]:
    """Returns formatted list of security findings."""
    inp, _ = _ensure_active_context()
    findings = inp.findings if inp else []
    return build_finding_views(findings, status_filter, severity_filter, owasp_filter)


@router.get(
    "/reporting/coverage",
    response_model=CoverageView,
    summary="Get spec-relative unique coverage metrics",
    description="Returns coverage metrics across endpoints, methods, parameters, request body fields, templates, and categories.",
)
def get_coverage_breakdown() -> CoverageView:
    """Returns coverage breakdown view model."""
    _, res = _ensure_active_context()
    return build_coverage_view(res)


@router.get(
    "/reporting/adaptive",
    response_model=AdaptiveTraceView,
    summary="Get adaptive testing session trace and decision provenance",
    description="Returns iteration timeline, decision rationale, information gain scores, and stopping conditions.",
)
def get_adaptive_trace() -> AdaptiveTraceView:
    """Returns adaptive trace view model."""
    inp, res = _ensure_active_context()
    session = inp.adaptive_session if inp else None
    return build_adaptive_trace_view(res, session)


@router.get(
    "/reporting/comparison",
    response_model=ComparisonView,
    summary="Get side-by-side strategy comparison metrics",
    description="Returns comparison metrics between two runs enforcing target ID compatibility.",
)
def get_comparison() -> ComparisonView:
    """Returns comparison view model for active and secondary runs."""
    _, res_a = _ensure_active_context()
    res_b = evaluation_store.get_secondary_result()

    if not res_b:
        # Fallback comparison against self if no secondary run provided
        res_b = res_a

    try:
        return build_comparison_view(res_a, res_b)
    except IncompatibleComparisonError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/reporting/export/json",
    response_model=ExportPayload,
    summary="Export research report as structured JSON",
    description="Download complete machine-readable evaluation report for academic research and baseline comparison.",
)
def export_json_report() -> ExportPayload:
    """Export complete research payload as JSON."""
    inp, res_a = _ensure_active_context()
    res_b = evaluation_store.get_secondary_result()
    return build_export_payload(res_a, inp, res_b)


@router.get(
    "/reporting/export/csv",
    summary="Export security findings as CSV table",
    description="Download tabular CSV report of discovered security findings.",
)
def export_csv_report() -> Response:
    """Export findings table as CSV."""
    inp, _ = _ensure_active_context()
    findings = inp.findings if inp else []
    finding_views = build_finding_views(findings)
    csv_content = generate_csv_export(finding_views)

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="autoredteam_findings.csv"'},
    )


@router.get(
    "/reporting/manifest",
    response_model=ResearchManifest,
    summary="Get research reproducibility manifest",
    description="Returns machine-readable manifest containing versioning metadata, LLM provider settings, target ID, and strategy configuration.",
)
def get_manifest() -> ResearchManifest:
    """Get research reproducibility manifest."""
    inp, res = _ensure_active_context()
    return build_research_manifest(res, inp)
