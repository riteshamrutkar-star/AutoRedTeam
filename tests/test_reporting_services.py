import json
from pathlib import Path
import pytest

from app.schemas.evaluation import EvaluationInput, EvaluationStrategy, GroundTruthDataset
from app.schemas.finding import FindingStatus
from app.services.evaluation.comparison import IncompatibleComparisonError
from app.services.evaluation.engine import EvaluationEngine
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import normalize_openapi_spec
from app.services.openapi.resolver import resolve_local_references
from app.services.openapi.validator import validate_openapi_spec
from app.services.reporting.adaptive import build_adaptive_trace_view
from app.services.reporting.comparison import build_comparison_view
from app.services.reporting.dashboard import build_dashboard_summary
from app.services.reporting.export import build_export_payload, generate_csv_export
from app.services.reporting.findings import build_finding_views
from app.services.reporting.metrics import build_coverage_view, build_owasp_summary_view
from app.services.reporting.store import evaluation_store
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from app.services.security_analysis.owasp_mapper import OWASPMapper
from tests.test_execution_safety import create_sample_generated_test
from tests.test_security_analyzer import create_sample_execution_result

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def petstore_spec():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    raw = load_spec_from_bytes(yaml_bytes, filename="petstore_openapi.yaml")
    validate_openapi_spec(raw)
    resolved = resolve_local_references(raw)
    return normalize_openapi_spec(resolved)


@pytest.fixture
def ground_truth_dataset():
    gt_data = json.loads((FIXTURES_DIR / "evaluation_ground_truth.json").read_text())
    return GroundTruthDataset(**gt_data)


def test_reporting_store_in_memory_lifecycle(petstore_spec):
    """Test in-memory EvaluationStore set/get/clear lifecycle."""
    input_data = EvaluationInput(
        run_name="Lifecycle Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
    )
    engine = EvaluationEngine()
    result = engine.evaluate(input_data)

    evaluation_store.set_active(input_data, result)
    assert evaluation_store.get_active_result() is not None
    assert evaluation_store.get_active_result().run_name == "Lifecycle Run"

    evaluation_store.clear()
    assert evaluation_store.get_active_result() is None


def test_dashboard_summary_builder(petstore_spec, ground_truth_dataset):
    """Test DashboardSummary generation from EvaluationResult."""
    analyzer = EvidenceAnalyzer()
    owasp_mapper = OWASPMapper()

    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")
    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.status = FindingStatus.CONFIRMED
    finding.owasp = owasp_mapper.map_category("API1:2023", "BOLA")

    input_data = EvaluationInput(
        run_name="Summary Test Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
        execution_results=[exec_res],
        generated_tests=[gen_test],
        findings=[finding],
        ground_truth=ground_truth_dataset,
    )

    engine = EvaluationEngine()
    result = engine.evaluate(input_data)

    summary = build_dashboard_summary(result, input_data)
    assert summary.run_name == "Summary Test Run"
    assert summary.confirmed_findings_count == 1
    assert summary.spec_title == "PetStore Test API"


def test_findings_formatting_and_filtering(petstore_spec):
    """Test FindingView formatting, sanitization, and filtering."""
    analyzer = EvidenceAnalyzer()
    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")
    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.status = FindingStatus.CONFIRMED

    views = build_finding_views([finding], status_filter="CONFIRMED")
    assert len(views) == 1
    assert views[0].status == "CONFIRMED"

    filtered_out = build_finding_views([finding], status_filter="SUSPECTED")
    assert len(filtered_out) == 0


def test_owasp_summary_distinguishes_active_from_registered(petstore_spec):
    """Test OWASPSummaryView clearly distinguishes active rules from registered taxonomy."""
    owasp_summary = build_owasp_summary_view([])
    assert owasp_summary.active_rules_count == 4

    active_cat = next(c for c in owasp_summary.categories if c.category_id == "API1:2023")
    registered_cat = next(c for c in owasp_summary.categories if c.category_id == "API4:2023")

    assert active_cat.has_active_detection_rule is True
    assert "Active rule" in active_cat.status_label

    assert registered_cat.has_active_detection_rule is False
    assert "Registered taxonomy" in registered_cat.status_label


def test_comparison_view_target_mismatch_rejection(petstore_spec):
    """Test build_comparison_view rejects target_id mismatch."""
    input_a = EvaluationInput(run_name="A", target_id="target-1", normalized_spec=petstore_spec)
    input_b = EvaluationInput(run_name="B", target_id="target-2", normalized_spec=petstore_spec)

    engine = EvaluationEngine()
    res_a = engine.evaluate(input_a)
    res_b = engine.evaluate(input_b)

    with pytest.raises(IncompatibleComparisonError):
        build_comparison_view(res_a, res_b)


def test_json_and_csv_exports(petstore_spec):
    """Test research JSON export and tabular CSV generation."""
    input_data = EvaluationInput(
        run_name="Export Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
    )
    engine = EvaluationEngine()
    result = engine.evaluate(input_data)

    export_payload = build_export_payload(result, input_data)
    assert export_payload.run_name == "Export Run"
    assert export_payload.evaluation_version == "v1"

    finding_views = build_finding_views([])
    csv_str = generate_csv_export(finding_views)
    assert "finding_id,status,severity" in csv_str
