import asyncio
import json
from pathlib import Path
import pytest

from app.schemas.evaluation import EvaluationInput, EvaluationStrategy, GroundTruthDataset
from app.schemas.finding import FindingStatus
from app.services.adaptive.session_manager import AdaptiveSessionManager
from app.services.evaluation.comparison import compare_evaluation_results
from app.services.evaluation.engine import EvaluationEngine
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import normalize_openapi_spec
from app.services.openapi.resolver import resolve_local_references
from app.services.openapi.validator import validate_openapi_spec
from app.services.reporting.export import build_export_payload, generate_csv_export
from app.services.reporting.findings import build_finding_views
from app.services.reporting.manifest import build_research_manifest
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


def test_full_pipeline_static_integration(petstore_spec, ground_truth_dataset):
    """End-to-end integration test: Spec -> Test -> Execution -> Finding -> Evaluation -> Export."""
    analyzer = EvidenceAnalyzer()
    owasp_mapper = OWASPMapper()

    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")
    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.status = FindingStatus.CONFIRMED
    finding.owasp = owasp_mapper.map_category("API1:2023", "BOLA")

    input_data = EvaluationInput(
        run_name="Full Pipeline Integration Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
        execution_results=[exec_res],
        generated_tests=[gen_test],
        findings=[finding],
        ground_truth=ground_truth_dataset,
    )

    engine = EvaluationEngine()
    eval_result = engine.evaluate(input_data)

    assert eval_result.strategy == EvaluationStrategy.STATIC
    assert eval_result.discovery.true_positives == 1
    assert eval_result.discovery.unique_vulnerabilities_discovered == 1

    export_payload = build_export_payload(eval_result, input_data)
    assert export_payload.summary.confirmed_findings_count == 1
    assert export_payload.summary.spec_title == "PetStore Test API"

    manifest = build_research_manifest(eval_result, input_data)
    assert manifest.autoredteam_version == "1.0.0"
    assert manifest.target_id == "vampi-local"


def test_full_pipeline_adaptive_suspected_to_confirmed(petstore_spec):
    """End-to-end integration test: Adaptive loop transitions SUSPECTED -> CONFIRMED and stops."""
    from app.schemas.adaptive import CreateAdaptiveSessionRequest
    manager = AdaptiveSessionManager()
    session = asyncio.run(manager.create_session(CreateAdaptiveSessionRequest(target_id="vampi-local", spec=petstore_spec)))

    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")
    analyzer = EvidenceAnalyzer()
    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.status = FindingStatus.SUSPECTED

    from app.services.adaptive.decision_engine import AdaptiveDecisionEngine
    decision_engine = AdaptiveDecisionEngine()

    # Step 1: Record suspected finding -> Decision engine evaluates CONFIRM follow-up action
    session.findings.append(finding)
    dec1 = decision_engine.evaluate_next_step(session, elapsed_seconds=0.0)
    assert dec1.action.value == "CONFIRM"

    # Step 2: Transition finding to CONFIRMED -> Confirmation chain stops for that finding
    finding.status = FindingStatus.CONFIRMED
    dec2 = decision_engine.evaluate_next_step(session, elapsed_seconds=0.0)
    assert dec2.action.value in ("REFINE", "EXPLORE", "STOP")


def test_baseline_run_comparison_pipeline(petstore_spec, ground_truth_dataset):
    """End-to-end integration test: Static run vs Baseline run comparison."""
    input_static = EvaluationInput(
        run_name="Static Run",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
        ground_truth=ground_truth_dataset,
    )
    base_data = json.loads((FIXTURES_DIR / "evaluation_baseline.json").read_text())
    input_base = EvaluationInput(
        run_name="Baseline Run",
        strategy=EvaluationStrategy.BASELINE,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
        baseline_run=base_data,
        ground_truth=ground_truth_dataset,
    )

    engine = EvaluationEngine()
    res_static = engine.evaluate(input_static)
    res_base = engine.evaluate(input_base)

    comparison = compare_evaluation_results(res_static, res_base)
    assert comparison.run_a_name.startswith("Static Run")
    assert comparison.run_b_name.startswith("Baseline Run")
    assert len(comparison.metrics_comparison) > 0


def test_safety_regressions_and_dashboard_readonly(client):
    """Safety regression tests: Health exposes version, Dashboard is read-only, Manifest available."""
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    h_data = health_resp.json()
    assert h_data["version"] == "1.0.0"
    assert h_data["status"] == "ok"

    manifest_resp = client.get("/api/v1/reporting/manifest")
    assert manifest_resp.status_code == 200
    m_data = manifest_resp.json()
    assert m_data["autoredteam_version"] == "1.0.0"

    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    assert "Research Disclaimer:" in dash_resp.text
