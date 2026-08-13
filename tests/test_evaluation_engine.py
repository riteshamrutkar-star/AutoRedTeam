import json
from pathlib import Path
import pytest

from app.schemas.evaluation import (
    BaselineRun,
    EvaluationInput,
    EvaluationStrategy,
    GroundTruthDataset,
    MetricStatus,
)
from app.schemas.finding import FindingStatus
from app.services.evaluation.comparison import IncompatibleComparisonError, compare_evaluation_results
from app.services.evaluation.engine import EvaluationEngine
from app.services.evaluation.ground_truth import match_findings_to_ground_truth
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import normalize_openapi_spec
from app.services.openapi.resolver import resolve_local_references
from app.services.openapi.validator import validate_openapi_spec
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


@pytest.fixture
def baseline_run_data():
    base_data = json.loads((FIXTURES_DIR / "evaluation_baseline.json").read_text())
    return BaselineRun(**base_data)


def test_cross_target_ground_truth_matching_rejection(petstore_spec, ground_truth_dataset):
    """Negative test: matching findings from a different target_id against ground truth must be rejected/unmatched."""
    analyzer = EvidenceAnalyzer()
    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTH-001")
    exec_res.target_id = "different-target-123"

    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.target_id = "different-target-123"

    matches = match_findings_to_ground_truth("different-target-123", [finding], ground_truth_dataset)
    assert len(matches) == 1
    assert matches[0].match_status.value == "UNMATCHED"
    assert "Target ID mismatch" in matches[0].reason


def test_finding_status_tp_fp_eligibility(petstore_spec, ground_truth_dataset):
    """Test that only CONFIRMED findings are eligible for TP/FP ground-truth matching."""
    analyzer = EvidenceAnalyzer()
    owasp_mapper = OWASPMapper()

    # Confirmed finding matching gt_auth_001
    gen1 = create_sample_generated_test(path="/users/{id}", method="GET")
    exec1 = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")
    confirmed_f = analyzer.analyze(gen1, exec1, spec=petstore_spec)
    confirmed_f.status = FindingStatus.CONFIRMED
    confirmed_f.owasp = owasp_mapper.map_category("API1:2023", "BOLA")

    # Suspected finding on /admin/settings
    gen2 = create_sample_generated_test(path="/admin/settings", method="POST")
    exec2 = create_sample_execution_result(status_code=200, template_id="AUTH-001")
    suspected_f = analyzer.analyze(gen2, exec2, spec=petstore_spec)
    suspected_f.status = FindingStatus.SUSPECTED

    matches = match_findings_to_ground_truth("vampi-local", [confirmed_f, suspected_f], ground_truth_dataset)

    # Only 1 confirmed finding matched + 1 ground-truth miss recorded
    matched_ids = [m.ground_truth_id for m in matches if m.match_status.value == "KNOWN_MATCH"]
    assert matched_ids == ["gt_auth_001"]


def test_evaluation_engine_deterministic_metrics(petstore_spec, ground_truth_dataset):
    """Test EvaluationEngine computes complete deterministic evaluation metrics."""
    analyzer = EvidenceAnalyzer()
    owasp_mapper = OWASPMapper()

    gen_test = create_sample_generated_test(path="/users/{id}", method="GET")
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")

    finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    finding.status = FindingStatus.CONFIRMED
    finding.owasp = owasp_mapper.map_category("API1:2023", "BOLA")

    input_data = EvaluationInput(
        run_name="Test Run",
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

    assert result.strategy == EvaluationStrategy.STATIC
    assert result.discovery.true_positives == 1
    assert result.discovery.unique_vulnerabilities_discovered == 1
    assert result.discovery.known_vulnerabilities_total == 2
    assert result.discovery.discovery_rate.value == 0.5


def test_baseline_run_evaluation_setting_adaptive_not_applicable(petstore_spec, baseline_run_data):
    """Test evaluating a baseline run sets adaptive metrics to NOT_APPLICABLE."""
    input_data = EvaluationInput(
        run_name="Baseline Run",
        strategy=EvaluationStrategy.BASELINE,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
        baseline_run=baseline_run_data,
    )

    engine = EvaluationEngine()
    result = engine.evaluate(input_data)

    assert result.strategy == EvaluationStrategy.BASELINE
    assert result.adaptive_efficiency.followup_tests_count.status == MetricStatus.NOT_APPLICABLE
    assert "not applicable" in result.adaptive_efficiency.followup_tests_count.reason.lower()


def test_incompatible_baseline_comparison_rejection(petstore_spec, ground_truth_dataset):
    """Test that comparing evaluation runs with different target_id throws IncompatibleComparisonError."""
    input_a = EvaluationInput(
        run_name="Run A",
        strategy=EvaluationStrategy.STATIC,
        target_id="vampi-local",
        normalized_spec=petstore_spec,
    )
    input_b = EvaluationInput(
        run_name="Run B",
        strategy=EvaluationStrategy.ADAPTIVE,
        target_id="juiceshop-local",  # Different target_id
        normalized_spec=petstore_spec,
    )

    engine = EvaluationEngine()
    res_a = engine.evaluate(input_a)
    res_b = engine.evaluate(input_b)

    with pytest.raises(IncompatibleComparisonError) as exc_info:
        compare_evaluation_results(res_a, res_b)
    assert "Incompatible experiment comparison" in exc_info.value.args[0]
