from app.schemas.execution import (
    ExecutionResult,
    ExecutionStatus,
    PolicyDecision,
    RequestEvidence,
    ResponseEvidence,
)
from app.schemas.finding import FindingStatus, SeverityLevel
from app.schemas.generated_test import InputMutation
from app.schemas.spec import NormalizedApiSpec, NormalizedEndpoint
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from tests.test_execution_safety import create_sample_generated_test


def create_sample_execution_result(
    status_code: int = 200,
    body: str = '{"id": "1", "username": "alice"}',
    template_id: str = "AUTH-001",
    auth_state: str | None = "unauthenticated",
) -> ExecutionResult:
    return ExecutionResult(
        execution_id="exec_test_001",
        target_id="vampi-local",
        generated_test_id="gen_test_001",
        status=ExecutionStatus.COMPLETED,
        started_at="2026-08-12T20:00:00Z",
        completed_at="2026-08-12T20:00:00.100Z",
        duration_ms=100.0,
        request_evidence=RequestEvidence(
            method="GET",
            target_id="vampi-local",
            path="/users",
            headers={"Accept": "application/json"},
            auth_state=auth_state,
        ),
        response_evidence=ResponseEvidence(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            body=body,
            body_size=len(body),
            duration_ms=90.0,
            final_url_host="localhost",
        ),
        policy_decision=PolicyDecision(allowed=True, reason="Allowed"),
    )


def test_positive_authentication_vulnerability():
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users", method="GET")
    test.template_id = "AUTH-001"
    # Unauthenticated request returning HTTP 200 on declared protected endpoint -> CONFIRMED API2:2023
    result = create_sample_execution_result(status_code=200, template_id="AUTH-001", auth_state="unauthenticated")

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.owasp.category_id == "API2:2023"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence >= 0.8


def test_negative_unprotected_public_endpoint():
    """Requirement 1 Negative Test: HTTP 200 on unprotected public endpoint must be NEGATIVE, not API2."""
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/health", method="GET")
    test.template_id = "AUTH-001"
    test.expected_behavior.expected_status_codes = [200]  # Public endpoint expects 200

    from app.schemas.spec import ApiMetadata

    spec = NormalizedApiSpec(
        metadata=ApiMetadata(title="Public API", version="1.0.0"),
        endpoints=[
            NormalizedEndpoint(
                path="/health",
                method="GET",
                security=[],  # Explicitly unauthenticated
            )
        ],
    )
    result = create_sample_execution_result(status_code=200, template_id="AUTH-001", auth_state="unauthenticated")

    finding = analyzer.analyze(test, result, spec=spec)
    assert finding.status == FindingStatus.NEGATIVE
    assert finding.owasp.category_id == "NONE"


def test_negative_benign_property_accepted():
    """Requirement 2 Negative Test: Accepting unexpected benign field (e.g. page) must be NEGATIVE, not API3."""
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users", method="POST")
    test.template_id = "BODY-002"
    test.input_mutations = [
        InputMutation(
            location="REQUEST_BODY",
            target="page",  # Benign property
            mutation_type="UNEXPECTED_FIELD",
            rationale="Add benign property",
        )
    ]
    result = create_sample_execution_result(
        status_code=200,
        body='{"status": "ok", "page": 1}',
        template_id="BODY-002",
    )

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.NEGATIVE
    assert finding.owasp.category_id == "NONE"


def test_positive_sensitive_property_mass_assignment():
    """Requirement 2 Positive Test: Accepting sensitive property (role/is_admin) triggers API3."""
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users", method="POST")
    test.template_id = "BODY-002"
    test.input_mutations = [
        InputMutation(
            location="REQUEST_BODY",
            target="is_admin",  # Sensitive property
            mutation_type="UNEXPECTED_FIELD",
            rationale="Add admin property",
        )
    ]
    result = create_sample_execution_result(
        status_code=200,
        body='{"username": "test", "is_admin": true}',
        template_id="BODY-002",
    )

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.owasp.category_id == "API3:2023"


def test_http_500_evaluates_to_inconclusive_without_owasp8():
    """Requirement 3 Negative Test: HTTP 500 without security evidence evaluates to INCONCLUSIVE with OWASP category_id=NONE."""
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users", method="GET")
    test.template_id = "INP-001"
    result = create_sample_execution_result(status_code=500, template_id="INP-001")

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.INCONCLUSIVE
    assert finding.owasp.category_id == "NONE"


def test_normal_validation_error_evaluates_to_negative():
    """Requirement 3 Negative Test: Defensive 400/422 validation responses evaluate to NEGATIVE."""
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users", method="POST")
    test.template_id = "INP-001"
    result = create_sample_execution_result(status_code=422, body='{"error": "Validation Error"}', template_id="INP-001")

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.NEGATIVE
    assert finding.owasp.category_id == "NONE"


def test_positive_bola_vulnerability():
    analyzer = EvidenceAnalyzer()
    test = create_sample_generated_test(path="/users/00000000-0000-0000-0000-000000000001", method="GET")
    test.template_id = "AUTHZ-001"
    result = create_sample_execution_result(status_code=200, template_id="AUTHZ-001")

    finding = analyzer.analyze(test, result)
    assert finding.status == FindingStatus.CONFIRMED
    assert finding.owasp.category_id == "API1:2023"
    assert finding.severity == SeverityLevel.HIGH
