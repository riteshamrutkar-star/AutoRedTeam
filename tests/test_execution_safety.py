import httpx
import pytest

from app.schemas.execution import (
    ExecutionOptions,
    ExecutionRequest,
    ExecutionStatus,
    RegisteredTarget,
)
from app.schemas.generated_test import (
    EvidenceRequirements,
    ExpectedBehavior,
    GeneratedSecurityTest,
    GenerationMetadata,
    RequestPlan,
)
from app.services.execution.executor import ExecutionEngine
from app.services.execution.request_builder import redact_headers
from app.services.execution.target_registry import TargetRegistry
from tests.harness import harness_app


def create_sample_generated_test(path: str = "/users", method: str = "GET") -> GeneratedSecurityTest:
    return GeneratedSecurityTest(
        generated_test_id="gen_test_001",
        instance_id="users_GET_AUTH-001",
        template_id="AUTH-001",
        endpoint_target=path,
        http_method=method,
        rationale="Testing safety boundaries",
        test_objective="Ensure execution safety policy holds",
        request_plan=RequestPlan(http_method=method, path=path),
        expected_behavior=ExpectedBehavior(description="Reject", expected_status_codes=[401], security_goal="Goal"),
        evidence_requirements=EvidenceRequirements(),
        generation_metadata=GenerationMetadata(
            provider="mock",
            model="mock-v1",
            generation_timestamp="2026-08-12T19:00:00Z",
            template_id="AUTH-001",
        ),
        confidence=0.9,
    )


@pytest.mark.anyio
async def test_unregistered_target_rejected():
    engine = ExecutionEngine()
    test = create_sample_generated_test()
    req = ExecutionRequest(target_id="unregistered-target-999", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.allowed is False
    assert result.policy_decision.rule_violated == "UNREGISTERED_TARGET"


@pytest.mark.anyio
async def test_disabled_target_rejected():
    registry = TargetRegistry()
    target = RegisteredTarget(
        target_id="disabled-target",
        name="Disabled Target",
        description="Testing disabled target policy",
        target_type="test",
        base_url="http://localhost:8001",
        enabled=False,
    )
    registry.register_target(target)

    engine = ExecutionEngine(registry=registry)
    test = create_sample_generated_test()
    req = ExecutionRequest(target_id="disabled-target", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.rule_violated == "TARGET_DISABLED"


@pytest.mark.anyio
async def test_ssrf_absolute_url_rejected():
    registry = TargetRegistry()
    registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )
    engine = ExecutionEngine(registry=registry)

    test = create_sample_generated_test(path="http://evil.example.com/steal")
    req = ExecutionRequest(target_id="test-harness", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.rule_violated == "ABSOLUTE_URL_FORBIDDEN"


@pytest.mark.anyio
async def test_ssrf_scheme_relative_url_rejected():
    registry = TargetRegistry()
    registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )
    engine = ExecutionEngine(registry=registry)

    test = create_sample_generated_test(path="//evil.example.com/steal")
    req = ExecutionRequest(target_id="test-harness", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.rule_violated == "SCHEME_RELATIVE_URL_FORBIDDEN"


@pytest.mark.anyio
async def test_ssrf_authority_change_rejected():
    registry = TargetRegistry()
    registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )
    engine = ExecutionEngine(registry=registry)

    test = create_sample_generated_test(path="/user@evil.example.com")
    req = ExecutionRequest(target_id="test-harness", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.rule_violated == "AUTHORITY_CHANGE_FORBIDDEN"


@pytest.mark.anyio
async def test_path_traversal_rejected():
    registry = TargetRegistry()
    registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )
    engine = ExecutionEngine(registry=registry)

    test = create_sample_generated_test(path="/users/../admin")
    req = ExecutionRequest(target_id="test-harness", generated_test=test)

    result = await engine.execute_test(req)
    assert result.status == ExecutionStatus.BLOCKED
    assert result.policy_decision.rule_violated == "PATH_TRAVERSAL_FORBIDDEN"


@pytest.mark.anyio
async def test_header_redaction():
    headers = {
        "Authorization": "Bearer super_secret_token",
        "Cookie": "session=secret_session_id",
        "X-API-Key": "secret_api_key_123",
        "Accept": "application/json",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["X-API-Key"] == "[REDACTED]"
    assert redacted["Accept"] == "application/json"


@pytest.mark.anyio
async def test_redirect_not_followed():
    """Verify that external redirects are not followed when follow_redirects is False."""
    registry = TargetRegistry()
    registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )
    engine = ExecutionEngine(registry=registry)

    test = create_sample_generated_test(path="/redirect")
    req = ExecutionRequest(
        target_id="test-harness",
        generated_test=test,
        options=ExecutionOptions(follow_redirects=False),
    )

    transport = httpx.ASGITransport(app=harness_app)
    result = await engine.execute_test(req, transport=transport)

    assert result.status == ExecutionStatus.COMPLETED
    assert result.response_evidence is not None
    assert result.response_evidence.status_code == 302
    assert "evil.example.com" in result.response_evidence.headers.get("location", "")
    assert result.response_evidence.final_url_host == "testserver"  # Did NOT follow redirect to evil.example.com
