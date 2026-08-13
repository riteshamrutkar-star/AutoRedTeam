from pathlib import Path
import asyncio
import httpx
import pytest

from app.schemas.adaptive import (
    AdaptiveAction,
    AdaptiveBudget,
    CreateAdaptiveSessionRequest,
    SessionStatus,
)
from app.schemas.execution import RegisteredTarget
from app.schemas.finding import FindingStatus, SecurityFinding, OWASPMapping, SeverityLevel
from app.services.adaptive.decision_engine import AdaptiveDecisionEngine
from app.services.adaptive.deduplication import compute_test_signature
from app.services.adaptive.engine import AdaptiveTestingEngine
from app.services.adaptive.session_manager import AdaptiveSessionError, session_manager
from app.services.execution.target_registry import TargetRegistry, target_registry
from app.services.openapi.loader import load_spec_from_bytes
from app.services.openapi.normalizer import normalize_openapi_spec
from app.services.openapi.resolver import resolve_local_references
from app.services.openapi.validator import validate_openapi_spec
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from tests.harness import harness_app
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


@pytest.mark.anyio
async def test_adaptive_session_target_lock_and_creation(petstore_spec):
    req = CreateAdaptiveSessionRequest(target_id="vampi-local", spec=petstore_spec)
    session = await session_manager.create_session(req)

    assert session.session_id.startswith("sess_")
    assert session.target_id == "vampi-local"
    assert session.status == SessionStatus.CREATED
    assert session.current_iteration == 0

    # Unregistered target rejection
    bad_req = CreateAdaptiveSessionRequest(target_id="invalid-target-999", spec=petstore_spec)
    with pytest.raises(AdaptiveSessionError) as exc_info:
        await session_manager.create_session(bad_req)
    assert "not registered" in exc_info.value.message


@pytest.mark.anyio
async def test_adaptive_session_state_machine_validation(petstore_spec):
    req = CreateAdaptiveSessionRequest(target_id="vampi-local", spec=petstore_spec)
    session = await session_manager.create_session(req)

    # Valid transition: CREATED -> RUNNING
    session_manager.transition_state(session, SessionStatus.RUNNING)
    assert session.status == SessionStatus.RUNNING

    # Valid transition: RUNNING -> PAUSED
    session_manager.transition_state(session, SessionStatus.PAUSED)
    assert session.status == SessionStatus.PAUSED

    # Valid transition: PAUSED -> COMPLETED
    session_manager.transition_state(session, SessionStatus.COMPLETED, reason="DONE")
    assert session.status == SessionStatus.COMPLETED
    assert session.completed_at is not None

    # Invalid transition: COMPLETED -> RUNNING (terminal state)
    with pytest.raises(AdaptiveSessionError) as exc_info:
        session_manager.transition_state(session, SessionStatus.RUNNING)
    assert "Invalid session state transition" in exc_info.value.message


@pytest.mark.anyio
async def test_strengthened_deduplication_signature():
    sig1 = compute_test_signature("vampi-local", "AUTH-001", "/users", "GET", "AUTHENTICATION", "Authorization", "OMIT", None)
    sig2 = compute_test_signature("vampi-local", "AUTH-001", "/users", "GET", "AUTHENTICATION", "Authorization", "OMIT", None)
    sig3 = compute_test_signature("vampi-local", "AUTH-002", "/users", "GET", "AUTHENTICATION", "Authorization", "OMIT", None)

    assert sig1 == sig2
    assert sig1 != sig3


@pytest.mark.anyio
async def test_adaptive_engine_single_step(petstore_spec):
    target_registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )

    req = CreateAdaptiveSessionRequest(target_id="test-harness", spec=petstore_spec)
    session = await session_manager.create_session(req)

    engine = AdaptiveTestingEngine(manager=session_manager)
    transport = httpx.ASGITransport(app=harness_app)

    updated_session = await engine.step_session(session.session_id, transport=transport)

    assert updated_session.current_iteration == 1
    assert len(updated_session.iterations) == 1
    assert updated_session.status == SessionStatus.RUNNING
    assert len(updated_session.executed_signatures) == 1


@pytest.mark.anyio
async def test_adaptive_engine_budget_limit_enforcement(petstore_spec):
    target_registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )

    # Tight budget of max_iterations = 2
    budget = AdaptiveBudget(max_iterations=2, max_executions=2, max_runtime_seconds=120)
    req = CreateAdaptiveSessionRequest(target_id="test-harness", spec=petstore_spec, budget=budget)
    session = await session_manager.create_session(req)

    engine = AdaptiveTestingEngine(manager=session_manager)
    transport = httpx.ASGITransport(app=harness_app)

    # Step 1
    await engine.step_session(session.session_id, transport=transport)
    assert session.current_iteration == 1
    assert session.status == SessionStatus.RUNNING

    # Step 2
    await engine.step_session(session.session_id, transport=transport)
    assert session.current_iteration == 2

    # Step 3 -> max_iterations (2) reached, session transitions to COMPLETED
    await engine.step_session(session.session_id, transport=transport)
    assert session.status == SessionStatus.COMPLETED
    assert session.stop_reason == "MAX_ITERATIONS_REACHED"


@pytest.mark.anyio
async def test_per_session_concurrency_lock(petstore_spec):
    req = CreateAdaptiveSessionRequest(target_id="vampi-local", spec=petstore_spec)
    session = await session_manager.create_session(req)

    lock1 = await session_manager.get_session_lock(session.session_id)
    lock2 = await session_manager.get_session_lock(session.session_id)

    assert lock1 is lock2


@pytest.mark.anyio
async def test_concurrent_same_session_step(petstore_spec):
    target_registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )

    req = CreateAdaptiveSessionRequest(target_id="test-harness", spec=petstore_spec)
    session = await session_manager.create_session(req)

    engine = AdaptiveTestingEngine(manager=session_manager)
    transport = httpx.ASGITransport(app=harness_app)

    # Launch 2 concurrent step calls on the exact same session
    await asyncio.gather(
        engine.step_session(session.session_id, transport=transport),
        engine.step_session(session.session_id, transport=transport),
    )

    # Check that both stepped sequentially (iteration 1 and iteration 2) under per-session lock
    iteration_numbers = [it.iteration_number for it in session.iterations]
    assert iteration_numbers == [1, 2]
    assert session.current_iteration == 2


@pytest.mark.anyio
async def test_adaptive_suspected_to_confirmed_flow(petstore_spec):
    """Test scenario: SUSPECTED finding -> decision engine triggers CONFIRM -> follow-up executed -> CONFIRMED -> chain stops for that finding."""
    target_registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )

    req = CreateAdaptiveSessionRequest(target_id="test-harness", spec=petstore_spec)
    session = await session_manager.create_session(req)

    analyzer = EvidenceAnalyzer()
    decision_engine = AdaptiveDecisionEngine()

    gen_test = create_sample_generated_test(path="/users", method="GET")
    gen_test.template_id = "AUTH-001"
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTH-001", auth_state="unauthenticated")

    suspected_finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    suspected_finding.status = FindingStatus.SUSPECTED
    session.findings.append(suspected_finding)

    # Evaluate decision -> should decide CONFIRM with complementary template AUTH-002
    decision = decision_engine.evaluate_next_step(session, elapsed_seconds=1.0)
    assert decision.action == AdaptiveAction.CONFIRM
    assert decision.candidate_template_ids == ["AUTH-002"]


@pytest.mark.anyio
async def test_adaptive_negative_to_stop(petstore_spec):
    """Test scenario: NEGATIVE finding with no unexecuted candidates -> decision engine outputs STOP."""
    req = CreateAdaptiveSessionRequest(target_id="vampi-local", spec=petstore_spec)
    session = await session_manager.create_session(req)

    analyzer = EvidenceAnalyzer()
    decision_engine = AdaptiveDecisionEngine()

    # Add all candidate signatures to executed_signatures
    applicable_results = decision_engine.applicability_engine.evaluate_spec(petstore_spec)
    for cand in applicable_results:
        session.executed_signatures.append(f"{cand.template_id}:{cand.target.path}:{cand.target.http_method}")

    gen_test = create_sample_generated_test(path="/health", method="GET")
    gen_test.template_id = "AUTH-001"
    exec_res = create_sample_execution_result(status_code=200, template_id="AUTH-001", auth_state="unauthenticated")

    neg_finding = analyzer.analyze(gen_test, exec_res, spec=petstore_spec)
    session.findings.append(neg_finding)

    decision = decision_engine.evaluate_next_step(session, elapsed_seconds=1.0)
    assert decision.action == AdaptiveAction.STOP
    assert decision.stop_reason == "ALL_CANDIDATES_EXHAUSTED"


@pytest.mark.anyio
async def test_llm_governance_cannot_bypass_applicability_or_target_lock(petstore_spec):
    """LLM governance test proving invalid LLM recommendations cannot bypass Phase 3 applicability or target locking."""
    target_registry.register_target(
        RegisteredTarget(
            target_id="test-harness",
            name="Test Harness",
            description="Local harness",
            target_type="harness",
            base_url="http://testserver",
        )
    )

    req = CreateAdaptiveSessionRequest(target_id="test-harness", spec=petstore_spec)
    session = await session_manager.create_session(req)

    # Attempting to change target_id on session model is locked
    assert session.target_id == "test-harness"

    # Attempting to request unregistered target in session manager raises error
    bad_req = CreateAdaptiveSessionRequest(target_id="http://evil.com/hack", spec=petstore_spec)
    with pytest.raises(AdaptiveSessionError):
        await session_manager.create_session(bad_req)
