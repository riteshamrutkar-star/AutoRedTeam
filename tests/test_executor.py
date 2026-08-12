import httpx
import pytest

from app.schemas.execution import (
    ExecutionOptions,
    ExecutionRequest,
    ExecutionStatus,
    RegisteredTarget,
)
from app.services.execution.executor import ExecutionEngine
from app.services.execution.target_registry import TargetRegistry
from tests.harness import harness_app
from tests.test_execution_safety import create_sample_generated_test


@pytest.mark.anyio
async def test_executor_successful_get():
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

    test = create_sample_generated_test(path="/users/00000000-0000-0000-0000-000000000001", method="GET")
    req = ExecutionRequest(target_id="test-harness", generated_test=test)

    transport = httpx.ASGITransport(app=harness_app)
    result = await engine.execute_test(req, transport=transport)

    assert result.status == ExecutionStatus.COMPLETED
    assert result.response_evidence is not None
    assert result.response_evidence.status_code == 200
    assert "alice" in result.response_evidence.body
    assert result.request_evidence.path == "/users/00000000-0000-0000-0000-000000000001"


@pytest.mark.anyio
async def test_executor_streamed_response_truncation():
    """Verify that responses exceeding max_response_bytes are truncated during streamed reading."""
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

    test = create_sample_generated_test(path="/large-response", method="GET")
    # Cap max response bytes at 50,000 bytes (50 KB) while payload is ~250 KB
    req = ExecutionRequest(
        target_id="test-harness",
        generated_test=test,
        options=ExecutionOptions(max_response_bytes=50000),
    )

    transport = httpx.ASGITransport(app=harness_app)
    result = await engine.execute_test(req, transport=transport)

    assert result.status == ExecutionStatus.COMPLETED
    assert result.response_evidence is not None
    assert result.response_evidence.truncated is True
    assert len(result.response_evidence.body) == 50000
    assert result.response_evidence.body_size > 50000


class TimingOutTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Request timed out after 1.0 seconds.")


@pytest.mark.anyio
async def test_executor_timeout_handling():
    """Verify timeout leads to ExecutionStatus.TIMEOUT status."""
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

    test = create_sample_generated_test(path="/slow-response", method="GET")
    req = ExecutionRequest(
        target_id="test-harness",
        generated_test=test,
        options=ExecutionOptions(timeout_seconds=1),
    )

    transport = TimingOutTransport()
    result = await engine.execute_test(req, transport=transport)

    assert result.status == ExecutionStatus.TIMEOUT
    assert "timed out" in result.error.lower()
