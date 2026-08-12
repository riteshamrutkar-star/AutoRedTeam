from fastapi import APIRouter

from app.schemas.execution import ExecutionRequest, ExecutionResult, RegisteredTarget
from app.services.execution.executor import ExecutionEngine
from app.services.execution.target_registry import target_registry

router = APIRouter(tags=["Executions"])


@router.get(
    "/targets",
    response_model=list[RegisteredTarget],
    summary="Get registered controlled target list",
    description="Retrieve all registered controlled target environments and their base URL configurations.",
)
def list_registered_targets() -> list[RegisteredTarget]:
    """List all registered controlled targets."""
    return target_registry.list_targets()


@router.post(
    "/executions",
    response_model=ExecutionResult,
    summary="Execute a GeneratedSecurityTest against a registered target",
    description="Execute a single declarative GeneratedSecurityTest against an explicitly registered target_id, returning structured execution evidence.",
)
async def execute_security_test(request: ExecutionRequest) -> ExecutionResult:
    """Execute a single GeneratedSecurityTest against a registered target."""
    engine = ExecutionEngine()
    return await engine.execute_test(request)
