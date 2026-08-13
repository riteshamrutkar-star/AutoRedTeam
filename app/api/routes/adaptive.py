from fastapi import APIRouter, HTTPException, status

from app.schemas.adaptive import (
    AdaptiveSession,
    CreateAdaptiveSessionRequest,
    RunSessionRequest,
)
from app.services.adaptive.engine import AdaptiveTestingEngine
from app.services.adaptive.session_manager import AdaptiveSessionError, session_manager

router = APIRouter(tags=["Adaptive Red-Team Loop"])


@router.post(
    "/adaptive/sessions",
    response_model=AdaptiveSession,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new adaptive red-team testing session",
    description="Initialize a new adaptive session locked to a single target_id and OpenAPI specification baseline.",
)
async def create_adaptive_session(request: CreateAdaptiveSessionRequest) -> AdaptiveSession:
    """Create a new adaptive session."""
    try:
        return await session_manager.create_session(request)
    except AdaptiveSessionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)


@router.get(
    "/adaptive/sessions/{session_id}",
    response_model=AdaptiveSession,
    summary="Get adaptive testing session state and iteration history",
    description="Retrieve full session state, current budget, finding history, and iteration trace for an active or completed session.",
)
def get_adaptive_session(session_id: str) -> AdaptiveSession:
    """Get session state by ID."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session '{session_id}' not found.")
    return session


@router.post(
    "/adaptive/sessions/{session_id}/step",
    response_model=AdaptiveSession,
    summary="Execute exactly one iteration step in an adaptive session",
    description="Execute one single iteration (decision -> candidate selection -> generation -> execution -> analysis) under per-session concurrency lock.",
)
async def step_adaptive_session(session_id: str) -> AdaptiveSession:
    """Execute one step in an adaptive session."""
    engine = AdaptiveTestingEngine()
    try:
        return await engine.step_session(session_id)
    except AdaptiveSessionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)


@router.post(
    "/adaptive/sessions/{session_id}/run",
    response_model=AdaptiveSession,
    summary="Run bounded adaptive iterations for a session",
    description="Run up to max_steps_this_call adaptive iterations in a loop while respecting session budget and stopping conditions.",
)
async def run_adaptive_session(session_id: str, request: RunSessionRequest | None = None) -> AdaptiveSession:
    """Run bounded iterations in an adaptive session."""
    steps = request.max_steps_this_call if request else 5
    engine = AdaptiveTestingEngine()
    try:
        return await engine.run_session(session_id, max_steps_this_call=steps)
    except AdaptiveSessionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)
