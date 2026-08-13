import asyncio
from datetime import datetime, timezone
import uuid

from app.core.config import settings
from app.core.exceptions import OpenAPIException
from app.schemas.adaptive import (
    AdaptiveBudget,
    AdaptiveSession,
    CreateAdaptiveSessionRequest,
    SessionStatus,
)
from app.services.execution.target_registry import target_registry


class AdaptiveSessionError(OpenAPIException):
    """Exception raised when adaptive session creation, state transition, or lock fails."""

    pass


class AdaptiveSessionManager:
    """Manages in-memory adaptive sessions, state machine transitions, and per-session concurrency locks."""

    def __init__(self) -> None:
        self._sessions: dict[str, AdaptiveSession] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def create_session(self, request: CreateAdaptiveSessionRequest) -> AdaptiveSession:
        """Initializes a new AdaptiveSession locked to target_id and spec."""
        target = target_registry.get_target(request.target_id)
        if not target:
            raise AdaptiveSessionError(f"Target '{request.target_id}' is not registered in target allowlist.")

        if not target.enabled:
            raise AdaptiveSessionError(f"Target '{request.target_id}' is currently disabled.")

        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc).isoformat()

        budget = request.budget or AdaptiveBudget(
            max_iterations=settings.ADAPTIVE_MAX_ITERATIONS,
            max_executions=settings.ADAPTIVE_MAX_EXECUTIONS,
            max_generated_tests=settings.ADAPTIVE_MAX_GENERATED_TESTS,
            max_runtime_seconds=settings.ADAPTIVE_MAX_RUNTIME_SECONDS,
            max_followups_per_finding=settings.ADAPTIVE_MAX_FOLLOWUPS_PER_FINDING,
        )

        session = AdaptiveSession(
            session_id=session_id,
            target_id=target.target_id,
            spec=request.spec,
            status=SessionStatus.CREATED,
            started_at=now_utc,
            budget=budget,
        )

        async with self._global_lock:
            self._sessions[session_id] = session
            self._locks[session_id] = asyncio.Lock()

        return session

    def get_session(self, session_id: str) -> AdaptiveSession | None:
        """Retrieves a session by ID."""
        return self._sessions.get(session_id)

    async def get_session_lock(self, session_id: str) -> asyncio.Lock:
        """Retrieves the per-session concurrency lock, preventing simultaneous step/run races."""
        async with self._global_lock:
            if session_id not in self._locks:
                self._locks[session_id] = asyncio.Lock()
            return self._locks[session_id]

    def transition_state(self, session: AdaptiveSession, new_status: SessionStatus, reason: str | None = None) -> None:
        """Enforces valid state machine transitions."""
        current = session.status

        valid_transitions = {
            SessionStatus.CREATED: {SessionStatus.RUNNING, SessionStatus.CANCELLED, SessionStatus.FAILED},
            SessionStatus.RUNNING: {SessionStatus.PAUSED, SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED},
            SessionStatus.PAUSED: {SessionStatus.RUNNING, SessionStatus.CANCELLED, SessionStatus.COMPLETED},
            SessionStatus.COMPLETED: set(),
            SessionStatus.FAILED: set(),
            SessionStatus.CANCELLED: set(),
        }

        if new_status not in valid_transitions.get(current, set()):
            raise AdaptiveSessionError(
                f"Invalid session state transition from '{current}' to '{new_status}'."
            )

        session.status = new_status
        if reason:
            session.stop_reason = reason

        if new_status in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED):
            session.completed_at = datetime.now(timezone.utc).isoformat()


# Global default manager instance
session_manager = AdaptiveSessionManager()
