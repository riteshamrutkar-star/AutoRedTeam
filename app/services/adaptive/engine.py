from datetime import datetime, timezone
import time
import httpx

from app.schemas.adaptive import (
    AdaptiveAction,
    AdaptiveDecision,
    AdaptiveIteration,
    AdaptiveSession,
    SessionStatus,
)
from app.schemas.generated_test import GenerateSecurityTestsRequest
from app.schemas.execution import ExecutionRequest
from app.services.adaptive.decision_engine import AdaptiveDecisionEngine
from app.services.adaptive.deduplication import compute_generated_test_signature
from app.services.adaptive.session_manager import (
    AdaptiveSessionError,
    AdaptiveSessionManager,
    session_manager,
)
from app.services.execution.executor import ExecutionEngine
from app.services.llm.generator import SecurityTestGenerator
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from app.services.security_tests.applicability import ApplicabilityEngine


class AdaptiveTestingEngine:
    """Orchestration service driving the adaptive red-team loop across Phases 3, 4, 5, and 6."""

    def __init__(
        self,
        manager: AdaptiveSessionManager | None = None,
        decision_engine: AdaptiveDecisionEngine | None = None,
        applicability_engine: ApplicabilityEngine | None = None,
        generator: SecurityTestGenerator | None = None,
        executor: ExecutionEngine | None = None,
        analyzer: EvidenceAnalyzer | None = None,
    ) -> None:
        self.manager = manager or session_manager
        self.decision_engine = decision_engine or AdaptiveDecisionEngine()
        self.applicability_engine = applicability_engine or ApplicabilityEngine()
        self.generator = generator or SecurityTestGenerator()
        self.executor = executor or ExecutionEngine()
        self.analyzer = analyzer or EvidenceAnalyzer()

    async def step_session(
        self,
        session_id: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> AdaptiveSession:
        """Executes exactly one adaptive iteration under per-session concurrency lock."""
        lock = await self.manager.get_session_lock(session_id)

        async with lock:
            session = self.manager.get_session(session_id)
            if not session:
                raise AdaptiveSessionError(f"Adaptive session '{session_id}' not found.")

            if session.status in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED):
                raise AdaptiveSessionError(f"Session '{session_id}' is already in terminal state '{session.status}'.")

            if session.status in (SessionStatus.CREATED, SessionStatus.PAUSED):
                self.manager.transition_state(session, SessionStatus.RUNNING)

            # Measure wall-clock elapsed runtime
            started_dt = datetime.fromisoformat(session.started_at)
            elapsed_seconds = (datetime.now(timezone.utc) - started_dt).total_seconds()

            # 1. Evaluate Adaptive Decision
            decision = self.decision_engine.evaluate_next_step(session, elapsed_seconds)

            if decision.action == AdaptiveAction.STOP:
                self.manager.transition_state(session, SessionStatus.COMPLETED, reason=decision.stop_reason)
                return session

            session.current_iteration += 1

            # 2. Select Candidate Template & Evaluate Applicability (Phase 3)
            template_id = decision.candidate_template_ids[0] if decision.candidate_template_ids else "AUTH-001"
            applicable_results = self.applicability_engine.evaluate_spec(session.spec)

            matching_cands = [r for r in applicable_results if r.template_id == template_id]
            if not matching_cands:
                # Fallback to first available applicable candidate if specific template not applicable
                matching_cands = applicable_results[:1]

            if not matching_cands:
                self.manager.transition_state(session, SessionStatus.COMPLETED, reason="NO_APPLICABLE_CANDIDATES")
                return session

            target_cand = matching_cands[0]

            # 3. Generate Security Test Plan (Phase 4)
            gen_req = GenerateSecurityTestsRequest(spec=session.spec, applicable_tests=[target_cand])
            gen_resp = await self.generator.generate_tests(gen_req)

            if not gen_resp.generated_tests:
                # Generation failed or rejected by post-LLM validator
                trace_item = AdaptiveIteration(
                    iteration_number=session.current_iteration,
                    parent_execution_id=None,
                    parent_finding_id=decision.parent_finding_id,
                    decision=decision,
                    selected_template_id=template_id,
                    rationale=f"Test generation failed for candidate template {template_id}.",
                )
                session.iterations.append(trace_item)
                return session

            gen_test = gen_resp.generated_tests[0]

            # 4. Deduplication Check
            sig = compute_generated_test_signature(session.target_id, gen_test)
            if sig in session.executed_signatures:
                trace_item = AdaptiveIteration(
                    iteration_number=session.current_iteration,
                    parent_execution_id=None,
                    parent_finding_id=decision.parent_finding_id,
                    decision=decision,
                    selected_template_id=template_id,
                    generated_test_id=gen_test.generated_test_id,
                    rationale=f"Skipped execution of duplicate test signature for template {template_id}.",
                )
                session.iterations.append(trace_item)
                return session

            # 5. Controlled Target Execution (Phase 5)
            exec_req = ExecutionRequest(target_id=session.target_id, generated_test=gen_test)
            exec_result = await self.executor.execute_test(exec_req, transport=transport)

            # Record signature
            session.executed_signatures.append(sig)

            # 6. Evidence Analysis & OWASP Classification (Phase 6)
            finding = self.analyzer.analyze(gen_test, exec_result, spec=session.spec)
            session.findings.append(finding)

            # 7. Record Iteration Trace
            trace_item = AdaptiveIteration(
                iteration_number=session.current_iteration,
                parent_execution_id=exec_result.execution_id,
                parent_finding_id=decision.parent_finding_id,
                decision=decision,
                selected_template_id=template_id,
                generated_test_id=gen_test.generated_test_id,
                execution_id=exec_result.execution_id,
                finding_status=finding.status,
                rationale=f"Executed iteration {session.current_iteration}: {gen_test.template_id} -> {exec_result.status.value} -> {finding.status.value}",
            )
            session.iterations.append(trace_item)

            return session

    async def run_session(
        self,
        session_id: str,
        max_steps_this_call: int = 5,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> AdaptiveSession:
        """Runs up to max_steps_this_call iterations in a loop while session remains RUNNING."""
        steps_executed = 0
        while steps_executed < max_steps_this_call:
            session = self.manager.get_session(session_id)
            if not session or session.status in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED):
                break

            await self.step_session(session_id, transport=transport)
            steps_executed += 1

        return self.manager.get_session(session_id) or session
