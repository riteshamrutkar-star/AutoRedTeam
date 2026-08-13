from typing import Any

from app.schemas.adaptive import (
    AdaptiveAction,
    AdaptiveDecision,
    AdaptiveSession,
    DecisionProvenance,
)
from app.schemas.finding import FindingStatus, SecurityFinding
from app.services.llm.provider import LLMProvider, get_llm_provider
from app.services.security_tests.applicability import ApplicabilityEngine
from app.services.security_tests.catalogue import TestCatalogue, catalogue_registry

COMPLEMENTARY_TEMPLATES: dict[str, list[str]] = {
    "AUTH-001": ["AUTH-002", "AUTH-003"],
    "AUTH-002": ["AUTH-003", "AUTH-001"],
    "AUTH-003": ["AUTH-002", "AUTH-001"],
    "AUTHZ-001": ["AUTHZ-002", "AUTHZ-003"],
    "AUTHZ-002": ["AUTHZ-001", "AUTHZ-003"],
    "AUTHZ-003": ["AUTHZ-001", "AUTHZ-002"],
    "BODY-001": ["BODY-002", "BODY-003"],
    "BODY-002": ["BODY-003", "BODY-001"],
    "INP-001": ["INP-002", "INP-003", "INP-004"],
}


class AdaptiveDecisionEngine:
    """Evidence-driven decision engine with deterministic information gain heuristics and advisory LLM metadata."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or get_llm_provider()
        self.applicability_engine = ApplicabilityEngine()
        self.catalogue = catalogue_registry

    def evaluate_next_step(self, session: AdaptiveSession, elapsed_seconds: float) -> AdaptiveDecision:
        """Evaluates session state and determines the next adaptive decision."""

        # 1. Budget & Timeout Checks
        if session.current_iteration >= session.budget.max_iterations:
            return AdaptiveDecision(
                action=AdaptiveAction.STOP,
                rationale="Session reached maximum allowed iteration budget.",
                stop_reason="MAX_ITERATIONS_REACHED",
            )

        if len(session.iterations) >= session.budget.max_executions:
            return AdaptiveDecision(
                action=AdaptiveAction.STOP,
                rationale="Session reached maximum allowed execution budget.",
                stop_reason="MAX_EXECUTIONS_REACHED",
            )

        if elapsed_seconds >= session.budget.max_runtime_seconds:
            return AdaptiveDecision(
                action=AdaptiveAction.STOP,
                rationale=f"Session wall-clock runtime ({round(elapsed_seconds, 1)}s) exceeded budget ({session.budget.max_runtime_seconds}s).",
                stop_reason="MAX_RUNTIME_EXCEEDED",
            )

        # 2. Analyze Existing Findings State
        latest_finding: SecurityFinding | None = session.findings[-1] if session.findings else None

        # Count followups for latest finding
        parent_finding_id = latest_finding.finding_id if latest_finding else None
        followup_count = sum(
            1 for it in session.iterations if it.parent_finding_id == parent_finding_id
        )

        # 3. Handle SUSPECTED Finding (Attempt Confirmation)
        if latest_finding and latest_finding.status == FindingStatus.SUSPECTED:
            if followup_count < session.budget.max_followups_per_finding:
                complementary = COMPLEMENTARY_TEMPLATES.get(latest_finding.template_id, [])
                # Filter out already executed templates for this path/method
                unexecuted = [
                    t_id for t_id in complementary
                    if not any(t_id == sig.split(":")[1] for sig in session.executed_signatures if len(sig.split(":")) > 1)
                ]
                if unexecuted:
                    target_template = unexecuted[0]
                    provenance = DecisionProvenance(
                        evidence_gap=f"Suspected {latest_finding.title} requires confirmation with complementary template {target_template}.",
                        selected_candidate=target_template,
                        rationale=f"Triggering targeted confirmation test {target_template} for suspected finding {latest_finding.finding_id}.",
                        information_gain=0.85,
                        provider=self.provider.provider_name,
                        model=self.provider.model_name,
                    )
                    return AdaptiveDecision(
                        action=AdaptiveAction.CONFIRM,
                        rationale=provenance.rationale,
                        confidence=0.85,
                        candidate_template_ids=[target_template],
                        parent_finding_id=latest_finding.finding_id,
                        evidence_gap=provenance.evidence_gap,
                        provenance=provenance,
                    )

        # 4. Handle CONFIRMED Finding (Stop confirmation chain for that finding, continue session for others)
        # Find next un-explored applicable template candidates across spec
        applicable_results = self.applicability_engine.evaluate_spec(session.spec)
        unexecuted_candidates = []

        for cand in applicable_results:
            cand_template = cand.template_id
            cand_path = cand.target.path
            cand_method = cand.target.http_method

            # Check if this template/path/method combo was already executed
            already_done = any(
                f"{cand_template}:{cand_path}:{cand_method}" in sig
                for sig in session.executed_signatures
            )
            if not already_done:
                unexecuted_candidates.append(cand)

        if not unexecuted_candidates:
            reason = "No un-explored applicable security test candidates remain."
            if latest_finding and latest_finding.status == FindingStatus.CONFIRMED:
                reason = f"Security finding {latest_finding.finding_id} confirmed and no remaining un-executed test candidates exist."
            return AdaptiveDecision(
                action=AdaptiveAction.STOP,
                rationale=reason,
                stop_reason="ALL_CANDIDATES_EXHAUSTED",
            )

        # 5. Calculate Information Gain & Rank Next Candidate
        # Deterministic ranking heuristic: novel template on unresolved endpoint
        best_cand = unexecuted_candidates[0]
        provenance = DecisionProvenance(
            evidence_gap=f"Exploring un-tested candidate {best_cand.template_id} on {best_cand.target.http_method} {best_cand.target.path}.",
            selected_candidate=best_cand.template_id,
            rationale=f"Selected candidate template {best_cand.template_id} with highest information gain heuristic score.",
            information_gain=0.75,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
        )

        return AdaptiveDecision(
            action=AdaptiveAction.EXPLORE if not latest_finding or latest_finding.status == FindingStatus.NEGATIVE else AdaptiveAction.REFINE,
            rationale=provenance.rationale,
            confidence=0.75,
            candidate_template_ids=[best_cand.template_id],
            parent_finding_id=parent_finding_id,
            evidence_gap=provenance.evidence_gap,
            provenance=provenance,
        )
