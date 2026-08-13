from app.schemas.adaptive import AdaptiveSession
from app.schemas.evaluation import EvaluationResult
from app.schemas.reporting import AdaptiveTraceItemView, AdaptiveTraceView


def build_adaptive_trace_view(
    result: EvaluationResult,
    session: AdaptiveSession | None = None,
) -> AdaptiveTraceView:
    """Builds AdaptiveTraceView view model from EvaluationResult and optional AdaptiveSession."""

    session_id = session.session_id if session else "N/A"
    target_id = result.target_id
    status = session.status.value if session else "NOT_APPLICABLE"
    total_iters = session.current_iteration if session else 0
    total_execs = len(session.execution_history) if session else result.execution_efficiency.total_executed
    followups = len(session.followup_history) if session else 0
    stop_reason = session.stop_reason if session else None

    trace_items: list[AdaptiveTraceItemView] = []

    if session and session.iterations:
        for it in session.iterations:
            dec = it.decision
            gen_test = dec.generated_test
            tmpl_id = gen_test.template_id if gen_test else None
            endp = gen_test.endpoint_target if gen_test else (dec.target_finding.endpoint if dec.target_finding else "N/A")
            method = gen_test.http_method if gen_test else (dec.target_finding.http_method if dec.target_finding else "N/A")

            provider = gen_test.generator_metadata.get("provider") if gen_test else None
            model = gen_test.generator_metadata.get("model") if gen_test else None

            item = AdaptiveTraceItemView(
                iteration=it.iteration_number,
                action=dec.action.value,
                target_endpoint=endp,
                http_method=method,
                selected_template_id=tmpl_id,
                information_gain_score=dec.information_gain_score,
                rationale=dec.reasoning,
                finding_status=dec.target_finding.status.value if dec.target_finding else None,
                stop_reason=it.stop_reason,
                llm_provider=provider,
                llm_model=model,
            )
            trace_items.append(item)

    return AdaptiveTraceView(
        session_id=session_id,
        target_id=target_id,
        status=status,
        total_iterations=total_iters,
        total_executions=total_execs,
        followup_tests_count=followups,
        stop_reason=stop_reason,
        trace=trace_items,
        efficiency=result.adaptive_efficiency,
    )
