from app.schemas.adaptive import AdaptiveAction, AdaptiveSession
from app.schemas.evaluation import (
    AdaptiveEfficiencyMetrics,
    EvaluationStrategy,
    ExecutionEfficiencyMetrics,
    MetricStatus,
    MetricValue,
)
from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import FindingStatus, SecurityFinding
from app.schemas.generated_test import GeneratedSecurityTest


def compute_efficiency_metrics(
    strategy: EvaluationStrategy,
    generated_tests: list[GeneratedSecurityTest],
    execution_results: list[ExecutionResult],
    findings: list[SecurityFinding],
    unique_vulnerabilities_discovered: int,
    adaptive_session: AdaptiveSession | None = None,
) -> tuple[AdaptiveEfficiencyMetrics, ExecutionEfficiencyMetrics]:
    """Computes execution breakdown and adaptive efficiency metrics safely."""

    total_gen = len(generated_tests)
    total_exec = len(execution_results)

    success_cnt = sum(1 for r in execution_results if r.status == ExecutionStatus.COMPLETED)
    blocked_cnt = sum(1 for r in execution_results if r.status == ExecutionStatus.BLOCKED)
    failed_cnt = sum(1 for r in execution_results if r.status == ExecutionStatus.FAILED)
    timeout_cnt = sum(1 for r in execution_results if r.status == ExecutionStatus.TIMEOUT)

    # Average duration
    durations = [r.duration_ms for r in execution_results if r.duration_ms is not None]
    avg_dur = sum(durations) / len(durations) if durations else None

    avg_dur_val = MetricValue(
        value=round(avg_dur, 2) if avg_dur is not None else None,
        status=MetricStatus.COMPUTED if avg_dur is not None else MetricStatus.UNDEFINED,
    )

    confirmed_cnt = sum(1 for f in findings if f.status == FindingStatus.CONFIRMED)

    # Requests per finding
    if confirmed_cnt > 0:
        req_per_finding = round(total_exec / confirmed_cnt, 2)
        req_finding_val = MetricValue(value=req_per_finding, status=MetricStatus.COMPUTED)
    else:
        req_finding_val = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="Zero CONFIRMED findings reported in run.",
        )

    # Requests per known vulnerability
    if unique_vulnerabilities_discovered > 0:
        req_per_known = round(total_exec / unique_vulnerabilities_discovered, 2)
        req_known_val = MetricValue(value=req_per_known, status=MetricStatus.COMPUTED)
    else:
        req_known_val = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="Zero known vulnerabilities discovered in run.",
        )

    exec_metrics = ExecutionEfficiencyMetrics(
        total_generated=total_gen,
        total_executed=total_exec,
        successful_count=success_cnt,
        blocked_count=blocked_cnt,
        failed_count=failed_cnt,
        timed_out_count=timeout_cnt,
        avg_duration_ms=avg_dur_val,
        requests_per_finding=req_finding_val,
        requests_per_known_vulnerability=req_known_val,
    )

    # Adaptive Efficiency Metrics
    if strategy == EvaluationStrategy.BASELINE or not adaptive_session:
        na_reason = "Adaptive metrics are not applicable for baseline or static strategies."
        adaptive_metrics = AdaptiveEfficiencyMetrics(
            followup_tests_count=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
            followup_rate=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
            confirmation_efficiency=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
            tests_per_vulnerability=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
            redundant_attempts_count=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
            redundant_test_rate=MetricValue(value=None, status=MetricStatus.NOT_APPLICABLE, reason=na_reason),
        )
        return adaptive_metrics, exec_metrics

    # Compute adaptive metrics from session trace
    iterations = adaptive_session.iterations
    total_iters = len(iterations)

    followups = [
        it for it in iterations
        if it.decision.action in (AdaptiveAction.CONFIRM, AdaptiveAction.REFINE) or it.parent_finding_id is not None
    ]
    followup_cnt = len(followups)

    redundant_cnt = sum(1 for it in iterations if "duplicate" in (it.rationale or "").lower())

    followup_rate_val = round(followup_cnt / total_iters, 4) if total_iters > 0 else None
    conf_eff_val = round(confirmed_cnt / followup_cnt, 4) if followup_cnt > 0 else None
    tests_per_vuln_val = round(total_exec / confirmed_cnt, 2) if confirmed_cnt > 0 else None
    redundant_rate_val = round(redundant_cnt / (total_exec + redundant_cnt), 4) if (total_exec + redundant_cnt) > 0 else None

    adaptive_metrics = AdaptiveEfficiencyMetrics(
        followup_tests_count=MetricValue(value=followup_cnt, status=MetricStatus.COMPUTED),
        followup_rate=MetricValue(
            value=followup_rate_val,
            status=MetricStatus.COMPUTED if followup_rate_val is not None else MetricStatus.UNDEFINED,
        ),
        confirmation_efficiency=MetricValue(
            value=conf_eff_val,
            status=MetricStatus.COMPUTED if conf_eff_val is not None else MetricStatus.NOT_APPLICABLE,
            reason=None if conf_eff_val is not None else "Zero follow-up tests executed.",
        ),
        tests_per_vulnerability=MetricValue(
            value=tests_per_vuln_val,
            status=MetricStatus.COMPUTED if tests_per_vuln_val is not None else MetricStatus.NOT_APPLICABLE,
            reason=None if tests_per_vuln_val is not None else "Zero confirmed findings.",
        ),
        redundant_attempts_count=MetricValue(value=redundant_cnt, status=MetricStatus.COMPUTED),
        redundant_test_rate=MetricValue(
            value=redundant_rate_val,
            status=MetricStatus.COMPUTED if redundant_rate_val is not None else MetricStatus.UNDEFINED,
        ),
    )

    return adaptive_metrics, exec_metrics
