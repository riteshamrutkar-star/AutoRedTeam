from typing import Any

from app.schemas.evaluation import (
    ComparisonMetricItem,
    EvaluationResult,
    MetricStatus,
    MetricValue,
    RunComparison,
)


class IncompatibleComparisonError(ValueError):
    """Exception raised when comparing evaluation runs with incompatible targets or scopes."""

    pass


def extract_scalar(val: MetricValue | float | int | None) -> tuple[float | int | None, MetricStatus, str | None]:
    """Helper extracting scalar value and metric status."""
    if isinstance(val, MetricValue):
        return val.value, val.status, val.reason
    if val is None:
        return None, MetricStatus.UNDEFINED, None
    return val, MetricStatus.COMPUTED, None


def compare_metrics(name: str, a_val_raw: Any, b_val_raw: Any) -> ComparisonMetricItem:
    """Compares two metric values, calculating absolute and relative differences safely."""
    val_a, status_a, reason_a = extract_scalar(a_val_raw)
    val_b, status_b, reason_b = extract_scalar(b_val_raw)

    if status_a == MetricStatus.NOT_APPLICABLE or status_b == MetricStatus.NOT_APPLICABLE:
        return ComparisonMetricItem(
            metric_name=name,
            run_a_value=val_a,
            run_b_value=val_b,
            absolute_difference=None,
            relative_difference=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason=reason_a or reason_b or "Metric is not applicable for one or both runs.",
        )

    if val_a is None or val_b is None:
        return ComparisonMetricItem(
            metric_name=name,
            run_a_value=val_a,
            run_b_value=val_b,
            absolute_difference=None,
            relative_difference=None,
            status=MetricStatus.UNDEFINED,
            reason="One or both metric values are undefined.",
        )

    abs_diff = round(val_b - val_a, 4)
    rel_diff = round(((val_b - val_a) / val_a) * 100.0, 2) if val_a != 0 else None

    return ComparisonMetricItem(
        metric_name=name,
        run_a_value=val_a,
        run_b_value=val_b,
        absolute_difference=abs_diff,
        relative_difference=rel_diff,
        status=MetricStatus.COMPUTED,
    )


def compare_evaluation_results(res_a: EvaluationResult, res_b: EvaluationResult) -> RunComparison:
    """Generates side-by-side metric comparisons between two evaluation results."""

    if res_a.target_id != res_b.target_id:
        raise IncompatibleComparisonError(
            f"Incompatible experiment comparison: target_id '{res_a.target_id}' != '{res_b.target_id}'."
        )

    metrics_list: list[ComparisonMetricItem] = [
        # Coverage metrics
        compare_metrics("endpoint_coverage_pct", res_a.coverage.endpoint_coverage.percentage, res_b.coverage.endpoint_coverage.percentage),
        compare_metrics("method_coverage_pct", res_a.coverage.method_coverage.percentage, res_b.coverage.method_coverage.percentage),
        compare_metrics("parameter_coverage_pct", res_a.coverage.parameter_coverage.percentage, res_b.coverage.parameter_coverage.percentage),
        compare_metrics("template_coverage_pct", res_a.coverage.template_coverage.percentage, res_b.coverage.template_coverage.percentage),
        compare_metrics("category_coverage_pct", res_a.coverage.category_coverage.percentage, res_b.coverage.category_coverage.percentage),

        # Discovery metrics
        compare_metrics("unique_vulnerabilities_discovered", res_a.discovery.unique_vulnerabilities_discovered, res_b.discovery.unique_vulnerabilities_discovered),
        compare_metrics("true_positives", res_a.discovery.true_positives, res_b.discovery.true_positives),
        compare_metrics("false_positives", res_a.discovery.false_positives, res_b.discovery.false_positives),
        compare_metrics("false_negatives", res_a.discovery.false_negatives, res_b.discovery.false_negatives),
        compare_metrics("precision", res_a.discovery.precision, res_b.discovery.precision),
        compare_metrics("recall", res_a.discovery.recall, res_b.discovery.recall),

        # Timing metrics
        compare_metrics("time_to_first_vulnerability_ms", res_a.timing.time_to_first_vulnerability_ms, res_b.timing.time_to_first_vulnerability_ms),
        compare_metrics("time_to_first_known_vulnerability_ms", res_a.timing.time_to_first_known_vulnerability_ms, res_b.timing.time_to_first_known_vulnerability_ms),

        # Efficiency metrics
        compare_metrics("total_executions", res_a.execution_efficiency.total_executed, res_b.execution_efficiency.total_executed),
        compare_metrics("requests_per_known_vulnerability", res_a.execution_efficiency.requests_per_known_vulnerability, res_b.execution_efficiency.requests_per_known_vulnerability),
        compare_metrics("followup_rate", res_a.adaptive_efficiency.followup_rate, res_b.adaptive_efficiency.followup_rate),
    ]

    return RunComparison(
        run_a_name=f"{res_a.run_name} ({res_a.strategy.value})",
        run_b_name=f"{res_b.run_name} ({res_b.strategy.value})",
        metrics_comparison=metrics_list,
    )
