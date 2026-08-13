from app.schemas.evaluation import EvaluationResult
from app.schemas.reporting import ComparisonView
from app.services.evaluation.comparison import compare_evaluation_results


def build_comparison_view(res_a: EvaluationResult, res_b: EvaluationResult) -> ComparisonView:
    """Builds ComparisonView view model after validating target compatibility."""

    run_comp = compare_evaluation_results(res_a, res_b)

    return ComparisonView(
        run_a_name=run_comp.run_a_name,
        run_b_name=run_comp.run_b_name,
        target_id=res_a.target_id,
        metrics=run_comp.metrics_comparison,
    )
