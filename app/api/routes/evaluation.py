from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.config import settings
from app.schemas.evaluation import EvaluationInput, EvaluationResult, RunComparison
from app.services.evaluation.comparison import IncompatibleComparisonError, compare_evaluation_results
from app.services.evaluation.engine import EvaluationEngine

router = APIRouter(tags=["Coverage & Evaluation Engine"])


class CompareRunsRequest(BaseModel):
    """Payload to compare two evaluation run results."""

    run_a: EvaluationResult
    run_b: EvaluationResult


@router.post(
    "/evaluation/compute",
    response_model=EvaluationResult,
    status_code=status.HTTP_200_OK,
    summary="Compute evaluation metrics for recorded testing artifacts",
    description="Deterministically calculate endpoint/method/param coverage, vulnerability discovery rate, TP/FP/FN, timing, and efficiency metrics.",
)
def compute_evaluation(input_data: EvaluationInput) -> EvaluationResult:
    """Compute evaluation metrics for recorded test artifacts."""
    engine = EvaluationEngine()
    return engine.evaluate(input_data)


@router.post(
    "/evaluation/compare",
    response_model=RunComparison,
    status_code=status.HTTP_200_OK,
    summary="Compare two evaluation runs side-by-side",
    description="Generate side-by-side absolute and relative metric comparisons between two evaluation results (e.g. Static vs Adaptive or AutoRedTeam vs Baseline).",
)
def compare_evaluations(request: CompareRunsRequest) -> RunComparison:
    """Compare two evaluation run results."""
    try:
        return compare_evaluation_results(request.run_a, request.run_b)
    except IncompatibleComparisonError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/evaluation/metrics",
    summary="Get supported evaluation metrics definition and version metadata",
    description="Retrieve version metadata, metric formulas, and supported strategy taxonomy.",
)
def get_evaluation_metrics_info() -> dict[str, str | list[str]]:
    """Get evaluation metrics metadata."""
    return {
        "evaluation_version": settings.EVALUATION_VERSION,
        "metric_definition_version": settings.METRIC_DEFINITION_VERSION,
        "supported_strategies": ["STATIC", "ADAPTIVE", "BASELINE", "CATALOGUE_ONLY"],
        "ground_truth_matching_rules": "Target ID, path, method, and category/alias matching.",
        "coverage_taxonomy": "Phase 3 SecurityTestCategory taxonomy.",
    }
