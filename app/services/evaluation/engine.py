from datetime import datetime, timezone
import uuid

from app.core.config import settings
from app.schemas.evaluation import EvaluationInput, EvaluationResult, EvaluationStrategy
from app.services.evaluation.baseline import normalize_baseline_run
from app.services.evaluation.coverage import compute_coverage
from app.services.evaluation.discovery import compute_discovery_metrics
from app.services.evaluation.efficiency import compute_efficiency_metrics
from app.services.evaluation.ground_truth import match_findings_to_ground_truth
from app.services.evaluation.timing import compute_timing_metrics


class EvaluationEngine:
    """Deterministic evaluation engine computing effectiveness, efficiency, coverage, and discovery metrics."""

    def evaluate(self, input_data: EvaluationInput) -> EvaluationResult:
        """Evaluates recorded testing artifacts and computes machine-readable metrics."""

        evaluation_id = f"eval_{uuid.uuid4().hex[:12]}"

        gen_tests = input_data.generated_tests
        exec_results = input_data.execution_results
        findings = input_data.findings

        # If evaluating a baseline run, normalize baseline finding objects
        if input_data.strategy == EvaluationStrategy.BASELINE and input_data.baseline_run:
            base_gen, base_exec, base_find = normalize_baseline_run(input_data.baseline_run)
            gen_tests = gen_tests or base_gen
            exec_results = exec_results or base_exec
            findings = findings or base_find

        # Determine timestamps
        started_at = "2026-08-12T00:00:00Z"
        completed_at = "2026-08-12T00:00:01Z"

        if exec_results:
            starts = [r.started_at for r in exec_results if r.started_at]
            completes = [r.completed_at for r in exec_results if r.completed_at]
            if starts:
                started_at = min(starts)
            if completes:
                completed_at = max(completes)

        # 1. Coverage Metrics
        coverage = compute_coverage(
            spec=input_data.normalized_spec,
            generated_tests=gen_tests,
            execution_results=exec_results,
        )

        # 2. Ground-Truth Matching
        matches = match_findings_to_ground_truth(
            target_id=input_data.target_id,
            findings=findings,
            ground_truth=input_data.ground_truth,
        )

        # 3. Discovery & False Positive Metrics
        discovery, false_positives = compute_discovery_metrics(
            findings=findings,
            matches=matches,
            ground_truth=input_data.ground_truth,
        )

        # 4. Timing Metrics
        timing = compute_timing_metrics(
            execution_results=exec_results,
            findings=findings,
            matches=matches,
            started_at_iso=started_at,
            completed_at_iso=completed_at,
        )

        # 5. Efficiency Metrics
        adaptive_eff, exec_eff = compute_efficiency_metrics(
            strategy=input_data.strategy,
            generated_tests=gen_tests,
            execution_results=exec_results,
            findings=findings,
            unique_vulnerabilities_discovered=discovery.unique_vulnerabilities_discovered,
            adaptive_session=input_data.adaptive_session,
        )

        return EvaluationResult(
            evaluation_id=evaluation_id,
            evaluation_version=settings.EVALUATION_VERSION,
            run_name=input_data.run_name,
            strategy=input_data.strategy,
            target_id=input_data.target_id,
            started_at=started_at,
            completed_at=completed_at,
            coverage=coverage,
            discovery=discovery,
            false_positives=false_positives,
            timing=timing,
            adaptive_efficiency=adaptive_eff,
            execution_efficiency=exec_eff,
            matches=matches,
        )
