from app.schemas.evaluation import BaselineRun
from app.schemas.execution import ExecutionResult, ExecutionStatus, RequestEvidence, ResponseEvidence, PolicyDecision
from app.schemas.finding import FindingStatus, SecurityFinding
from app.schemas.generated_test import GeneratedSecurityTest
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from tests.test_execution_safety import create_sample_generated_test


def normalize_baseline_run(
    baseline: BaselineRun,
) -> tuple[list[GeneratedSecurityTest], list[ExecutionResult], list[SecurityFinding]]:
    """Normalizes an external baseline scanner run into standard evaluation artifacts."""

    generated_tests: list[GeneratedSecurityTest] = []
    execution_results: list[ExecutionResult] = []
    findings: list[SecurityFinding] = []

    analyzer = EvidenceAnalyzer()

    for idx, bf in enumerate(baseline.findings, start=1):
        gen_id = f"gen_base_{idx}"
        exec_id = f"exec_base_{idx}"

        # 1. Generated Test representation
        gen_test = create_sample_generated_test(path=bf.endpoint, method=bf.method)
        gen_test.generated_test_id = gen_id
        gen_test.template_id = bf.category or "BASELINE-001"
        gen_test.rationale = f"Baseline finding: {bf.title}"
        generated_tests.append(gen_test)

        # 2. Execution Result representation
        exec_res = ExecutionResult(
            execution_id=exec_id,
            target_id=baseline.target_id,
            generated_test_id=gen_id,
            status=ExecutionStatus.COMPLETED,
            started_at=baseline.started_at or "2026-08-12T00:00:00Z",
            completed_at=baseline.completed_at or "2026-08-12T00:00:01Z",
            duration_ms=100.0,
            request_evidence=RequestEvidence(
                method=bf.method.upper(),
                target_id=baseline.target_id,
                path=bf.endpoint,
            ),
            response_evidence=ResponseEvidence(
                status_code=200,
                headers={},
                body="Baseline report evidence",
                body_size=24,
            ),
            policy_decision=PolicyDecision(allowed=True, reason="Baseline execution"),
        )
        execution_results.append(exec_res)

        # 3. Security Finding representation generated via EvidenceAnalyzer
        finding = analyzer.analyze(gen_test, exec_res)
        finding.status = FindingStatus.CONFIRMED
        finding.title = bf.title
        finding.target_id = baseline.target_id
        findings.append(finding)

    return generated_tests, execution_results, findings
