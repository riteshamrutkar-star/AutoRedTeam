import uuid
from typing import Any

from app.core.config import settings
from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import (
    AnalysisCandidate,
    ConfidenceFactors,
    EvidenceStrength,
    FindingEvidence,
    FindingStatus,
    OWASPMapping,
    SecurityFinding,
    SeverityLevel,
)
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_analysis.confidence import ConfidenceEngine
from app.services.security_analysis.owasp_mapper import OWASPMapper
from app.services.security_analysis.rules.authentication import AuthenticationRule
from app.services.security_analysis.rules.authorization import AuthorizationRule
from app.services.security_analysis.rules.base import AnalysisRule
from app.services.security_analysis.rules.input_validation import InputValidationRule
from app.services.security_analysis.rules.property_access import PropertyAccessRule
from app.services.security_analysis.severity import SeverityEngine

REMEDIATIONS: dict[str, str] = {
    "API1:2023": "Enforce object-level authorization checks for every requested resource using user context.",
    "API2:2023": "Apply consistent authentication controls across all endpoints and properly validate access tokens.",
    "API3:2023": "Implement strict property-level access control and schema validation for request/response fields.",
    "API4:2023": "Enforce resource allocation limits, request size caps, and rate limiting.",
    "API5:2023": "Enforce function-level access control checks based on user roles and permissions.",
    "API8:2023": "Harden API configurations, disable verbose error traces, and enforce standard validation.",
}


class EvidenceAnalyzer:
    """Central evidence analyzer coordinating rule evaluation, OWASP mapping, and severity/confidence scoring."""

    def __init__(self) -> None:
        self.rules: list[AnalysisRule] = [
            AuthenticationRule(),
            AuthorizationRule(),
            PropertyAccessRule(),
            InputValidationRule(),
        ]
        self.owasp_mapper = OWASPMapper()
        self.severity_engine = SeverityEngine()
        self.confidence_engine = ConfidenceEngine()
        self.classifier_version = settings.CLASSIFIER_VERSION

    def analyze(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> SecurityFinding:
        """Analyzes an execution result against expected test behavior and produces a SecurityFinding."""
        finding_id = f"fnd_{uuid.uuid4().hex[:12]}"

        # 1. Evaluate Rule Engine Candidates
        candidate: AnalysisCandidate | None = None
        for rule in self.rules:
            cand = rule.evaluate(test, result, spec)
            if cand is not None:
                candidate = cand
                break

        # 2. Default Fallbacks for Non-Completed or Unmatched Executions
        if candidate is None:
            if result.status == ExecutionStatus.BLOCKED:
                candidate = AnalysisCandidate(
                    status=FindingStatus.INCONCLUSIVE,
                    template_id=test.template_id,
                    primary_owasp_id="API8:2023",
                    title="Execution Blocked by Policy",
                    description=f"Test execution was blocked by safety policy: {result.error}",
                    evidence_strength=EvidenceStrength.NONE,
                    observed_indicators=["EXECUTION_BLOCKED_BY_POLICY"],
                    detection_reason=result.error or "Blocked by execution policy.",
                    confidence_inputs={"evidence_strength": 0.0, "ambiguity": 1.0},
                )
            elif result.status == ExecutionStatus.TIMEOUT:
                candidate = AnalysisCandidate(
                    status=FindingStatus.INCONCLUSIVE,
                    template_id=test.template_id,
                    primary_owasp_id="API8:2023",
                    title="Execution Timed Out",
                    description=f"Test execution timed out: {result.error}",
                    evidence_strength=EvidenceStrength.NONE,
                    observed_indicators=["EXECUTION_TIMEOUT"],
                    detection_reason="Request timed out before evidence could be collected.",
                    confidence_inputs={"evidence_strength": 0.0, "ambiguity": 1.0},
                )
            elif result.status == ExecutionStatus.FAILED:
                candidate = AnalysisCandidate(
                    status=FindingStatus.INCONCLUSIVE,
                    template_id=test.template_id,
                    primary_owasp_id="API8:2023",
                    title="Execution Failed",
                    description=f"Test execution failed: {result.error}",
                    evidence_strength=EvidenceStrength.NONE,
                    observed_indicators=["EXECUTION_FAILED"],
                    detection_reason=result.error or "HTTP execution failure.",
                    confidence_inputs={"evidence_strength": 0.0, "ambiguity": 1.0},
                )
            else:
                # Default secure/negative behavior fallback
                candidate = AnalysisCandidate(
                    status=FindingStatus.NEGATIVE,
                    template_id=test.template_id,
                    primary_owasp_id=None,
                    title="No Vulnerability Detected",
                    description="Execution evidence demonstrated expected defensive behavior.",
                    evidence_strength=EvidenceStrength.MODERATE,
                    observed_indicators=["EXPECTED_DEFENSIVE_BEHAVIOR"],
                    detection_reason="Endpoint behavior satisfied security requirements.",
                    confidence_inputs={"evidence_strength": 0.7, "consistency": 1.0},
                )

        # 3. Resolve Candidate Status Against Evidence Thresholds
        final_status = candidate.status
        if final_status == FindingStatus.CONFIRMED and candidate.evidence_strength != EvidenceStrength.STRONG:
            # Demote to SUSPECTED if evidence strength is insufficient
            final_status = FindingStatus.SUSPECTED

        # 4. Map OWASP 2023 Category
        owasp_mapping = self.owasp_mapper.map_category(
            candidate.primary_owasp_id, candidate.detection_reason
        )

        # 5. Calculate Severity Level
        severity_level, severity_rationale = self.severity_engine.calculate_severity(
            final_status, owasp_mapping.category_id
        )

        # 6. Calculate Confidence Score
        c_inputs = candidate.confidence_inputs
        confidence_factors = self.confidence_engine.calculate_confidence(
            evidence_strength=candidate.evidence_strength,
            behavior_consistency=c_inputs.get("consistency", 1.0),
            test_specificity=1.0,
            expected_behavior_match=1.0 if final_status == FindingStatus.NEGATIVE else 0.8,
            ambiguity_penalty=c_inputs.get("ambiguity", 0.0),
        )

        # 7. Package Finding Evidence
        resp = result.response_evidence
        req = result.request_evidence

        finding_evidence = FindingEvidence(
            execution_id=result.execution_id,
            status_code=resp.status_code if resp else None,
            request_summary=req.model_dump(mode="json") if req else {},
            response_summary={
                "status_code": resp.status_code if resp else None,
                "body_size": resp.body_size if resp else 0,
                "final_url_host": resp.final_url_host if resp else None,
                "truncated": resp.truncated if resp else False,
            },
            expected_status_codes=test.expected_behavior.expected_status_codes,
            observed_indicators=candidate.observed_indicators,
        )

        # 8. Remediation Guidance
        remediation = REMEDIATIONS.get(
            owasp_mapping.category_id,
            "Apply proper validation and security controls to the endpoint.",
        )

        return SecurityFinding(
            finding_id=finding_id,
            execution_id=result.execution_id,
            generated_test_id=test.generated_test_id,
            template_id=test.template_id,
            target_id=result.target_id,
            endpoint=test.endpoint_target,
            http_method=test.http_method,
            status=final_status,
            title=candidate.title,
            description=candidate.description,
            category=owasp_mapping.category_name,
            owasp=owasp_mapping,
            severity=severity_level,
            severity_rationale=severity_rationale,
            confidence=confidence_factors.overall_score,
            confidence_factors=confidence_factors,
            evidence=finding_evidence,
            detection_reason=candidate.detection_reason,
            remediation_guidance=remediation,
            classifier_version=self.classifier_version,
        )
