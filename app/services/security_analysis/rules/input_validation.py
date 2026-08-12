from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import AnalysisCandidate, EvidenceStrength, FindingStatus
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_analysis.rules.base import AnalysisRule


class InputValidationRule(AnalysisRule):
    """Evaluates evidence for input validation test templates (INP-001..004)."""

    @property
    def rule_id(self) -> str:
        return "RULE_INPUT_VALIDATION"

    def evaluate(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> AnalysisCandidate | None:
        if "INP" not in test.template_id:
            return None

        if result.status != ExecutionStatus.COMPLETED or not result.response_evidence:
            return None

        resp = result.response_evidence

        # Defensive validation: 400, 422 -> NEGATIVE
        if resp.status_code in (400, 422):
            return AnalysisCandidate(
                status=FindingStatus.NEGATIVE,
                template_id=test.template_id,
                primary_owasp_id=None,  # No positive OWASP vulnerability
                title="Input Validation Controls Active",
                description=f"Endpoint rejected invalid input with defensive HTTP {resp.status_code}.",
                evidence_strength=EvidenceStrength.STRONG,
                observed_indicators=[f"HTTP_{resp.status_code}_VALIDATION_REJECTION"],
                detection_reason="Endpoint correctly validated input schema constraints.",
                confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
            )

        # HTTP 500 without security-specific evidence -> INCONCLUSIVE
        if resp.status_code == 500:
            return AnalysisCandidate(
                status=FindingStatus.INCONCLUSIVE,
                template_id=test.template_id,
                primary_owasp_id=None,  # No positive OWASP vulnerability
                title="Unhandled Server Error (Inconclusive)",
                description="Endpoint returned HTTP 500 server error, but no specific security vulnerability evidence (e.g. stack trace leak or state corruption) was extracted.",
                evidence_strength=EvidenceStrength.WEAK,
                observed_indicators=["HTTP_500_INTERNAL_SERVER_ERROR"],
                detection_reason="Unhandled server error requires further manual investigation.",
                confidence_inputs={"evidence_strength": 0.3, "ambiguity": 0.5},
            )

        return None
