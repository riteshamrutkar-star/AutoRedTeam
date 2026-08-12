from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import AnalysisCandidate, EvidenceStrength, FindingStatus
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_analysis.rules.base import AnalysisRule


class AuthorizationRule(AnalysisRule):
    """Evaluates evidence for BOLA (AUTHZ-001/002) and BFLA (AUTHZ-003)."""

    @property
    def rule_id(self) -> str:
        return "RULE_AUTHORIZATION"

    def evaluate(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> AnalysisCandidate | None:
        if "AUTHZ" not in test.template_id:
            return None

        if result.status != ExecutionStatus.COMPLETED or not result.response_evidence:
            return None

        resp = result.response_evidence

        # Defensive behavior: 401, 403, 404 -> NEGATIVE
        if resp.status_code in (401, 403, 404):
            return AnalysisCandidate(
                status=FindingStatus.NEGATIVE,
                template_id=test.template_id,
                primary_owasp_id="API1:2023" if test.template_id != "AUTHZ-003" else "API5:2023",
                title="Authorization Controls Active",
                description=f"Endpoint rejected unauthorized resource access with HTTP {resp.status_code}.",
                evidence_strength=EvidenceStrength.STRONG,
                observed_indicators=[f"HTTP_{resp.status_code}_RECEIVED"],
                detection_reason="Endpoint correctly enforced object/function authorization boundary.",
                confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
            )

        # Vulnerable behavior evaluation
        if resp.status_code in (200, 201, 204):
            body_text = resp.body or ""
            indicators = ["HTTP_200_OK_RECEIVED"]

            # BOLA (AUTHZ-001 / AUTHZ-002)
            if test.template_id in ("AUTHZ-001", "AUTHZ-002"):
                # Verify cross-object or cross-tenant data was returned
                if len(body_text) > 10:
                    indicators.append("TARGET_OBJECT_DATA_RETURNED")
                    return AnalysisCandidate(
                        status=FindingStatus.CONFIRMED,
                        template_id=test.template_id,
                        primary_owasp_id="API1:2023",
                        title="Broken Object Level Authorization",
                        description="Endpoint returned target object data when invoked with an unauthorized object identifier.",
                        evidence_strength=EvidenceStrength.STRONG,
                        observed_indicators=indicators,
                        detection_reason="Cross-user object access boundary was successfully breached.",
                        confidence_inputs={"evidence_strength": 1.0, "consistency": 0.9},
                    )

            # BFLA (AUTHZ-003)
            elif test.template_id == "AUTHZ-003":
                indicators.append("ADMIN_FUNCTION_ACCESSED")
                return AnalysisCandidate(
                    status=FindingStatus.CONFIRMED,
                    template_id=test.template_id,
                    primary_owasp_id="API5:2023",
                    title="Broken Function Level Authorization",
                    description="Endpoint permitted unauthorized invocation of a function/privilege level.",
                    evidence_strength=EvidenceStrength.STRONG,
                    observed_indicators=indicators,
                    detection_reason="Function-level authorization check was bypassed.",
                    confidence_inputs={"evidence_strength": 1.0, "consistency": 0.95},
                )

        return None
