import json

from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import AnalysisCandidate, EvidenceStrength, FindingStatus
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_analysis.rules.base import AnalysisRule

SENSITIVE_PROPERTY_NAMES = {
    "role",
    "is_admin",
    "admin",
    "permissions",
    "balance",
    "credit",
    "user_id",
    "owner_id",
    "password",
    "password_hash",
    "secret",
    "ssn",
    "private_key",
    "api_key",
}


class PropertyAccessRule(AnalysisRule):
    """Evaluates evidence for Broken Object Property Level Authorization (BODY-001..003)."""

    @property
    def rule_id(self) -> str:
        return "RULE_PROPERTY_ACCESS"

    def evaluate(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> AnalysisCandidate | None:
        if "BODY" not in test.template_id:
            return None

        if result.status != ExecutionStatus.COMPLETED or not result.response_evidence:
            return None

        resp = result.response_evidence

        # Defensive behavior: 400, 422 -> NEGATIVE
        if resp.status_code in (400, 422):
            return AnalysisCandidate(
                status=FindingStatus.NEGATIVE,
                template_id=test.template_id,
                primary_owasp_id="API3:2023",
                title="Property Level Controls Active",
                description=f"Endpoint rejected unexpected or restricted request property with HTTP {resp.status_code}.",
                evidence_strength=EvidenceStrength.STRONG,
                observed_indicators=[f"HTTP_{resp.status_code}_RECEIVED"],
                detection_reason="Endpoint correctly validated request properties.",
                confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
            )

        # Check for HTTP 200/201 when property mutation occurred
        if resp.status_code in (200, 201) and test.input_mutations:
            mutation = test.input_mutations[0]
            mutated_target = (mutation.target or "").lower()

            # Check if mutated target is a sensitive/privileged property
            is_sensitive_property = any(s in mutated_target for s in SENSITIVE_PROPERTY_NAMES)

            # Check response body for sensitive property exposure/acceptance
            body_text = resp.body or ""

            if is_sensitive_property and mutated_target in body_text.lower():
                return AnalysisCandidate(
                    status=FindingStatus.CONFIRMED,
                    template_id=test.template_id,
                    primary_owasp_id="API3:2023",
                    title="Broken Object Property Level Authorization",
                    description=f"Endpoint accepted or exposed sensitive object property '{mutation.target}'.",
                    evidence_strength=EvidenceStrength.STRONG,
                    observed_indicators=["UNAUTHORIZED_SENSITIVE_PROPERTY_ACCEPTED", f"FIELD_{mutation.target}_PRESENT"],
                    detection_reason="Mass assignment or property-level authorization check failed for sensitive property.",
                    confidence_inputs={"evidence_strength": 0.95, "consistency": 0.95},
                )
            else:
                # Benign/generic unexpected field accepted without sensitive property exposure -> NEGATIVE / INCONCLUSIVE
                return AnalysisCandidate(
                    status=FindingStatus.NEGATIVE,
                    template_id=test.template_id,
                    primary_owasp_id=None,
                    title="Benign Property Accepted (No Property Authorization Breach)",
                    description=f"Endpoint accepted request with field '{mutation.target}', but no unauthorized sensitive property access or modification was demonstrated.",
                    evidence_strength=EvidenceStrength.STRONG,
                    observed_indicators=["BENIGN_PROPERTY_ACCEPTED"],
                    detection_reason="No property-level authorization boundary breach occurred.",
                    confidence_inputs={"evidence_strength": 0.9, "consistency": 1.0},
                )

        return None
