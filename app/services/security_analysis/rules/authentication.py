from app.schemas.execution import ExecutionResult, ExecutionStatus
from app.schemas.finding import AnalysisCandidate, EvidenceStrength, FindingStatus
from app.schemas.generated_test import GeneratedSecurityTest
from app.schemas.spec import NormalizedApiSpec
from app.services.security_analysis.rules.base import AnalysisRule


class AuthenticationRule(AnalysisRule):
    """Evaluates evidence for missing or broken authentication (AUTH-001..003)."""

    @property
    def rule_id(self) -> str:
        return "RULE_AUTHENTICATION"

    def evaluate(
        self,
        test: GeneratedSecurityTest,
        result: ExecutionResult,
        spec: NormalizedApiSpec | None = None,
    ) -> AnalysisCandidate | None:
        if "AUTH" not in test.template_id or "AUTHZ" in test.template_id:
            return None

        if result.status != ExecutionStatus.COMPLETED or not result.response_evidence:
            return None

        resp = result.response_evidence
        req = result.request_evidence

        # Check if endpoint explicitly declares security requirement
        endpoint_is_protected = True
        if spec:
            matching = [
                ep for ep in spec.endpoints
                if ep.path == test.endpoint_target and ep.method.upper() == test.http_method.upper()
            ]
            if matching:
                endpoint = matching[0]
                # If operation security is explicitly [] or (no operation security AND no global security)
                if endpoint.security == [] or (endpoint.security is None and not spec.security_schemes):
                    endpoint_is_protected = False

        # Also check expected behavior status codes
        expects_401 = 401 in test.expected_behavior.expected_status_codes or 403 in test.expected_behavior.expected_status_codes

        auth_header = (req.headers if req else {}).get("Authorization")
        is_unauth_context = (req.auth_state in ("unauthenticated", "invalid_token", "malformed_token")) or not auth_header

        # Defensive behavior: 401, 403, 405 -> NEGATIVE
        if resp.status_code in (401, 403, 405, 422):
            return AnalysisCandidate(
                status=FindingStatus.NEGATIVE,
                template_id=test.template_id,
                primary_owasp_id="API2:2023",
                title="Authentication Controls Active",
                description=f"Endpoint rejected unauthenticated/invalid request with HTTP {resp.status_code}.",
                evidence_strength=EvidenceStrength.STRONG,
                observed_indicators=[f"HTTP_{resp.status_code}_RECEIVED"],
                detection_reason="Endpoint correctly enforced authentication boundary.",
                confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
            )

        # Un-protected / public endpoint returning 200 OK -> NEGATIVE (not a vulnerability)
        if not endpoint_is_protected or not expects_401:
            if resp.status_code in (200, 201, 204):
                return AnalysisCandidate(
                    status=FindingStatus.NEGATIVE,
                    template_id=test.template_id,
                    primary_owasp_id=None,
                    title="Public Endpoint (No Auth Required)",
                    description="Endpoint does not declare authentication requirements; HTTP 200 OK is expected behavior.",
                    evidence_strength=EvidenceStrength.STRONG,
                    observed_indicators=["PUBLIC_ENDPOINT_ACCESS"],
                    detection_reason="Endpoint is public or unauthenticated by design.",
                    confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
                )

        # Vulnerable behavior: Declared protected endpoint returning 200 OK for unauthenticated context
        if resp.status_code in (200, 201, 204) and endpoint_is_protected and is_unauth_context and expects_401:
            return AnalysisCandidate(
                status=FindingStatus.CONFIRMED,
                template_id=test.template_id,
                primary_owasp_id="API2:2023",
                title="Broken Authentication",
                description="Protected endpoint returned successful HTTP 200 response for an unauthenticated/invalid request.",
                evidence_strength=EvidenceStrength.STRONG,
                observed_indicators=["HTTP_200_UNAUTHENTICATED_ACCESS", "AUTHENTICATION_BOUNDARY_BYPASS"],
                detection_reason="Protected endpoint failed to enforce declared authentication requirement.",
                confidence_inputs={"evidence_strength": 1.0, "consistency": 1.0},
            )

        return None
