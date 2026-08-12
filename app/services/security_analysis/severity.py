from app.schemas.finding import FindingStatus, SeverityLevel


class SeverityEngine:
    """Deterministic severity engine calculating risk impact independently of confidence scores."""

    def calculate_severity(
        self,
        status: FindingStatus,
        owasp_category_id: str | None,
        boundary_crossed: str | None = None,
    ) -> tuple[SeverityLevel, str]:
        """Calculates deterministic severity level and rationale."""

        if status == FindingStatus.NEGATIVE:
            return (
                SeverityLevel.INFO,
                "No security vulnerability detected; endpoint demonstrated expected defensive behavior.",
            )

        if status == FindingStatus.INCONCLUSIVE:
            return (
                SeverityLevel.INFO,
                "Execution evidence was incomplete or ambiguous; no security vulnerability confirmed.",
            )

        # Base severity matrix for CONFIRMED findings
        base_severity = SeverityLevel.MEDIUM
        rationale = "Potential security boundary flaw detected."

        if owasp_category_id == "API1:2023":
            base_severity = SeverityLevel.HIGH
            rationale = "Crossed object-level authorization boundary, permitting unauthorized access to target object."
        elif owasp_category_id == "API2:2023":
            base_severity = SeverityLevel.HIGH
            rationale = "Crossed authentication boundary, permitting unauthenticated access to protected endpoint."
        elif owasp_category_id == "API5:2023":
            base_severity = SeverityLevel.HIGH
            rationale = "Crossed function-level authorization boundary, permitting unauthorized invocation of privileged function."
        elif owasp_category_id == "API3:2023":
            base_severity = SeverityLevel.MEDIUM
            rationale = "Crossed object property level boundary, exposing or mutating unauthorized object attributes."
        elif owasp_category_id == "API4:2023":
            base_severity = SeverityLevel.MEDIUM
            rationale = "Resource consumption limits missing or bypassed."

        # Adjust for SUSPECTED findings (reduce by one step)
        if status == FindingStatus.SUSPECTED:
            if base_severity == SeverityLevel.CRITICAL:
                base_severity = SeverityLevel.HIGH
            elif base_severity == SeverityLevel.HIGH:
                base_severity = SeverityLevel.MEDIUM
            elif base_severity == SeverityLevel.MEDIUM:
                base_severity = SeverityLevel.LOW
            rationale = f"Suspected security weakness: {rationale} Requires additional evidence confirmation."

        return base_severity, rationale
