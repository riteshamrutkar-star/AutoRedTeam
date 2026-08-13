from app.schemas.finding import SecurityFinding
from app.schemas.reporting import FindingView


def sanitize_text(text: str) -> str:
    """Ensures sensitive patterns like tokens or authorization headers are masked."""
    if not text:
        return ""
    # Basic redaction check
    lines = text.splitlines()
    sanitized_lines = []
    for line in lines:
        if "authorization:" in line.lower() or "bearer " in line.lower():
            sanitized_lines.append("[REDACTED_HEADER]")
        else:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def build_finding_views(
    findings: list[SecurityFinding],
    status_filter: str | None = None,
    severity_filter: str | None = None,
    owasp_filter: str | None = None,
) -> list[FindingView]:
    """Formats SecurityFinding items into presentation-level FindingView view models."""

    views: list[FindingView] = []

    for f in findings:
        if status_filter and f.status.value.upper() != status_filter.upper():
            continue
        if severity_filter and f.severity.value.upper() != severity_filter.upper():
            continue
        if owasp_filter and f.owasp.category_id.upper() != owasp_filter.upper():
            continue

        exp_beh = f"Expected endpoint {f.endpoint} to enforce access controls and reject invalid/unauthorized payloads."
        if isinstance(f.evidence, str):
            obs_beh = sanitize_text(f.evidence or f.detection_reason)
            evidence_summary = sanitize_text(f.evidence)
        else:
            obs_beh = sanitize_text(", ".join(f.evidence.observed_indicators) or f.detection_reason)
            evidence_summary = f"HTTP {f.evidence.status_code} response received with indicators: {', '.join(f.evidence.observed_indicators)}"

        view = FindingView(
            finding_id=f.finding_id,
            status=f.status.value,
            severity=f.severity.value,
            confidence_score=f.confidence_factors.overall_score,
            owasp_category_id=f.owasp.category_id,
            owasp_category_name=f.owasp.category_name,
            target_id=f.target_id,
            endpoint=f.endpoint,
            http_method=f.http_method,
            title=f.title,
            description=f.description,
            detection_reason=f.detection_reason,
            remediation_guidance=f.remediation_guidance,
            expected_behavior=exp_beh,
            observed_behavior=obs_beh,
            raw_evidence_summary=evidence_summary,
        )
        views.append(view)

    return views
