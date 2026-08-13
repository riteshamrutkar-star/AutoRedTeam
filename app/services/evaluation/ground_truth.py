from app.schemas.evaluation import (
    GroundTruthDataset,
    GroundTruthFinding,
    MatchResult,
    MatchStatus,
)
from app.schemas.finding import FindingStatus, SecurityFinding


def match_findings_to_ground_truth(
    target_id: str,
    findings: list[SecurityFinding],
    ground_truth: GroundTruthDataset | None,
) -> list[MatchResult]:
    """Deterministically matches findings to ground truth, enforcing target_id equality and FindingStatus eligibility."""

    results: list[MatchResult] = []
    if not ground_truth:
        return results

    # Target ID Guard: cross-target matching is forbidden
    if ground_truth.target_id != target_id:
        for f in findings:
            results.append(
                MatchResult(
                    finding_id=f.finding_id,
                    ground_truth_id=None,
                    match_status=MatchStatus.UNMATCHED,
                    confidence=0.0,
                    reason=f"Target ID mismatch: finding target '{f.target_id}' != ground truth target '{ground_truth.target_id}'.",
                )
            )
        return results

    # Only CONFIRMED findings are eligible for TP/FP ground-truth matching
    confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    matched_gt_ids: set[str] = set()

    for f in confirmed_findings:
        matched_gt: GroundTruthFinding | None = None

        for gt in ground_truth.vulnerabilities:
            if gt.target_id != target_id:
                continue

            # Path & Method match
            same_path = (f.endpoint.strip().rstrip("/") == gt.endpoint.strip().rstrip("/"))
            same_method = (f.http_method.upper() == gt.method.upper())

            if same_path and same_method:
                # OWASP Category / Vulnerability Identifier / Alias match check
                owasp_cat = f.owasp.category_id if f.owasp else ""
                category_match = (
                    gt.owasp_category == owasp_cat
                    or gt.vulnerability_identifier.upper() in f.title.upper()
                    or any(alias.upper() in f.title.upper() or alias.upper() in f.description.upper() for alias in gt.aliases)
                )

                if category_match:
                    matched_gt = gt
                    break

        if matched_gt:
            matched_gt_ids.add(matched_gt.ground_truth_id)
            results.append(
                MatchResult(
                    finding_id=f.finding_id,
                    ground_truth_id=matched_gt.ground_truth_id,
                    match_status=MatchStatus.KNOWN_MATCH,
                    confidence=1.0,
                    reason=f"Matched ground-truth vulnerability {matched_gt.ground_truth_id} on {gt.method} {gt.endpoint}.",
                )
            )
        else:
            results.append(
                MatchResult(
                    finding_id=f.finding_id,
                    ground_truth_id=None,
                    match_status=MatchStatus.UNMATCHED,
                    confidence=0.0,
                    reason="Finding does not match any known ground-truth vulnerability.",
                )
            )

    # Record KNOWN_MISS for unmatched ground-truth vulnerabilities
    for gt in ground_truth.vulnerabilities:
        if gt.ground_truth_id not in matched_gt_ids:
            results.append(
                MatchResult(
                    finding_id="N/A",
                    ground_truth_id=gt.ground_truth_id,
                    match_status=MatchStatus.KNOWN_MISS,
                    confidence=1.0,
                    reason=f"Ground-truth vulnerability {gt.ground_truth_id} ({gt.title}) was not discovered.",
                )
            )

    return results
