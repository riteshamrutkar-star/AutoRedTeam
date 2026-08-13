from app.schemas.evaluation import (
    DiscoveryMetrics,
    FalsePositiveMetrics,
    GroundTruthDataset,
    MatchResult,
    MatchStatus,
    MetricStatus,
    MetricValue,
)
from app.schemas.finding import FindingStatus, SecurityFinding


def compute_discovery_metrics(
    findings: list[SecurityFinding],
    matches: list[MatchResult],
    ground_truth: GroundTruthDataset | None,
) -> tuple[DiscoveryMetrics, FalsePositiveMetrics]:
    """Computes vulnerability discovery accuracy, TP, FP, FN, precision, recall, and false positive metrics."""

    confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    suspected_count = sum(1 for f in findings if f.status == FindingStatus.SUSPECTED)
    inconclusive_count = sum(1 for f in findings if f.status == FindingStatus.INCONCLUSIVE)

    total_known = len(ground_truth.vulnerabilities) if ground_truth else 0

    # Unique discovered vulnerability IDs
    discovered_gt_ids = {
        m.ground_truth_id for m in matches if m.match_status == MatchStatus.KNOWN_MATCH and m.ground_truth_id
    }
    unique_discovered = len(discovered_gt_ids)

    # TP = count of unique matched vulnerabilities
    tp = unique_discovered
    fn = total_known - unique_discovered if total_known >= unique_discovered else 0

    # FP computation relies on complete ground-truth scope
    fp = 0
    fp_computable = bool(ground_truth and ground_truth.scope_complete)

    if fp_computable:
        fp = sum(1 for m in matches if m.match_status == MatchStatus.UNMATCHED)

    # 1. Discovery Rate
    if total_known > 0:
        disc_rate_val = round(unique_discovered / total_known, 4)
        discovery_rate = MetricValue(value=disc_rate_val, status=MetricStatus.COMPUTED)
    else:
        discovery_rate = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="No ground truth supplied or known vulnerabilities total is 0.",
        )

    # 2. Precision
    if fp_computable and (tp + fp) > 0:
        prec_val = round(tp / (tp + fp), 4)
        precision = MetricValue(value=prec_val, status=MetricStatus.COMPUTED)
    else:
        precision = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="Precision cannot be computed (ground truth scope incomplete or zero confirmed findings).",
        )

    # 3. Recall
    if (tp + fn) > 0:
        rec_val = round(tp / (tp + fn), 4)
        recall = MetricValue(value=rec_val, status=MetricStatus.COMPUTED)
    else:
        recall = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="Recall cannot be computed (zero known vulnerabilities).",
        )

    # 4. False Positive Rate
    eligible_confirmed = len(confirmed_findings)
    if fp_computable and (tp + fp) > 0:
        fp_rate_val = round(fp / (tp + fp), 4)
        false_positive_rate = MetricValue(value=fp_rate_val, status=MetricStatus.COMPUTED)
    else:
        false_positive_rate = MetricValue(
            value=None,
            status=MetricStatus.NOT_APPLICABLE,
            reason="False positive rate cannot be computed (ground truth scope incomplete or no eligible findings).",
        )

    discovery_metrics = DiscoveryMetrics(
        known_vulnerabilities_total=total_known,
        unique_vulnerabilities_discovered=unique_discovered,
        discovery_rate=discovery_rate,
        true_positives=tp,
        false_positives=fp if fp_computable else 0,
        false_negatives=fn,
        suspected_count=suspected_count,
        inconclusive_count=inconclusive_count,
        precision=precision,
        recall=recall,
    )

    false_positive_metrics = FalsePositiveMetrics(
        false_positive_count=fp if fp_computable else 0,
        eligible_confirmed_findings=eligible_confirmed,
        false_positive_rate=false_positive_rate,
    )

    return discovery_metrics, false_positive_metrics
