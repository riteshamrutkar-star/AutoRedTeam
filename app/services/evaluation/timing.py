from datetime import datetime, timezone

from app.schemas.evaluation import MatchResult, MatchStatus, MetricStatus, MetricValue, TimingMetrics
from app.schemas.execution import ExecutionResult
from app.schemas.finding import FindingStatus, SecurityFinding


def parse_iso_timestamp(ts: str | None) -> datetime | None:
    """Parses an ISO format timestamp into UTC datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def compute_timing_metrics(
    execution_results: list[ExecutionResult],
    findings: list[SecurityFinding],
    matches: list[MatchResult],
    started_at_iso: str,
    completed_at_iso: str,
) -> TimingMetrics:
    """Computes TTFV (time to first CONFIRMED finding) and TTFKV (time to first CONFIRMED ground-truth match)."""

    start_dt = parse_iso_timestamp(started_at_iso)
    end_dt = parse_iso_timestamp(completed_at_iso)

    total_duration_sec: float | None = None
    if start_dt and end_dt:
        total_duration_sec = max(0.0, (end_dt - start_dt).total_seconds())

    # Map execution results to timestamps
    exec_map = {r.execution_id: r for r in execution_results}

    # TTFV: Time to first CONFIRMED finding
    confirmed_findings = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    ttfv_ms: float | None = None
    if confirmed_findings and start_dt:
        first_confirmed = confirmed_findings[0]
        exec_res = exec_map.get(first_confirmed.execution_id)
        if exec_res and exec_res.completed_at:
            comp_dt = parse_iso_timestamp(exec_res.completed_at)
            if comp_dt:
                ttfv_ms = max(0.0, (comp_dt - start_dt).total_seconds() * 1000.0)

    # TTFKV: Time to first CONFIRMED finding matching ground truth
    known_match_ids = {m.finding_id for m in matches if m.match_status == MatchStatus.KNOWN_MATCH}
    ttfkv_ms: float | None = None
    if known_match_ids and start_dt:
        for f in confirmed_findings:
            if f.finding_id in known_match_ids:
                exec_res = exec_map.get(f.execution_id)
                if exec_res and exec_res.completed_at:
                    comp_dt = parse_iso_timestamp(exec_res.completed_at)
                    if comp_dt:
                        ttfkv_ms = max(0.0, (comp_dt - start_dt).total_seconds() * 1000.0)
                        break

    ttfv_val = MetricValue(
        value=round(ttfv_ms, 2) if ttfv_ms is not None else None,
        status=MetricStatus.COMPUTED if ttfv_ms is not None else MetricStatus.NOT_APPLICABLE,
        reason=None if ttfv_ms is not None else "No CONFIRMED findings reported in run.",
    )

    ttfv_sec_val = MetricValue(
        value=round(ttfv_ms / 1000.0, 3) if ttfv_ms is not None else None,
        status=MetricStatus.COMPUTED if ttfv_ms is not None else MetricStatus.NOT_APPLICABLE,
        reason=None if ttfv_ms is not None else "No CONFIRMED findings reported in run.",
    )

    ttfkv_val = MetricValue(
        value=round(ttfkv_ms, 2) if ttfkv_ms is not None else None,
        status=MetricStatus.COMPUTED if ttfkv_ms is not None else MetricStatus.NOT_APPLICABLE,
        reason=None if ttfkv_ms is not None else "No CONFIRMED ground-truth matches reported in run.",
    )

    duration_val = MetricValue(
        value=round(total_duration_sec, 2) if total_duration_sec is not None else None,
        status=MetricStatus.COMPUTED if total_duration_sec is not None else MetricStatus.UNDEFINED,
    )

    return TimingMetrics(
        time_to_first_vulnerability_ms=ttfv_val,
        time_to_first_vulnerability_sec=ttfv_sec_val,
        time_to_first_known_vulnerability_ms=ttfkv_val,
        total_duration_sec=duration_val,
    )
