from typing import Any
from fastapi import APIRouter

from app.schemas.finding import AnalyzeExecutionRequest, SecurityFinding
from app.services.security_analysis.analyzer import EvidenceAnalyzer
from app.services.security_analysis.owasp_mapper import OWASPMapper

router = APIRouter(tags=["Security Analysis"])


@router.get(
    "/security-analysis/owasp",
    response_model=dict[str, dict[str, Any]],
    summary="Get OWASP API Security Top 10 — 2023 taxonomy definitions",
    description="Retrieve the complete OWASP API Security Top 10 (2023 Edition) category registry used for finding classification.",
)
def get_owasp_taxonomy() -> dict[str, dict[str, Any]]:
    """Return OWASP API Top 10 2023 category definitions."""
    mapper = OWASPMapper()
    return mapper.get_supported_taxonomy()


@router.post(
    "/security-analysis/analyze",
    response_model=SecurityFinding,
    summary="Analyze execution evidence and produce a machine-readable SecurityFinding",
    description="Evaluate an ExecutionResult against a GeneratedSecurityTest using deterministic rules, returning a structured SecurityFinding with OWASP 2023 mapping.",
)
def analyze_execution_evidence(request: AnalyzeExecutionRequest) -> SecurityFinding:
    """Analyze execution evidence and produce a SecurityFinding."""
    analyzer = EvidenceAnalyzer()
    return analyzer.analyze(
        test=request.generated_test,
        result=request.execution_result,
        spec=request.spec,
    )
