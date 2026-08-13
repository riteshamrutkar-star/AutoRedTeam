import platform
from app.core.config import settings
from app.schemas.evaluation import EvaluationInput, EvaluationResult
from app.schemas.manifest import ResearchManifest


def build_research_manifest(
    result: EvaluationResult,
    input_data: EvaluationInput | None = None,
) -> ResearchManifest:
    """Builds a ResearchManifest reproducibility artifact from evaluation objects."""

    spec_title = None
    spec_version = None

    if input_data and input_data.normalized_spec:
        spec_title = input_data.normalized_spec.metadata.title
        spec_version = input_data.normalized_spec.metadata.version

    exec_limits = {
        "execution_timeout_seconds": settings.EXECUTION_TIMEOUT_SECONDS,
        "max_request_body_bytes": settings.MAX_REQUEST_BODY_BYTES,
        "max_response_bytes": settings.MAX_RESPONSE_BYTES,
        "follow_redirects": settings.FOLLOW_REDIRECTS,
    }

    return ResearchManifest(
        autoredteam_version=settings.AUTOREDTEAM_VERSION,
        evaluation_version=result.evaluation_version,
        metric_definition_version=settings.METRIC_DEFINITION_VERSION,
        classifier_version=settings.CLASSIFIER_VERSION,
        owasp_taxonomy_version=settings.OWASP_API_TOP_10_VERSION,
        llm_provider=settings.LLM_PROVIDER,
        llm_model=settings.OLLAMA_MODEL if settings.LLM_PROVIDER == "ollama" else "mock-security-generator",
        prompt_version="v1",
        python_version=platform.python_version(),
        target_id=result.target_id,
        spec_title=spec_title,
        spec_version=spec_version,
        strategy=result.strategy.value,
        timestamp=result.completed_at,
        execution_limits=exec_limits,
    )
