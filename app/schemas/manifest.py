from typing import Any
from pydantic import BaseModel, Field


class ResearchManifest(BaseModel):
    """Machine-readable reproducibility manifest for research experiments."""

    autoredteam_version: str
    evaluation_version: str
    metric_definition_version: str
    classifier_version: str
    owasp_taxonomy_version: str
    llm_provider: str
    llm_model: str
    prompt_version: str = "v1"
    python_version: str
    target_id: str
    spec_title: str | None = None
    spec_version: str | None = None
    strategy: str
    timestamp: str
    execution_limits: dict[str, Any] = Field(default_factory=dict)
