from typing import Any
from fastapi import APIRouter

from app.services.llm.provider import get_llm_provider

router = APIRouter(prefix="/api/v1/llm", tags=["LLM"])


@router.get(
    "/health",
    summary="Check LLM provider readiness",
    description="Check the availability and configuration status of the configured LLM provider (Mock or Ollama).",
)
async def llm_health() -> dict[str, Any]:
    """Check configured LLM provider health status."""
    provider = get_llm_provider()
    return await provider.health_check()
