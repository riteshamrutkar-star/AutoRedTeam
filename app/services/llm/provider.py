from abc import ABC, abstractmethod
from typing import Any

from app.core.config import settings
from app.core.exceptions import OpenAPIException


class LLMProviderError(OpenAPIException):
    """Exception raised when an LLM provider encounters network, timeout, or model errors."""

    pass


class LLMProvider(ABC):
    """Framework-independent abstract base class for LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the provider type identifier (e.g. 'mock', 'ollama')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Returns the actual underlying model name."""
        pass

    @abstractmethod
    async def generate_structured(
        self, prompt: str, system_prompt: str | None = None
    ) -> dict[str, Any]:
        """Generates structured JSON output from prompt input."""
        pass

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Returns provider status and readiness metadata."""
        pass


def get_llm_provider(provider_type: str | None = None) -> LLMProvider:
    """Factory function returning configured LLMProvider instance."""
    selected_provider = (provider_type or settings.LLM_PROVIDER).lower()

    if selected_provider == "mock":
        from app.services.llm.mock import MockLLMProvider
        return MockLLMProvider()
    elif selected_provider == "ollama":
        from app.services.llm.ollama import OllamaProvider
        return OllamaProvider()
    else:
        raise LLMProviderError(f"Unsupported LLM provider type: '{selected_provider}'. Valid options: 'mock', 'ollama'.")
