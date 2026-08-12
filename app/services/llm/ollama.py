import json
from typing import Any
import httpx

from app.core.config import settings
from app.services.llm.provider import LLMProvider, LLMProviderError


class OllamaProvider(LLMProvider):
    """Local Ollama open-source LLM provider implementation using httpx."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self._model = model or settings.OLLAMA_MODEL
        self.timeout = timeout_seconds or settings.LLM_TIMEOUT_SECONDS

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    async def health_check(self) -> dict[str, Any]:
        """Checks if local Ollama server is reachable and configured model is available."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    model_found = any(self._model in m for m in models)
                    return {
                        "status": "ok" if model_found else "warning",
                        "provider": self.provider_name,
                        "model": self.model_name,
                        "available": True,
                        "model_installed": model_found,
                        "installed_models": models,
                    }
                return {
                    "status": "error",
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "available": False,
                    "error": f"Ollama API returned HTTP {response.status_code}",
                }
        except Exception as exc:
            return {
                "status": "error",
                "provider": self.provider_name,
                "model": self.model_name,
                "available": False,
                "error": str(exc),
            }

    async def generate_structured(
        self, prompt: str, system_prompt: str | None = None
    ) -> dict[str, Any]:
        """Sends prompt to Ollama with format="json" and returns parsed JSON dict."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self._model,
            "prompt": prompt,
            "system": system_prompt or "",
            "format": "json",
            "stream": False,
            "options": {
                "temperature": settings.LLM_TEMPERATURE,
                "num_predict": settings.LLM_MAX_TOKENS,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    raise LLMProviderError(
                        f"Ollama API request failed with HTTP status {response.status_code}: {response.text}"
                    )
                data = response.json()
                raw_response = data.get("response", "").strip()
                if not raw_response:
                    raise LLMProviderError("Ollama API returned empty response string.")

                try:
                    return json.loads(raw_response)
                except json.JSONDecodeError as exc:
                    raise LLMProviderError(
                        f"Failed to parse Ollama JSON response: {exc}. Raw response: {raw_response[:200]}"
                    ) from exc
        except httpx.TimeoutException as exc:
            raise LLMProviderError(f"Ollama request timed out after {self.timeout} seconds.") from exc
        except httpx.ConnectError as exc:
            raise LLMProviderError(f"Could not connect to Ollama server at {self.base_url}. Is Ollama running?") from exc
        except Exception as exc:
            if isinstance(exc, LLMProviderError):
                raise
            raise LLMProviderError(f"Ollama provider error: {exc}") from exc
