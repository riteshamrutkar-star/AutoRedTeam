import pytest

from app.services.llm.mock import MockLLMProvider
from app.services.llm.ollama import OllamaProvider
from app.services.llm.provider import get_llm_provider


@pytest.mark.anyio
async def test_mock_provider_determinism():
    provider = MockLLMProvider()
    assert provider.provider_name == "mock"
    assert provider.model_name == "mock-v1"

    health = await provider.health_check()
    assert health["status"] == "ok"
    assert health["provider"] == "mock"
    assert health["model"] == "mock-v1"

    prompt = "TEMPLATE_ID: AUTH-001\nINSTANCE_ID: petstore_users_GET_AUTH-001\nENDPOINT_PATH: /users\nHTTP_METHOD: GET\nCATEGORY: AUTHENTICATION"
    result1 = await provider.generate_structured(prompt)
    result2 = await provider.generate_structured(prompt)

    assert result1 == result2
    assert result1["template_id"] == "AUTH-001"
    assert result1["endpoint_target"] == "/users"


def test_provider_factory_mock():
    provider = get_llm_provider("mock")
    assert isinstance(provider, MockLLMProvider)
    assert provider.provider_name == "mock"


def test_ollama_provider_configuration():
    ollama = OllamaProvider(base_url="http://localhost:11434", model="llama3.2", timeout_seconds=15)
    assert ollama.provider_name == "ollama"
    assert ollama.model_name == "llama3.2"
    assert ollama.timeout == 15
