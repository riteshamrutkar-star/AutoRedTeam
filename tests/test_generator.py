from pathlib import Path
import pytest

from app.schemas.generated_test import GenerateSecurityTestsRequest
from app.services.openapi.normalizer import process_spec_bytes
from app.services.security_tests.applicability import ApplicabilityEngine
from app.services.llm.generator import SecurityTestGenerator
from app.services.llm.mock import MockLLMProvider
from app.services.llm.provider import LLMProvider

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.mark.anyio
async def test_generator_successful_flow():
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")

    engine = ApplicabilityEngine()
    applicable_results = engine.evaluate_spec(spec)
    assert len(applicable_results) > 0

    generator = SecurityTestGenerator(provider=MockLLMProvider())
    req = GenerateSecurityTestsRequest(spec=spec, applicable_tests=applicable_results[:3])
    resp = await generator.generate_tests(req)

    assert resp.total_requested == 3
    assert resp.total_generated == 3
    assert resp.total_failed == 0
    assert len(resp.generated_tests) == 3

    # Check accuracy of generated test metadata
    first_test = resp.generated_tests[0]
    assert first_test.generation_metadata.provider == "mock"
    assert first_test.generation_metadata.model == "mock-v1"
    assert first_test.confidence == 0.95


class HallucinatingLLMProvider(LLMProvider):
    """Faulty provider returning hallucinated endpoints and parameters to test validation rejection."""

    def __init__(self, defect_type: str) -> None:
        self.defect_type = defect_type

    @property
    def provider_name(self) -> str:
        return "faulty_mock"

    @property
    def model_name(self) -> str:
        return "faulty-v1"

    async def health_check(self):
        return {"status": "ok"}

    async def generate_structured(self, prompt: str, system_prompt=None):
        base = await MockLLMProvider().generate_structured(prompt, system_prompt)
        if self.defect_type == "template_mismatch":
            base["template_id"] = "WRONG-999"
        elif self.defect_type == "endpoint_mismatch":
            base["endpoint_target"] = "/hallucinated/admin"
        elif self.defect_type == "method_mismatch":
            base["http_method"] = "POST"  # when expected GET
            base["request_plan"]["http_method"] = "POST"
        elif self.defect_type == "parameter_hallucination":
            base["input_mutations"][0]["location"] = "QUERY"
            base["input_mutations"][0]["target"] = "non_existent_secret_key"
        return base


@pytest.mark.anyio
async def test_generator_hallucination_resistance():
    """Negative tests verifying deep post-LLM validation rejects hallucinated model outputs."""
    yaml_bytes = (FIXTURES_DIR / "petstore_openapi.yaml").read_bytes()
    spec = process_spec_bytes(yaml_bytes, filename="petstore_openapi.yaml")
    engine = ApplicabilityEngine()
    applicable_results = engine.evaluate_spec(spec)
    candidate = [r for r in applicable_results if r.target.path == "/users" and r.target.http_method == "GET"][:1]

    # 1. Template ID mismatch rejection
    gen_template_err = SecurityTestGenerator(provider=HallucinatingLLMProvider("template_mismatch"))
    resp1 = await gen_template_err.generate_tests(GenerateSecurityTestsRequest(spec=spec, applicable_tests=candidate))
    assert resp1.total_failed == 1
    assert "Template ID mismatch" in resp1.failed_generations[0].reason

    # 2. Endpoint path mismatch rejection
    gen_path_err = SecurityTestGenerator(provider=HallucinatingLLMProvider("endpoint_mismatch"))
    resp2 = await gen_path_err.generate_tests(GenerateSecurityTestsRequest(spec=spec, applicable_tests=candidate))
    assert resp2.total_failed == 1
    assert "Endpoint path mismatch" in resp2.failed_generations[0].reason

    # 3. HTTP method mismatch rejection
    gen_method_err = SecurityTestGenerator(provider=HallucinatingLLMProvider("method_mismatch"))
    resp3 = await gen_method_err.generate_tests(GenerateSecurityTestsRequest(spec=spec, applicable_tests=candidate))
    assert resp3.total_failed == 1
    assert "HTTP method mismatch" in resp3.failed_generations[0].reason

    # 4. Parameter target hallucination rejection
    gen_param_err = SecurityTestGenerator(provider=HallucinatingLLMProvider("parameter_hallucination"))
    resp4 = await gen_param_err.generate_tests(GenerateSecurityTestsRequest(spec=spec, applicable_tests=candidate))
    assert resp4.total_failed == 1
    assert "Hallucinated parameter target" in resp4.failed_generations[0].reason
