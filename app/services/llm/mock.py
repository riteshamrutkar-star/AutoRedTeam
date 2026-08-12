import json
import re
from typing import Any

from app.services.llm.provider import LLMProvider


class MockLLMProvider(LLMProvider):
    """Deterministic Mock LLM provider for unit tests, CI, and offline evaluation."""

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock-v1"

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "provider": self.provider_name,
            "model": self.model_name,
            "available": True,
        }

    async def generate_structured(
        self, prompt: str, system_prompt: str | None = None
    ) -> dict[str, Any]:
        """Generates deterministic mock test plan dict matching candidate context in prompt."""
        # Extract candidate metadata from prompt
        template_id_match = re.search(r"TEMPLATE_ID:\s*([A-Z0-9\-]+)", prompt)
        instance_id_match = re.search(r"INSTANCE_ID:\s*([^\n\s]+)", prompt)
        path_match = re.search(r"ENDPOINT_PATH:\s*([^\n\s]+)", prompt)
        method_match = re.search(r"HTTP_METHOD:\s*([A-Z]+)", prompt)
        param_match = re.search(r"TARGET_PARAMETER:\s*([^\n\s]+)", prompt)
        category_match = re.search(r"CATEGORY:\s*([^\n\s]+)", prompt)

        template_id = template_id_match.group(1) if template_id_match else "AUTH-001"
        instance_id = instance_id_match.group(1) if instance_id_match else f"mock_{template_id}"
        path = path_match.group(1) if path_match else "/users"
        method = method_match.group(1) if method_match else "GET"
        param = param_match.group(1) if param_match and param_match.group(1) != "N/A" else None
        category = category_match.group(1) if category_match else "AUTHENTICATION"

        target_location = "ENDPOINT"
        mutation_type = "UNSUPPORTED_METHOD"
        mutation_target = "endpoint"
        generated_value = None
        query_params = {}
        request_body = None
        auth_state = None

        if "BODY" in template_id or category == "REQUEST_BODY":
            target_location = "REQUEST_BODY"
            mutation_type = "OMIT" if "001" in template_id else ("UNEXPECTED_FIELD" if "002" in template_id else "MUTATE_TYPE")
            mutation_target = "request_body"
            request_body = {"username": "testuser", "email": "test@example.com"}
        elif "AUTHZ" in template_id or category == "AUTHORIZATION":
            target_location = "PATH" if (param and "id" in param.lower()) else ("QUERY" if param else "ENDPOINT")
            mutation_type = "OTHER_USER_ID"
            mutation_target = param or "id"
            generated_value = "00000000-0000-0000-0000-000000000000"
            if target_location == "QUERY" and param:
                query_params = {param: generated_value}
        elif "AUTH" in template_id or category == "AUTHENTICATION":
            target_location = "AUTHENTICATION"
            mutation_type = "OMIT"
            mutation_target = "Authorization"
            auth_state = "unauthenticated"
        elif "INP" in template_id:
            target_location = "QUERY" if param else "PATH"
            mutation_type = "BOUNDARY_MIN"
            mutation_target = param or "page"
            generated_value = 0
            if param:
                query_params = {param: 0}
        elif "HTTP" in template_id:
            target_location = "ENDPOINT"
            mutation_type = "UNSUPPORTED_METHOD"
            mutation_target = "HTTP_METHOD"

        mock_payload = {
            "generated_test_id": f"gen_{instance_id}",
            "instance_id": instance_id,
            "template_id": template_id,
            "endpoint_target": path,
            "http_method": method,
            "rationale": f"Deterministic mock reasoning for candidate {template_id} on {method} {path}.",
            "test_objective": f"Evaluate endpoint resilience against {template_id} security mutation.",
            "request_plan": {
                "http_method": method,
                "path": path,
                "query_parameters": query_params,
                "headers": {"Accept": "application/json"},
                "cookies": {},
                "request_body": request_body,
                "auth_state": auth_state,
            },
            "input_mutations": [
                {
                    "location": target_location,
                    "target": mutation_target,
                    "original_schema": {"type": "string"},
                    "mutation_type": mutation_type,
                    "generated_value": generated_value,
                    "rationale": f"Mock input mutation targeting {mutation_target}.",
                    "constraints_respected": True,
                }
            ],
            "authentication_context": auth_state,
            "expected_behavior": {
                "description": f"The endpoint must reject {template_id} mutation attempt.",
                "expected_status_codes": [400, 401, 403, 405, 422],
                "should_reject": True,
                "security_goal": f"Protect endpoint {path} against {template_id}.",
            },
            "evidence_requirements": {
                "status_code": True,
                "response_headers": True,
                "response_body": True,
                "response_size": False,
                "response_time": False,
                "redirect_information": False,
                "comparison_context": None,
            },
            "prerequisites": ["Valid OpenAPI specification baseline"],
            "generation_metadata": {
                "provider": self.provider_name,
                "model": self.model_name,
                "prompt_version": "SECURITY_TEST_GENERATION_PROMPT_V1",
                "schema_version": "GENERATED_TEST_SCHEMA_V1",
                "generation_timestamp": "2026-08-12T19:00:00Z",
                "template_id": template_id,
            },
            "confidence": 0.95,
        }
        return mock_payload
