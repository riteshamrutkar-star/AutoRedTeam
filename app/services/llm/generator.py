from datetime import datetime, timezone
import json
from typing import Any

from app.schemas.generated_test import (
    FailedGenerationResult,
    GenerateSecurityTestsRequest,
    GenerateSecurityTestsResponse,
    GeneratedSecurityTest,
    GenerationMetadata,
    PROMPT_VERSION,
    SCHEMA_VERSION,
)
from app.schemas.security_test import ApplicableTestResult
from app.schemas.spec import NormalizedApiSpec, NormalizedEndpoint
from app.services.llm.prompts import build_test_generation_prompt
from app.services.llm.provider import LLMProvider, get_llm_provider


class SecurityTestGenerator:
    """Orchestrates LLM security test generation with strict post-LLM anti-hallucination validation."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or get_llm_provider()

    async def generate_tests(
        self, request: GenerateSecurityTestsRequest
    ) -> GenerateSecurityTestsResponse:
        """Processes candidate tests against API specification to produce validated GeneratedSecurityTest instances."""
        spec = request.spec
        candidates = request.applicable_tests

        # Build lookup map for endpoints by (path, method)
        endpoint_map: dict[tuple[str, str], NormalizedEndpoint] = {
            (e.path, e.method.upper()): e for e in spec.endpoints
        }

        generated_list: list[GeneratedSecurityTest] = []
        failed_list: list[FailedGenerationResult] = []

        for candidate in candidates:
            path = candidate.target.path
            method = candidate.target.http_method.upper()
            endpoint = endpoint_map.get((path, method))

            if not endpoint:
                failed_list.append(
                    FailedGenerationResult(
                        instance_id=candidate.instance_id,
                        template_id=candidate.template_id,
                        endpoint_target=path,
                        http_method=method,
                        failure_type="ENDPOINT_NOT_FOUND",
                        reason=f"Candidate target path '{path}' [{method}] not found in provided specification.",
                    )
                )
                continue

            user_prompt, system_prompt = build_test_generation_prompt(endpoint, candidate)

            try:
                raw_json = await self.provider.generate_structured(user_prompt, system_prompt)
                validated_test = self._validate_llm_output(raw_json, candidate, endpoint)
                generated_list.append(validated_test)
            except Exception as exc:
                failed_list.append(
                    FailedGenerationResult(
                        instance_id=candidate.instance_id,
                        template_id=candidate.template_id,
                        endpoint_target=path,
                        http_method=method,
                        failure_type="VALIDATION_FAILURE",
                        reason=str(exc),
                        raw_output=json.dumps(raw_json) if 'raw_json' in locals() and isinstance(raw_json, dict) else None,
                    )
                )

        return GenerateSecurityTestsResponse(
            generated_tests=generated_list,
            failed_generations=failed_list,
            total_requested=len(candidates),
            total_generated=len(generated_list),
            total_failed=len(failed_list),
        )

    def _validate_llm_output(
        self,
        raw_json: dict[str, Any],
        candidate: ApplicableTestResult,
        endpoint: NormalizedEndpoint,
    ) -> GeneratedSecurityTest:
        """Deeply validates raw LLM output against candidate metadata and endpoint schema bounds."""
        
        # 1. Pydantic Model Validation
        try:
            gen_test = GeneratedSecurityTest.model_validate(raw_json)
        except Exception as exc:
            raise ValueError(f"LLM output failed Pydantic schema validation: {exc}") from exc

        # 2. Consistency & Anti-Hallucination Checks
        if gen_test.template_id != candidate.template_id:
            raise ValueError(
                f"Template ID mismatch: LLM returned '{gen_test.template_id}', expected '{candidate.template_id}'."
            )

        if gen_test.endpoint_target != candidate.target.path:
            raise ValueError(
                f"Endpoint path mismatch: LLM returned '{gen_test.endpoint_target}', expected '{candidate.target.path}'."
            )

        if gen_test.http_method.upper() != candidate.target.http_method.upper():
            raise ValueError(
                f"HTTP method mismatch: LLM returned '{gen_test.http_method}', expected '{candidate.target.http_method}'."
            )

        # 3. Validate Target Parameter Identity against Endpoint Schema
        declared_param_names = {p.name for p in endpoint.parameters}
        for mut in gen_test.input_mutations:
            if mut.location.value in ("PATH", "QUERY", "HEADER", "COOKIE"):
                if mut.target not in declared_param_names and mut.target not in ("Authorization", "Accept", "Content-Type", "endpoint"):
                    raise ValueError(
                        f"Hallucinated parameter target: LLM targeted parameter '{mut.target}' in location '{mut.location.value}', which is not declared for endpoint '{endpoint.path}'."
                    )

        # 4. Attach Accurate Provider Metadata
        now_utc = datetime.now(timezone.utc).isoformat()
        gen_test.generation_metadata = GenerationMetadata(
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            prompt_version=PROMPT_VERSION,
            schema_version=SCHEMA_VERSION,
            generation_timestamp=now_utc,
            template_id=candidate.template_id,
        )

        return gen_test
