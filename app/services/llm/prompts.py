import json
from app.schemas.security_test import ApplicableTestResult
from app.schemas.spec import NormalizedEndpoint

PROMPT_VERSION = "SECURITY_TEST_GENERATION_PROMPT_V1"

SYSTEM_PROMPT = """You are an AI Security Test-Generation Agent for AutoRedTeam.
Your task is to instantiate a concrete, declarative security test plan for a specific API endpoint based on a candidate security test template.

STRICT RULES & CONSTRAINTS:
1. OUTPUT FORMAT: You MUST return ONLY valid, single JSON object conforming strictly to the requested schema. Do NOT include markdown code blocks, preambles, explanations, or prose outside JSON.
2. NO HALLUCINATION: You MUST ONLY target the exact HTTP method, path, parameter names, and schema locations provided in the prompt context. Do NOT invent un-declared endpoints, parameters, headers, cookies, or schema properties.
3. NO CODE GENERATION: You MUST output declarative test configurations only. Do NOT generate Python code, shell commands, Docker scripts, or tool calls.
4. CONFIDENCE SCORE: The 'confidence' field must represent your generation confidence (0.0 to 1.0) that the test plan correctly instantiates the candidate strategy, NOT vulnerability probability.
5. NO EXPLOIT STRING PAYLOADS: Generate abstract test input specifications and boundary mutation values, NOT real exploit payloads (no SQLi, XSS, or RCE strings).
"""


def build_test_generation_prompt(
    endpoint: NormalizedEndpoint, candidate: ApplicableTestResult
) -> tuple[str, str]:
    """Constructs a focused prompt containing endpoint context, candidate metadata, and anti-hallucination constraints."""
    
    # Extract focused endpoint details rather than sending whole spec
    params_summary = []
    for p in endpoint.parameters:
        p_info = {
            "name": p.name,
            "location": p.location,
            "required": p.required,
            "schema_type": p.schema_def.type if p.schema_def else None,
            "format": p.schema_def.format if p.schema_def else None,
            "enum": p.schema_def.enum if p.schema_def else None,
            "minimum": p.schema_def.minimum if p.schema_def else None,
            "maximum": p.schema_def.maximum if p.schema_def else None,
        }
        params_summary.append(p_info)

    body_summary = None
    if endpoint.request_body:
        body_summary = {
            "required": endpoint.request_body.required,
            "media_types": list(endpoint.request_body.content.keys()),
        }

    user_prompt = f"""### CANDIDATE TEST CONTEXT
TEMPLATE_ID: {candidate.template_id}
INSTANCE_ID: {candidate.instance_id}
CATEGORY: {candidate.category.value}
SUBCATEGORY: {candidate.subcategory}
NAME: {candidate.name}
STRATEGY_TYPE: {candidate.strategy.strategy_type.value}
MUTATION_TYPE: {candidate.strategy.mutation_type.value}
RATIONALE: {candidate.strategy.rationale}
TARGET_PARAMETER: {candidate.target.parameter_name or 'N/A'}
APPLICABILITY_REASONS: {json.dumps(candidate.applicability_reasons)}

### API ENDPOINT CONTEXT
ENDPOINT_PATH: {endpoint.path}
HTTP_METHOD: {endpoint.method}
DECLARED_SECURITY: {json.dumps(endpoint.security)}
DECLARED_PARAMETERS: {json.dumps(params_summary)}
DECLARED_REQUEST_BODY: {json.dumps(body_summary)}

### REQUIRED JSON RESPONSE STRUCTURE
Return a JSON object with the following fields:
{{
  "generated_test_id": "gen_{candidate.instance_id}",
  "instance_id": "{candidate.instance_id}",
  "template_id": "{candidate.template_id}",
  "endpoint_target": "{endpoint.path}",
  "http_method": "{endpoint.method}",
  "rationale": "<Detailed technical rationale explaining why this test applies>",
  "test_objective": "<Clear security objective>",
  "request_plan": {{
    "http_method": "{endpoint.method}",
    "path": "{endpoint.path}",
    "query_parameters": {{}},
    "headers": {{"Accept": "application/json"}},
    "cookies": {{}},
    "request_body": null,
    "auth_state": null
  }},
  "input_mutations": [
    {{
      "location": "{candidate.target.target_location.value}",
      "target": "{candidate.target.parameter_name or 'endpoint'}",
      "original_schema": null,
      "mutation_type": "{candidate.strategy.mutation_type.value}",
      "generated_value": "<test_value>",
      "rationale": "<reason for value>",
      "constraints_respected": true
    }}
  ],
  "authentication_context": null,
  "expected_behavior": {{
    "description": "<expected API security response>",
    "expected_status_codes": [400, 401, 403, 422],
    "should_reject": true,
    "security_goal": "<security goal>"
  }},
  "evidence_requirements": {{
    "status_code": true,
    "response_headers": true,
    "response_body": true,
    "response_size": false,
    "response_time": false,
    "redirect_information": false,
    "comparison_context": null
  }},
  "prerequisites": ["Valid OpenAPI specification baseline"],
  "generation_metadata": {{
    "provider": "<provider>",
    "model": "<model>",
    "prompt_version": "{PROMPT_VERSION}",
    "schema_version": "GENERATED_TEST_SCHEMA_V1",
    "generation_timestamp": "<timestamp>",
    "template_id": "{candidate.template_id}"
  }},
  "confidence": 0.90
}}
"""
    return user_prompt, SYSTEM_PROMPT
