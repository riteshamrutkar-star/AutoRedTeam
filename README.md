# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

---

## Overview

AutoRedTeam is an autonomous LLM red-teaming research prototype designed to ingest API specifications, normalize them into structured domain models, model security tests, generate concrete test plans using LLM reasoning, and execute test plans safely against explicitly registered, controlled target environments.

* **Phase 1**: Project Foundation & Repository Readiness (Completed)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Completed)
* **Phase 3**: Security Test Model & Test Catalogue (Completed)
* **Phase 4**: LLM Security Test-Generation Agent (Completed)
* **Phase 5**: Controlled Security Test Execution Engine (Completed)

---

## Architecture & Pipeline

```text
OpenAPI Spec (JSON/YAML)
         ↓
  NormalizedApiSpec (Phase 2)
         ↓
  ApplicabilityEngine (Phase 3)
         ↓
  ApplicableTestResult Candidates (Phase 3)
         ↓
  Focused Prompt Builder (prompts.py - Phase 4)
         ↓
  Framework-Independent LLM Provider (Ollama / Mock - Phase 4)
         ↓
  Post-LLM Anti-Hallucination Validator (generator.py - Phase 4)
         ↓
  GeneratedSecurityTest (Phase 4) + target_id
         ↓
  Execution Policy & SSRF Guard (policy.py - Phase 5)
         ↓
  Registered Controlled Target (target_registry.py - Phase 5)
         ↓
  Streamed Async HTTP Client against Target (executor.py - Phase 5)
         ↓
  Structured Execution Evidence / ExecutionResult (Phase 5)
```

---

## Features

### Phase 1: Core Foundation
* **FastAPI Skeleton**: Async web application with lifespan logging.
* **Centralized Configuration**: Environment-driven settings via `pydantic-settings`.
* **Structured Logging**: Standardized console log formatting.
* **System Health Endpoints**: `/` and `/health` readiness routes.
* **Docker Support**: Containerized deployment via `Dockerfile` and `docker-compose.yml`.

### Phase 2: OpenAPI Ingestion & Intelligence
* **Multi-Format Ingestion**: Ingests `.json`, `.yaml`, and `.yml` OpenAPI specifications.
* **OpenAPI 3.x Support**: Ingests and validates OpenAPI 3.0.x and 3.1.x documents. Rejects non-3.x specifications (e.g. Swagger 2.0).
* **Local Reference Dereferencing**: Resolves internal `$ref` pointers (e.g. `#/components/schemas/...`) with cycle protection.
* **Rich Schema Normalization**: Preserves primitive types, nested objects, array items, formats, enums, defaults, validation constraints, and raw schema objects.
* **Ingestion API**: `POST /api/v1/specifications/parse` and `POST /api/v1/specifications/validate` endpoints.

### Phase 3: Security Test Model & Catalogue
* **Typed Security Domain Model**: Structured `SecurityTestCase`, `TestTemplate`, `ApplicableTestResult`, `TestTarget`, `TestStrategy`, `InputSpecification`, `ExpectedBehavior`, and `EvidenceRequirements`.
* **Catalogue / Instance Separation**: Keeps catalogue templates immutable (`TestTemplate`) while generating endpoint-specific test results (`ApplicableTestResult`).
* **Feature Extraction**: Centralized parameter and endpoint feature extractor (`extract_endpoint_features`).
* **Deterministic Applicability Engine**: Evaluates `NormalizedApiSpec` against catalogue prerequisites and returns reproducible test results with structured applicability reasons.
* **Security Test API**: `GET /api/v1/security-tests/catalogue` and `POST /api/v1/security-tests/applicable` endpoints.

### Phase 4: LLM Security Test-Generation Agent
* **Provider Abstraction**: Framework-independent LLM provider interface (`LLMProvider`) supporting `MockLLMProvider` (offline/CI) and `OllamaProvider` (local open-source LLMs).
* **Focused Prompt Context**: Prompt builder (`prompts.py`) extracts endpoint schemas and candidate template requirements into versioned prompts (`SECURITY_TEST_GENERATION_PROMPT_V1`) with explicit anti-hallucination rules.
* **Strict Post-LLM Anti-Hallucination Validation**: Validates `template_id`, `endpoint_target`, `http_method`, parameter names, target locations, and schema bounds. Returns structured `FailedGenerationResult` objects for invalid LLM outputs.
* **Experiment Metadata & Confidence**: Records provider, model, prompt version, schema version, generation timestamp, and model-reported generation confidence score.
* **LLM API Endpoints**: `POST /api/v1/security-tests/generate` and `GET /api/v1/llm/health`.

### Phase 5: Controlled Security Test Execution Engine
* **Target Allowlist Registry**: Manages registered, controlled evaluation target environments (`vampi-local`, `juice-shop-local`, `dvwa-local`). Validates base URLs at startup to ensure scheme is `http`/`https` and host is within allowed scope (`localhost`, `127.0.0.1`, `testserver`), rejecting embedded credentials.
* **Centralized Safety Policy & SSRF Guard**: Re-validates resolved URL before every request. Rejects absolute URLs in path, scheme-relative URLs (`//`), authority changes (`@`), path traversal (`..`), disallowed HTTP methods, and external redirects.
* **Pre-flight & Streamed Resource Caps**: Enforces `MAX_REQUEST_BODY_BYTES` before sending requests and `MAX_RESPONSE_BYTES` via streamed chunk reading (`aiter_bytes`), preventing memory exhaustion.
* **Header & Body Redaction**: Automatically redacts sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`) and body credential fields in logged evidence.
* **Symbolic Authentication**: Uses symbolic target-mapped references (e.g. `TEST_TOKEN_USER`, `TEST_TOKEN_ADMIN`).
* **Execution API Endpoints**: `POST /api/v1/executions` and `GET /api/v1/targets`.

---

## Directory Layout

```text
AutoRedTeam/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── executions.py
│   │       ├── health.py
│   │       ├── llm.py
│   │       ├── security_tests.py
│   │       └── specifications.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── exceptions.py
│   │   └── logging.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── execution.py
│   │   ├── generated_test.py
│   │   ├── security_test.py
│   │   └── spec.py
│   └── services/
│       ├── __init__.py
│       ├── execution/
│       │   ├── __init__.py
│       │   ├── executor.py
│       │   ├── policy.py
│       │   ├── request_builder.py
│       │   └── target_registry.py
│       ├── llm/
│       │   ├── __init__.py
│       │   ├── generator.py
│       │   ├── mock.py
│       │   ├── ollama.py
│       │   ├── prompts.py
│       │   └── provider.py
│       ├── openapi/
│       │   ├── __init__.py
│       │   ├── loader.py
│       │   ├── normalizer.py
│       │   ├── resolver.py
│       │   └── validator.py
│       └── security_tests/
│           ├── __init__.py
│           ├── applicability.py
│           ├── catalogue.py
│           └── features.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── harness.py
│   ├── test_applicability.py
│   ├── test_catalogue.py
│   ├── test_execution_routes.py
│   ├── test_execution_safety.py
│   ├── test_executor.py
│   ├── test_generator.py
│   ├── test_generator_routes.py
│   ├── test_health.py
│   ├── test_llm_provider.py
│   ├── test_loader.py
│   ├── test_main.py
│   ├── test_normalizer.py
│   ├── test_prompts.py
│   ├── test_resolver.py
│   ├── test_security_test_models.py
│   ├── test_security_test_routes.py
│   ├── test_spec_routes.py
│   └── fixtures/
│       ├── petstore_openapi.yaml
│       ├── invalid_yaml.yaml
│       └── swagger2_spec.json
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Configuration Variables

Configure settings in `.env`:

```env
# Application Configuration
APP_NAME=AutoRedTeam
ENVIRONMENT=development
DEBUG=true
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

# LLM Configuration
LLM_PROVIDER=mock          # Options: "mock" (CI/Offline) or "ollama" (Local LLM)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
LLM_TIMEOUT_SECONDS=30
LLM_TEMPERATURE=0.2
LLM_MAX_TOKENS=2048

# Controlled Security Execution Settings
EXECUTION_TIMEOUT_SECONDS=10
MAX_REQUEST_BODY_BYTES=65536
MAX_RESPONSE_BYTES=1048576
FOLLOW_REDIRECTS=false
MAX_REDIRECTS=0
ALLOWED_TARGET_HOSTS=localhost,127.0.0.1,testserver

# Target Base URLs
TARGET_VAMPI_URL=http://localhost:8001
TARGET_JUICE_SHOP_URL=http://localhost:3000
TARGET_DVWA_URL=http://localhost:8080
```

---

## API Usage Examples

### 1. List Registered Controlled Targets

```bash
curl -X GET "http://localhost:8000/api/v1/targets" \
  -H "accept: application/json"
```

### 2. Execute a Generated Security Test

```bash
curl -X POST "http://localhost:8000/api/v1/executions" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "vampi-local",
    "generated_test": { ... }
  }'
```

**Example Response**:

```json
{
  "execution_id": "exec_a1b2c3d4e5f6",
  "target_id": "vampi-local",
  "generated_test_id": "gen_users_GET_AUTH-001",
  "status": "COMPLETED",
  "started_at": "2026-08-12T20:20:00Z",
  "completed_at": "2026-08-12T20:20:00.120Z",
  "duration_ms": 120.0,
  "request_evidence": {
    "method": "GET",
    "target_id": "vampi-local",
    "path": "/users",
    "headers": {
      "Accept": "application/json",
      "Authorization": "[REDACTED]"
    }
  },
  "response_evidence": {
    "status_code": 401,
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"error\": \"Unauthorized\"}",
    "body_size": 25,
    "duration_ms": 115.0,
    "final_url_host": "localhost",
    "truncated": false
  },
  "policy_decision": {
    "allowed": true,
    "reason": "Execution request satisfies all safety policy rules."
  }
}
```

---

## Running Tests

Execute the complete test suite (runs offline using `MockLLMProvider` and isolated `harness_app`):

```bash
pytest
```

---

## Known Limitations & Safety Boundaries (Phase 5)

* **No Vulnerability Classification**: Execution results contain raw observations (`status_code`, `response_evidence`). The executor does **not** classify responses as vulnerabilities (e.g. `SQLi`, `BOLA`).
* **Controlled Target Scope**: Execution is strictly restricted to pre-registered target IDs (`target_id`). Arbitrary public URLs, network scanning, or external targets are rejected by safety policies.
* **No Container Orchestration / Tool Manipulation**: Phase 5 does not provision arbitrary Docker containers or execute shell commands.

---

## Roadmap

* **Phase 1**: Project Foundation & Repository Readiness (Done)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Done)
* **Phase 3**: Security Test Model & Test Catalogue (Done)
* **Phase 4**: LLM Security Test-Generation Agent (Done)
* **Phase 5**: Controlled Security Test Execution Engine (Done)
* **Phase 6**: Response Analysis & Vulnerability Reporting (Future)
