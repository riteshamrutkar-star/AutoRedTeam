# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

---

## Overview

AutoRedTeam is an autonomous LLM red-teaming research prototype designed to ingest API specifications, normalize them into structured domain models, model security tests, and instantiate concrete, declarative test plans using LLM reasoning.

* **Phase 1**: Project Foundation & Repository Readiness (Completed)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Completed)
* **Phase 3**: Security Test Model & Test Catalogue (Completed)
* **Phase 4**: LLM Security Test-Generation Agent (Completed)

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
  Focused Prompt Builder (prompts.py)
         ↓
  Framework-Independent LLM Provider (Ollama / Mock)
         ↓
  Post-LLM Anti-Hallucination Validator (generator.py)
         ↓
  GeneratedSecurityTest (Phase 4)
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
│   │   ├── generated_test.py
│   │   ├── security_test.py
│   │   └── spec.py
│   └── services/
│       ├── __init__.py
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
│   ├── test_applicability.py
│   ├── test_catalogue.py
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
```

---

## API Usage Examples

### 1. Check LLM Provider Health

```bash
curl -X GET "http://localhost:8000/api/v1/llm/health" \
  -H "accept: application/json"
```

**Example Response**:

```json
{
  "status": "ok",
  "provider": "mock",
  "model": "mock-v1",
  "available": true
}
```

### 2. Generate Security Test Plans

```bash
# Parse spec
curl -X POST "http://localhost:8000/api/v1/specifications/parse" \
  -F "file=@tests/fixtures/petstore_openapi.yaml" > spec.json

# Get applicable test candidates
curl -X POST "http://localhost:8000/api/v1/security-tests/applicable" \
  -H "Content-Type: application/json" \
  -d @spec.json > candidates.json

# Generate concrete security test plans using configured LLM
curl -X POST "http://localhost:8000/api/v1/security-tests/generate" \
  -H "Content-Type: application/json" \
  -d "{\"spec\": $(cat spec.json), \"applicable_tests\": $(cat candidates.json)}"
```

---

## Running Tests

Execute the complete test suite (runs offline using `MockLLMProvider`):

```bash
pytest
```

---

## Known Limitations & Safety Boundaries (Phase 4)

* **No Execution**: Generated tests are declarative test plans (`GeneratedSecurityTest`). They are **not** executed against any target application in Phase 4.
* **Bounded Generation**: Test generation is strictly constrained by the candidate `ApplicableTestResult` list and target `NormalizedApiSpec`. The LLM cannot invent un-declared endpoints, parameters, or schema properties.
* **Model Confidence**: The `confidence` field represents model-reported generation confidence (0.0 to 1.0), NOT vulnerability probability.
* **No OWASP Vulnerability Classification**: Test plans are classified by generic functional categories (`AUTHENTICATION`, `AUTHORIZATION`, `INPUT_VALIDATION`), not OWASP API Top 10 vulnerability findings.

---

## Roadmap

* **Phase 1**: Project Foundation & Repository Readiness (Done)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Done)
* **Phase 3**: Security Test Model & Test Catalogue (Done)
* **Phase 4**: LLM Security Test-Generation Agent (Done)
* **Phase 5**: Execution Engine & Sandbox Execution (Future)
* **Phase 6**: Response Analysis & Vulnerability Reporting (Future)
