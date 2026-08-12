# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

---

## Overview

AutoRedTeam is an autonomous LLM red-teaming research prototype designed to ingest API specifications, normalize them into structured domain models, model security tests, generate concrete test plans using LLM reasoning, execute test plans safely against explicitly registered targets, and perform deterministic evidence analysis and OWASP API Top 10 (2023) vulnerability classification.

* **Phase 1**: Project Foundation & Repository Readiness (Completed)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Completed)
* **Phase 3**: Security Test Model & Test Catalogue (Completed)
* **Phase 4**: LLM Security Test-Generation Agent (Completed)
* **Phase 5**: Controlled Security Test Execution Engine (Completed)
* **Phase 6**: Vulnerability Detection, Evidence Analysis & OWASP Mapping (Completed)

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
  Streamed Async HTTP Client against Target (executor.py - Phase 5)
         ↓
  ExecutionResult Evidence (Phase 5)
         ↓
  Evidence Analyzer & Rules Engine (analyzer.py - Phase 6)
         ↓
  OWASP API Security Top 10 (2023) Mapper (owasp_mapper.py - Phase 6)
         ↓
  Deterministic Severity & Confidence Engines (severity.py, confidence.py - Phase 6)
         ↓
  Machine-Readable SecurityFinding Output (Phase 6)
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

### Phase 6: Vulnerability Detection & OWASP 2023 Mapping
* **Evidence-Driven Classification**: Evaluates observed HTTP response evidence against expected security behaviors using 100% deterministic rule logic (`AuthenticationRule`, `AuthorizationRule`, `PropertyAccessRule`, `InputValidationRule`).
* **OWASP API Security Top 10 — 2023 Mapping**: Maps verified findings to official OWASP API Top 10 (2023 Edition) categories (`API1:2023` to `API10:2023`).
* **Explicit Finding Statuses**: `CONFIRMED`, `SUSPECTED`, `INCONCLUSIVE`, `NEGATIVE`. HTTP 500 errors without security evidence evaluate to `INCONCLUSIVE`.
* **Deterministic Severity Matrix**: Derives severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) independently from risk impact, security boundary crossed, and data sensitivity.
* **Deterministic Confidence Factors**: Calculates confidence score (0.0 to 1.0) derived from evidence strength, behavior consistency, test specificity, and ambiguity penalties.
* **Analysis API Endpoints**: `POST /api/v1/security-analysis/analyze` and `GET /api/v1/security-analysis/owasp`.

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
│   │       ├── security_analysis.py
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
│   │   ├── finding.py
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
│       ├── security_analysis/
│       │   ├── __init__.py
│       │   ├── analyzer.py
│       │   ├── confidence.py
│       │   ├── owasp_mapper.py
│       │   ├── severity.py
│       │   └── rules/
│       │       ├── __init__.py
│       │       ├── authentication.py
│       │       ├── authorization.py
│       │       ├── base.py
│       │       ├── input_validation.py
│       │       └── property_access.py
│       └── security_tests/
│           ├── __init__.py
│           ├── applicability.py
│           ├── catalogue.py
│           └── features.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── harness.py
│   ├── test_analysis_routes.py
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
│   ├── test_owasp_mapper.py
│   ├── test_prompts.py
│   ├── test_resolver.py
│   ├── test_security_analyzer.py
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

# Classification Settings
CLASSIFIER_VERSION=v1
OWASP_API_TOP_10_VERSION=2023
```

---

## API Usage Examples

### 1. Get OWASP API Top 10 (2023) Taxonomy Definitions

```bash
curl -X GET "http://localhost:8000/api/v1/security-analysis/owasp" \
  -H "accept: application/json"
```

### 2. Analyze Execution Evidence & Generate Finding

```bash
curl -X POST "http://localhost:8000/api/v1/security-analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "generated_test": { ... },
    "execution_result": { ... }
  }'
```

**Example Output**:

```json
{
  "finding_id": "fnd_a1b2c3d4e5f6",
  "execution_id": "exec_12345",
  "generated_test_id": "gen_users_GET_AUTH-001",
  "template_id": "AUTH-001",
  "target_id": "vampi-local",
  "endpoint": "/users",
  "http_method": "GET",
  "status": "CONFIRMED",
  "title": "Broken Authentication",
  "description": "Endpoint returned successful HTTP 200 response for an unauthenticated request.",
  "category": "Broken Authentication",
  "owasp": {
    "taxonomy": "OWASP_API_TOP_10_2023",
    "category_id": "API2:2023",
    "category_name": "Broken Authentication",
    "rationale": "Endpoint failed to enforce authentication requirement on protected resource.",
    "secondary_categories": []
  },
  "severity": "HIGH",
  "severity_rationale": "Crossed authentication boundary, permitting unauthenticated access to protected endpoint.",
  "confidence": 0.98,
  "confidence_factors": {
    "evidence_strength": "STRONG",
    "behavior_consistency": 1.0,
    "test_specificity": 1.0,
    "expected_behavior_match": 0.8,
    "ambiguity_penalty": 0.0,
    "overall_score": 0.98
  },
  "evidence": {
    "execution_id": "exec_12345",
    "status_code": 200,
    "request_summary": { ... },
    "response_summary": {
      "status_code": 200,
      "body_size": 120,
      "final_url_host": "localhost",
      "truncated": false
    },
    "expected_status_codes": [401],
    "observed_indicators": ["HTTP_200_UNAUTHENTICATED_ACCESS", "AUTHENTICATION_BOUNDARY_BYPASS"]
  },
  "detection_reason": "Endpoint failed to enforce authentication requirement on protected resource.",
  "remediation_guidance": "Apply consistent authentication controls across all endpoints and properly validate access tokens.",
  "classifier_version": "v1"
}
```

---

## Running Tests

Execute the complete test suite (runs offline using `MockLLMProvider` and isolated `harness_app`):

```bash
pytest
```

---

## Known Limitations & Safety Boundaries (Phase 6)

* **No Adaptive Retesting / Multi-Round Feedback Loop**: Phase 6 processes single-pass execution evidence.
* **Deterministic Rules Only**: Classification decisions are grounded strictly in evidence analysis without LLM override.
* **No Database Persistence / Reporting UI**: Findings are output as machine-readable JSON objects without web dashboard UIs or database persistence.

---

## Roadmap

* **Phase 1**: Project Foundation & Repository Readiness (Done)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Done)
* **Phase 3**: Security Test Model & Test Catalogue (Done)
* **Phase 4**: LLM Security Test-Generation Agent (Done)
* **Phase 5**: Controlled Security Test Execution Engine (Done)
* **Phase 6**: Vulnerability Detection, Evidence Analysis & OWASP Mapping (Done)
