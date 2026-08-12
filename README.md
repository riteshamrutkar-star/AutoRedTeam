# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

---

## Overview

AutoRedTeam is an autonomous LLM red-teaming research prototype designed to ingest API specifications, normalize them into structured domain models, and model security tests for evaluation in controlled environments.

* **Phase 1**: Project Foundation & Repository Readiness (Completed)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Completed)
* **Phase 3**: Security Test Model & Test Catalogue (Completed)

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
* **Effective Security Requirements**: Implements global-vs-operation security inheritance semantics.
* **Ingestion API**: `POST /api/v1/specifications/parse` and `POST /api/v1/specifications/validate` endpoints.

### Phase 3: Security Test Model & Catalogue
* **Typed Security Domain Model**: Structured `SecurityTestCase`, `TestTemplate`, `ApplicableTestResult`, `TestTarget`, `TestStrategy`, `InputSpecification`, `ExpectedBehavior`, and `EvidenceRequirements`.
* **Catalogue / Instance Separation**: Keeps catalogue templates immutable (`TestTemplate`) while generating endpoint-specific test results (`ApplicableTestResult`).
* **Feature Extraction**: Centralized parameter and endpoint feature extractor (`extract_endpoint_features`) analyzing schema types, formats, locations, and constraints.
* **Deterministic Applicability Engine**: Evaluates `NormalizedApiSpec` against catalogue prerequisites and returns reproducible test results with structured applicability reasons.
* **Security Test API**: `GET /api/v1/security-tests/catalogue` and `POST /api/v1/security-tests/applicable` endpoints.

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
│   │       ├── security_tests.py
│   │       └── specifications.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── exceptions.py
│   │   └── logging.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── security_test.py
│   │   └── spec.py
│   └── services/
│       ├── __init__.py
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
│   ├── test_health.py
│   ├── test_loader.py
│   ├── test_main.py
│   ├── test_normalizer.py
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

## Local Development Setup

### 1. Prerequisites
* Python 3.11+
* Docker & Docker Compose (optional)

### 2. Environment Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Running the Application

```bash
uvicorn app.main:app --reload --port 8000
```

Access:
* **Interactive API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## API Endpoints Usage

### 1. Get Security Test Catalogue

```bash
curl -X GET "http://localhost:8000/api/v1/security-tests/catalogue" \
  -H "accept: application/json"
```

### 2. Evaluate Applicable Security Tests

```bash
# First parse an OpenAPI spec to get NormalizedApiSpec JSON
curl -X POST "http://localhost:8000/api/v1/specifications/parse" \
  -F "file=@tests/fixtures/petstore_openapi.yaml" > spec.json

# Pass NormalizedApiSpec to /security-tests/applicable
curl -X POST "http://localhost:8000/api/v1/security-tests/applicable" \
  -H "Content-Type: application/json" \
  -d @spec.json
```

---

## Running Tests

Execute the complete test suite:

```bash
pytest
```

---

## Known Limitations & Design Boundaries (Phase 3)

* **Static Security Modeling Only**: The catalogue contains abstract test definitions and mutation strategies. It does **not** generate executable attack payloads (e.g. SQLi/XSS strings).
* **No Test Execution**: Does not make network calls or execute HTTP requests against target servers.
* **No OWASP Finding Classification**: Test categories are generic functional categories (`AUTHENTICATION`, `AUTHORIZATION`, `INPUT_VALIDATION`), not OWASP API Top 10 vulnerability classifications.

---

## Roadmap

* **Phase 1**: Project Foundation & Repository Readiness (Done)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Done)
* **Phase 3**: Security Test Model & Test Catalogue (Done)
* **Phase 4**: Security Test Generation & Payload Reasoning (Future)
* **Phase 5**: Execution Engine & Sandbox Execution (Future)
* **Phase 6**: Response Analysis & Vulnerability Reporting (Future)
