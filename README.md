# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

---

## Overview

AutoRedTeam is an autonomous LLM red-teaming research prototype designed to ingest API specifications, normalize them into structured domain models, and perform automated security testing in controlled environments.

* **Phase 1**: Project Foundation & Repository Readiness (Completed)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Completed)

---

## Features

### Phase 1: Core Foundation
* **FastAPI Skeleton**: Async web application with lifespan logging.
* **Centralized Configuration**: Environment-driven settings via `pydantic-settings`.
* **Structured Logging**: Standardized console log formatting.
* **System Health Endpoints**: `/` and `/health` readiness routes.
* **Docker Support**: Containerized deployment via `Dockerfile` and `docker-compose.yml`.

### Phase 2: OpenAPI/Swagger Ingestion & Intelligence
* **Multi-Format Ingestion**: Supports `.json`, `.yaml`, and `.yml` OpenAPI specifications.
* **OpenAPI 3.x Support**: Ingests and validates OpenAPI 3.0.x and 3.1.x documents. Rejects non-3.x specifications (e.g. Swagger 2.0).
* **Local Reference Dereferencing**: Resolves internal `$ref` pointers (e.g. `#/components/schemas/...`) with cycle protection.
* **Rich Schema Normalization**: Preserves primitive types, nested objects, array items, formats, enums, defaults, validation constraints, and raw schema objects.
* **Effective Security Requirements**: Implements global-vs-operation security inheritance semantics.
* **Ingestion API**: `POST /api/v1/specifications/parse` and `POST /api/v1/specifications/validate` endpoints.

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
│   │       └── specifications.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── exceptions.py
│   │   └── logging.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── spec.py
│   └── services/
│       ├── __init__.py
│       └── openapi/
│           ├── __init__.py
│           ├── loader.py
│           ├── normalizer.py
│           ├── resolver.py
│           └── validator.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_health.py
│   ├── test_loader.py
│   ├── test_main.py
│   ├── test_normalizer.py
│   ├── test_resolver.py
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

## Ingestion API Usage

### Parse and Normalize Specification

```bash
curl -X POST "http://localhost:8000/api/v1/specifications/parse" \
  -H "accept: application/json" \
  -F "file=@tests/fixtures/petstore_openapi.yaml"
```

**Example Response**:

```json
{
  "metadata": {
    "title": "PetStore Test API",
    "version": "1.2.0",
    "description": "Evaluation OpenAPI specification for AutoRedTeam testing."
  },
  "servers": [
    {
      "url": "https://api.petstore.example.com/v1",
      "description": "Production server"
    }
  ],
  "security_schemes": {
    "BearerAuth": {
      "type": "http",
      "scheme": "bearer",
      "bearer_format": "JWT"
    }
  },
  "endpoints": [
    {
      "path": "/users",
      "method": "GET",
      "operation_id": "listUsers",
      "summary": "List all users",
      "tags": ["Users"],
      "parameters": [
        {
          "name": "page",
          "location": "query",
          "required": false,
          "schema_def": {
            "type": "integer",
            "default": 1,
            "minimum": 1
          }
        }
      ],
      "security": [{"BearerAuth": []}]
    }
  ]
}
```

### Validate Specification

```bash
curl -X POST "http://localhost:8000/api/v1/specifications/validate" \
  -H "accept: application/json" \
  -F "file=@tests/fixtures/petstore_openapi.yaml"
```

**Example Response**:

```json
{
  "valid": true,
  "title": "PetStore Test API",
  "version": "1.2.0",
  "endpoint_count": 3
}
```

---

## Running Tests

Execute the complete test suite:

```bash
pytest
```

---

## Running with Docker

```bash
docker-compose up --build
```

---

## Known Limitations (Phase 2)

* **External References**: Only internal local `$ref` pointers (starting with `#/`) are resolved. External URL references are rejected with an explicit error.
* **Specification Version**: Exclusively supports OpenAPI 3.x. Swagger 2.0 specifications are rejected.

---

## Roadmap

* **Phase 1**: Project Foundation & Repository Readiness (Done)
* **Phase 2**: OpenAPI/Swagger Intelligence & Ingestion Layer (Done)
* **Phase 3**: Security Test-Case Modeling & Generation (Future)
* **Phase 4**: Sandboxed Execution Engine (Future)
* **Phase 5**: Response Analysis & Vulnerability Reporting (Future)
