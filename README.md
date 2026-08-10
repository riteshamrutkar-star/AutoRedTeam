# AutoRedTeam

Autonomous LLM-based API security testing and red-team research framework.

> [!NOTE]
> **Phase 1 Baseline**: This repository currently contains Phase 1: project foundation and repository readiness. Later phases will introduce OpenAPI ingestion, LLM reasoning, sandboxed execution, vulnerability classification, and reporting features.

---

## Features (Phase 1)

* **FastAPI Skeleton**: Async web framework setup with lifespan logging.
* **Centralized Configuration**: Environment-based settings management via `pydantic-settings`.
* **Structured Logging**: Standardized console log formatting across the app lifecycle.
* **Health & Root Endpoints**: `/` and `/health` endpoints for readiness checks.
* **Containerization**: `Dockerfile` and `docker-compose.yml` pre-configured.
* **Testing Setup**: `pytest` suite testing endpoint functionality.

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
│   │       └── health.py
│   └── core/
│       ├── __init__.py
│       ├── config.py
│       └── logging.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_health.py
│   └── test_main.py
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
* Docker & Docker Compose (optional for local container execution)

### 2. Environment Setup

Clone the repository and set up a virtual environment:

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

---

## Running the Application

### Running Locally with Uvicorn

```bash
uvicorn app.main:app --reload --port 8000
```

Access the API:
* **Root Endpoint**: [http://localhost:8000/](http://localhost:8000/)
* **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
* **Swagger UI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Running Tests

Run the test suite using `pytest`:

```bash
pytest
```

---

## Running with Docker

### Using Docker Compose

```bash
docker-compose up --build
```

### Using Docker Directly

```bash
docker build -t autoredteam:latest .
docker run -p 8000:8000 autoredteam:latest
```

---

## Roadmap / Future Phases

* **Phase 2**: OpenAPI/Swagger Specification Ingestion & Schema Parsing
* **Phase 3**: LLM-driven Test Case & Payload Generation
* **Phase 4**: Sandboxed Test Execution Engine
* **Phase 5**: Response Analysis & Vulnerability Classification (OWASP API Top 10)
* **Phase 6**: Coverage & Security Reporting Dashboard
