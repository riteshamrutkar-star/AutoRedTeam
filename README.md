# AutoRedTeam — Autonomous API Red-Teaming & Security Test Generation Prototype

**Version:** 1.0.0 (Phase 10 — Feature-Complete Research Prototype)

AutoRedTeam is an autonomous LLM-driven API red-teaming and security-testing research prototype. It ingests OpenAPI 3.x specifications, evaluates security test applicability, generates schema-validated test plans using LLM abstractions (Mock / Ollama), executes bounded tests against registered target allowlists, analyzes evidence to classify vulnerabilities under OWASP API Top 10 (2023), executes adaptive follow-up chains, and generates research evaluation metrics and reporting visualizations.

---

## 1. Quickstart (Local Python Setup)

### Step 1: Clone & Set Up Environment
```bash
git clone https://github.com/user/AutoRedTeam.git
cd AutoRedTeam

python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### Step 2: Configure Environment Settings
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Step 3: Run Pytest Suite
```bash
pytest
```

### Step 4: Start AutoRedTeam Application Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- **API Documentation (Swagger UI):** `http://localhost:8000/docs`
- **Health Check Endpoint:** `http://localhost:8000/health`
- **Research Dashboard UI:** `http://localhost:8000/dashboard`

---

## 2. Docker Setup

### Build Docker Image
```bash
docker build -t autoredteam-phase10:latest .
```

### Run Docker Container
```bash
docker run -d -p 8000:8000 --name autoredteam-container autoredteam-phase10:latest
```

### Verify Container Health & Dashboard
```bash
curl http://localhost:8000/health
curl http://localhost:8000/dashboard
```

---

## 3. Complete API Endpoint Catalog

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Application status, version (`1.0.0`), and environment metadata |
| `GET` | `/dashboard` | HTML Single-Page Security Research Dashboard |
| `POST` | `/api/v1/specifications/parse` | Parse, resolve `$ref`, and normalize OpenAPI specification |
| `POST` | `/api/v1/specifications/validate` | Validate OpenAPI specification syntax and structure |
| `GET` | `/api/v1/security-tests/catalogue` | List all deterministic test templates in catalogue |
| `POST` | `/api/v1/security-tests/applicable` | Determine applicable security tests for spec |
| `POST` | `/api/v1/security-tests/generate` | Generate schema-validated LLM test plan |
| `GET` | `/api/v1/llm/health` | Check LLM provider availability (Mock / Ollama) |
| `GET` | `/api/v1/targets` | List registered targets and network policy allowlist |
| `POST` | `/api/v1/executions` | Execute bounded security test against registered target |
| `POST` | `/api/v1/security-analysis/analyze` | Analyze execution evidence & classify OWASP finding |
| `GET` | `/api/v1/security-analysis/owasp` | List OWASP API Top 10 (2023) taxonomy mapping |
| `POST` | `/api/v1/adaptive/sessions` | Create new adaptive testing session |
| `GET` | `/api/v1/adaptive/sessions/{id}` | Get adaptive session trace & status |
| `POST` | `/api/v1/adaptive/sessions/{id}/step`| Execute single step in adaptive testing session |
| `POST` | `/api/v1/adaptive/sessions/{id}/run` | Run bounded adaptive testing loop |
| `POST` | `/api/v1/evaluation/compute` | Compute coverage, discovery, TTFV, & timing metrics |
| `POST` | `/api/v1/evaluation/compare` | Compare two evaluation runs side-by-side |
| `GET` | `/api/v1/evaluation/metrics` | List supported evaluation metrics metadata |
| `POST` | `/api/v1/reporting/context` | Set active reporting session evaluation context |
| `GET` | `/api/v1/reporting/summary` | Get executive dashboard summary KPI cards |
| `GET` | `/api/v1/reporting/findings` | Get filterable security findings list |
| `GET | `/api/v1/reporting/coverage` | Get spec-relative unique coverage metrics |
| `GET` | `/api/v1/reporting/adaptive` | Get adaptive trace timeline & decision provenance |
| `GET` | `/api/v1/reporting/comparison` | Get side-by-side strategy comparison metrics |
| `GET` | `/api/v1/reporting/export/json` | Download complete JSON research export artifact |
| `GET` | `/api/v1/reporting/export/csv` | Download tabular CSV report of security findings |
| `GET` | `/api/v1/reporting/manifest` | Get machine-readable research reproducibility manifest |

---

## 4. Documentation Index

- **[System Architecture](docs/ARCHITECTURE.md)**: Detailed module breakdown, pipeline contracts, and security guardrails.
- **[Research Demonstration Guide](docs/DEMO.md)**: Step-by-step walkthrough for research paper presentations (Demos A–G).
- **[Research Paper Methodology](docs/RESEARCH.md)**: Evaluation formulas, OWASP taxonomy, baseline comparison, and prototype limitations.

---

## 5. Security & Safety Disclaimer

**Research Disclaimer:** AutoRedTeam is designed strictly for controlled research and testing against authorized, local target applications. Testing against unauthorized external entities or unauthorized networks is prohibited.
