# AutoRedTeam — Research Demonstration Guide

**Version:** 1.0.0  
**Phase:** 10 (Final Prototype Integration)

This document provides a step-by-step walkthrough for demonstrating AutoRedTeam's capabilities during research paper presentations and evaluation experiments.

---

## Controlled Demonstration Workflows

### Demo A: OpenAPI Ingestion & Feature Extraction
1. **Endpoint:** `POST /api/v1/specifications/parse`
2. **Action:** Upload `tests/fixtures/petstore_openapi.yaml`.
3. **Verification:** Observe normalized endpoints, authentication requirements, path parameters, and request body schema definitions in `NormalizedApiSpec`.

---

### Demo B: Security Test Applicability & LLM Test Generation
1. **Endpoint:** `POST /api/v1/security-tests/applicable`
2. **Action:** Pass the parsed `NormalizedApiSpec`.
3. **Verification:** Inspect deterministic applicability results (`BOLA`, `Broken Authentication`, `Mass Assignment`).
4. **Endpoint:** `POST /api/v1/security-tests/generate`
5. **Verification:** Verify generated `GeneratedSecurityTest` containing declarative `RequestPlan` and schema-validated `InputMutation`.

---

### Demo C: Controlled Execution Sandbox & Policy Verification
1. **Endpoint:** `POST /api/v1/executions`
2. **Action:** Submit `GeneratedSecurityTest` targeting registered `vampi-local` target (`http://localhost:8001`).
3. **Verification:** Confirm bounded HTTP execution (`status_code`, `response_evidence`, header redactions). Test an invalid target URL to prove SSRF allowlist rejection.

---

### Demo D: Evidence Analysis & OWASP Category Mapping
1. **Endpoint:** `POST /api/v1/security-analysis/analyze`
2. **Action:** Submit `ExecutionResult` and `GeneratedSecurityTest`.
3. **Verification:** Inspect output `SecurityFinding` showing `status` (`CONFIRMED` / `SUSPECTED`), severity, confidence factors, and OWASP API Security Top 10 (2023) classification (`API1:2023`, `API2:2023`).

---

### Demo E: Adaptive Testing Loop
1. **Endpoint:** `POST /api/v1/adaptive/sessions`
2. **Action:** Initialize adaptive testing session.
3. **Endpoint:** `POST /api/v1/adaptive/sessions/{session_id}/run`
4. **Verification:** Observe iterative follow-up testing (`SUSPECTED` → targeted follow-up → `CONFIRMED`). Verify stop conditions and deduplication checks.

---

### Demo F: Deterministic Evaluation Calculation
1. **Endpoint:** `POST /api/v1/evaluation/compute`
2. **Action:** Submit recorded testing artifacts and ground-truth dataset (`tests/fixtures/evaluation_ground_truth.json`).
3. **Verification:** Inspect spec-relative coverage percentages, TP/FP discovery metrics, TTFV timing, and execution efficiency scores.

---

### Demo G: Dashboard & Research Artifact Export
1. **UI Route:** `GET /dashboard`
2. **Action:** Open web dashboard in browser.
3. **Verification:** Inspect KPI cards, filterable findings table, coverage bars, OWASP active rules, adaptive session trace, and side-by-side strategy comparison.
4. **Action:** Click **Download JSON Export** or **Download Findings CSV**.
