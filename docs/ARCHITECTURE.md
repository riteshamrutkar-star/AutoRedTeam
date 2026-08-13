# AutoRedTeam — System Architecture & Component Design

**Version:** 1.0.0  
**Phase:** 10 (Final Prototype Integration)

---

## 1. System Pipeline Overview

AutoRedTeam is an autonomous LLM red-teaming and API security-testing research prototype. The system processes OpenAPI specifications through a multi-stage deterministic and LLM-assisted testing pipeline:

```text
OpenAPI Specification (JSON / YAML)
             │
             ▼
[Phase 2] OpenAPI Intelligence ($ref resolution & NormalizedApiSpec)
             │
             ▼
[Phase 3] Security Test Model (Applicability Rules & Catalogue)
             │
             ▼
[Phase 4] LLM Security Test Generator (Mock / Ollama & Schema Validation)
             │
             ▼
[Phase 5] Controlled Execution Sandbox (SSRF / Network Policy / Request Limits)
             │
             ▼
[Phase 6] Vulnerability Analyzer (Evidence Analysis & OWASP 2023 Mapping)
             │
             ▼
[Phase 7] Adaptive Feedback Loop (Information-Gain Ranking & Follow-up Chain)
             │
             ▼
[Phase 8] Evaluation Engine (Spec-Relative Coverage, Discovery, Timing & Baseline)
             │
             ▼
[Phase 9] Dashboard & Research Reporting (In-Memory Store, JSON/CSV Export & UI)
```

---

## 2. Core Modules & Responsibilities

| Module | Location | Primary Responsibilities |
| :--- | :--- | :--- |
| **Ingestion** | `app/services/openapi/` | Ingests, parses, validates, and normalizes OpenAPI 3.x specifications into `NormalizedApiSpec`. Resolves local `$ref` pointers deterministically. |
| **Catalogue** | `app/services/security_tests/` | Maintains versioned security test templates (`TestTemplate`) and feature extraction rules to evaluate endpoint applicability (`ApplicableTestResult`). |
| **LLM Provider** | `app/services/llm/` | Abstracts LLM providers (Mock & Ollama). Formats security prompts and validates generated tests (`GeneratedSecurityTest`) against strict JSON schemas. |
| **Execution** | `app/services/execution/` | Executes test plans against registered targets (`TargetAllowlist`). Enforces strict SSRF protections, timeout limits, response size limits, and header redactions. |
| **Security Analysis**| `app/services/security_analysis/` | Evaluates `ExecutionResult` evidence to produce `SecurityFinding` objects with severity, confidence factors, and OWASP API Top 10 (2023) classifications. |
| **Adaptive Loop** | `app/services/adaptive/` | Manages adaptive testing sessions (`AdaptiveSessionManager`). Computes information gain, prioritizes follow-up tests, deduplicates executions, and enforces session budgets. |
| **Evaluation** | `app/services/evaluation/` | Deterministically calculates spec-relative coverage, TP/FP/FN discovery metrics, TTFV/TTFKV timing, and baseline run comparisons (`EvaluationResult`). |
| **Reporting & UI** | `app/services/reporting/`, `app/templates/` | Stores active evaluation results in memory (`EvaluationStore`). Formats read-only view models, exports research JSON/CSV artifacts, and serves the single-page HTML dashboard. |

---

## 3. Security Boundaries & Guardrails

1. **Target Lock & Allowlist**: Execution is strictly restricted to registered target endpoints in `TargetAllowlist`. Arbitrary external URLs and unlisted hosts are rejected immediately.
2. **SSRF & Network Controls**: HTTP redirects are disabled by default. Private IP ranges and loopback bypasses are validated prior to every execution step.
3. **LLM Governance**: The LLM acts purely in an advisory capability. Generated security tests must pass schema validation before execution. LLM recommendations cannot override Phase 3 applicability rules, target boundaries, or execution safety policies.
4. **Read-Only Dashboard**: The reporting and dashboard UI (`/dashboard`) operates exclusively on completed evaluation objects stored in memory. Dashboard controls cannot trigger live network execution or alter configuration.
5. **No Secret Exposure**: Header redactions mask authorization tokens and sensitive credentials in evidence snippets, log files, and research export reports.
