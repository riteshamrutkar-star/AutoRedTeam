# AutoRedTeam — Research Paper Methodology & Metric Definitions

**Version:** 1.0.0  
**Phase:** 10 (Final Prototype Integration)

---

## 1. Research Methodology

AutoRedTeam evaluates autonomous API red-teaming through a dual-strategy approach:

1. **Static Test Generation**: Deterministic template applicability combined with schema-guided LLM request plan generation.
2. **Adaptive Feedback Loop**: Information-gain prioritized follow-up testing driven by evidence gaps from prior execution results.

All testing operates in a **controlled environment** against explicitly registered target applications (e.g. VAmPI, OWASP Juice Shop, DVWA).

---

## 2. Evaluation Metric Definitions

### 2.1 Spec-Relative Unique Coverage
Coverage metrics measure the fraction of unique specification elements exercised by executed tests relative to applicable test templates:

- **Endpoint Coverage**: $\frac{|\text{Tested Endpoints}|}{|\text{Total Endpoints in Spec}|}$
- **Method Coverage**: $\frac{|\text{Tested HTTP Methods}|}{|\text{Total Methods in Spec}|}$
- **Parameter Coverage**: $\frac{|\text{Tested Parameters}|}{|\text{Total Parameters in Spec}|}$
- **Category Coverage**: $\frac{|\text{Tested Phase 3 Categories}|}{|\text{Applicable Categories in Spec}|}$

---

### 2.2 Vulnerability Discovery Metrics
Vulnerability discovery is evaluated against ground-truth security datasets:

- **Ground-Truth Match Eligibility**: Only `CONFIRMED` findings matching target ID (`finding.target_id == ground_truth.target_id`), endpoint path, method, and category/aliases are counted.
- **Unique Discovered Vulnerabilities**: Count of unique `vulnerability_identifier` entries matched in ground truth.
- **Discovery Rate**: $\frac{\text{Unique Discovered Vulnerabilities}}{\text{Total Known Ground-Truth Vulnerabilities}}$
- **False-Positive Rate**: Computed over eligible confirmed findings only when `ground_truth.scope_complete == True`.

---

### 2.3 Timing Metrics
- **Time to First Vulnerability (TTFV)**: Elapsed duration from run start to the execution completion of the first `CONFIRMED` finding.
- **Time to First Known Vulnerability (TTFKV)**: Elapsed duration from run start to the execution completion of the first `CONFIRMED` finding matching a ground-truth entry.

---

## 3. OWASP API Security Top 10 (2023 Edition) Mapping

Phase 6 implements positive evidence-based classifiers for active categories:

| Category ID | Category Name | Classifier Active Status |
| :--- | :--- | :--- |
| **API1:2023** | Broken Object Level Authorization (BOLA) | Active Classifier |
| **API2:2023** | Broken Authentication | Active Classifier |
| **API3:2023** | Broken Object Property Level Authorization | Active Classifier |
| **API4:2023** | Unrestricted Resource Consumption | Registered Taxonomy Only |
| **API5:2023** | Broken Function Level Authorization | Active Classifier |
| **API6:2023** – **API10:2023** | Advanced Misconfiguration & SSRF | Registered Taxonomy Only |

---

## 4. Prototype Limitations

1. **Controlled Environment Scope**: Security testing must be conducted against authorized local targets.
2. **In-Memory State**: Active evaluation results and reporting contexts are maintained in memory for research presentation (no persistent SQL database).
3. **LLM Provider Variability**: Mock provider yields 100% deterministic test plans; live Ollama providers depend on model context capacity.
