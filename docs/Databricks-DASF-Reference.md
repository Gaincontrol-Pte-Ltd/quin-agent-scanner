# Databricks AI Security Framework (DASF) v3.0 — Quick Reference

**Source:** Databricks — AI Security Framework Compendium
**Version:** 3.0
**Full document:** `Databricks_DASF_v3.0.xlsx` (in this folder)

Use DASF as a **comprehensive control catalog** during risk assessment. DASF covers the entire AI/ML lifecycle and maps risks to specific mitigation controls, with cross-references to OWASP LLM Top 10, OWASP Agentic AI, MITRE ATLAS, NIST 800-53, ISO 42001, ISO 27001, HITRUST, ENISA, and the EU AI Act.

---

## When to Apply

DASF should be consulted for **every assessment** regardless of risk tier. It is especially valuable for:
- Identifying lifecycle-stage-specific risks the OWASP frameworks may not cover (data operations, model management, serving infrastructure)
- Sourcing specific mitigation controls (DASF 1–67+) with implementation guidance
- Cross-referencing to compliance frameworks (NIST, ISO, HITRUST, EU AI Act)
- Assessing systems deployed on Databricks (Bedrock, Foundry, Databricks-native controls map directly)

---

## DASF Structure — Key Sheets

### Sheet: "AI Lifecycle Risks" (98 risks)
The primary risk catalog. Each row contains:

| Column | Content |
|---|---|
| **Risk ID** | e.g., Raw Data 1.1, Data Prep 2.3, Model 7.1, Agents — Core 13.1, Agents — Tools MCP Server 13.16 |
| **System Component** | Lifecycle stage: Data operations, Data preparation, Datasets, Training, Evaluation, Model, Model Management, Model Serving, Platform, Agents — Core, Agents — Tools MCP Server, Agents — Tools MCP Client |
| **Risk** | Short risk title |
| **Risk Description** | Detailed explanation |
| **Mitigation Controls IDs** | DASF control IDs that address this risk |
| **Mitigation Controls** | Full control descriptions |
| **Deployment Models** | Applicability flags: Predictive ML, RAG-LLMs, Fine-tuned LLMs, Pre-trained LLMs, Foundational LLMs, External Models, Agentic AI |
| **Risk Impacts** | Initial AI risk impacts + business impacts |
| **Framework Mapping** | Cross-references to: MITRE ATLAS, MITRE ATT&CK, OWASP LLM Top 10 2025, OWASP ML Top 10, OWASP Agentic AI, NIST 800-53 Rev 5, HITRUST, ENISA, ISO 42001, ISO 27001, EU AI Act, CSA MCP Security, OWASP MCP Top 10 |

### Sheet: "Databricks AI Mitigation Controls" (74 controls)
The control catalog. Each DASF control includes:
- Control ID (DASF 1 through DASF 67+)
- Control description and implementation details
- Databricks-specific implementation (shared responsibility, product reference, AWS/Azure/GCP docs)
- Framework mappings to NIST, ISO, OWASP, MITRE

### Sheet: "DASF Risk Applicability"
Lets you filter risks by deployment model (e.g., show only risks relevant to RAG-LLMs + External Models).

### Sheet: "DASF Control Applicability"
Lets you filter controls by deployment model.

### Sheet: "Third-Party Tools"
Lists security tools (model scanners, vulnerability tools) useful for implementing DASF controls.

---

## AI Lifecycle Stages Covered by DASF

| Stage | Risk ID Prefix | Example Risks |
|---|---|---|
| **Raw Data** | 1.x | Insufficient access controls, missing data classification, data lineage gaps |
| **Data Preparation** | 2.x | Data poisoning during preprocessing, inadequate anonymization, bias in feature engineering |
| **Datasets** | 3.x | Unauthorized dataset access, data leakage between training/serving, stale or drift in datasets |
| **Training** | 4.x–5.x | Training infrastructure compromise, hyperparameter manipulation, compute resource abuse |
| **Evaluation** | 6.x | Insufficient evaluation coverage, biased benchmarks, missing adversarial testing |
| **Model** | 7.x | Model theft, backdoors in weights, serialization vulnerabilities |
| **Model Management** | 8.x | Unauthorized model registry access, missing model versioning, inadequate rollback |
| **Model Serving — Inference Requests** | 9.x | Prompt injection at inference, unauthorized API access, rate limiting gaps, input validation |
| **Model Serving — Inference Response** | 10.x | Sensitive data in responses, insecure output handling, response manipulation |
| **Platform** | 12.x | Platform misconfigurations, network exposure, secret management failures |
| **Agents — Core** | 13.1–13.15 | Goal hijacking, excessive permissions, uncontrolled autonomy, missing human-in-the-loop, identity escalation |
| **Agents — Tools MCP Server** | 13.16–13.24 | MCP server compromise, tool poisoning, insecure tool APIs, over-permissioned MCP integrations |
| **Agents — Tools MCP Client** | 13.25–13.34 | Client-side injection, insecure tool invocation, unvalidated tool responses |

---

## How to Use in Assessments

### During Phase 2 (Threat Modeling):
1. Open `Databricks_DASF_v3.0.xlsx` → "DASF Risk Applicability" sheet
2. Filter by the deployment model(s) applicable to the assessed system (RAG-LLMs, Agentic AI, etc.)
3. Review each applicable risk — check if it is already covered by the OWASP LLM/Agentic mapping, or if it adds new lifecycle-specific risks not in OWASP
4. Add any additional DASF risks to the Threat Applicability Table with prefix "DASF-" (e.g., DASF-1.1, DASF-13.16)

### During Phase 3 (Risk Scoring):
- Use DASF Risk Impacts and Business Impacts columns to inform Impact scoring
- Reference DASF Mitigation Controls to assess whether existing controls reduce Likelihood

### During Phase 5 (Remediation):
1. Open "Databricks AI Mitigation Controls" sheet
2. For each identified risk, look up the recommended DASF controls
3. Include DASF Control IDs in the Remediation Roadmap alongside OWASP mitigations
4. Use the framework mapping columns to provide compliance cross-references (NIST, ISO) in the remediation justification

---

## Key DASF Controls for Common Agentic Risks

| Agentic Risk Area | Key DASF Controls |
|---|---|
| Agent Authentication | DASF 1 (SSO + MFA), DASF 2 (User sync), DASF 67 (Federated auth) |
| Agent Permissions | DASF 5 (Access control), DASF 51 (Secure sharing) |
| MCP Server Security | DASF controls mapped to risks 13.16–13.24 |
| Audit & Observability | DASF 55 (Monitor audit logs) |
| Data Isolation | DASF 59 (Clean rooms), DASF 4 (Private link) |
| Network Security | DASF 3 (IP access lists), DASF 4 (Private link) |
