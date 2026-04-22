# OWASP MAESTRO — Multi-Agent System Threat Modelling Framework
## Quick Reference

**Source:** OWASP GenAI Security Project / Cloud Security Alliance
**Document:** *Agentic AI & MAS Threat Modelling Guide v1.0*, April 22, 2025
**Full document:** `OWASP_MAESTRO_MAS_Threat_Modelling_Guide_v1.pdf` (in this folder)

---

## What MAESTRO Is (and Is Not)

MAESTRO (**M**ulti-Agent **E**nvironment, **S**ecurity, **T**hreat, **R**isk, and **O**utcome) is a **threat modelling methodology**, not a threat taxonomy. It does not introduce competing threat IDs — it applies the existing **OWASP Agentic Security Initiative (ASI) threat taxonomy** through an **architectural/layered lens** specific to multi-agent systems.

**Use MAESTRO when:** The assessed system has true multi-agent architecture — multiple co-operating agents, orchestrator/sub-agent hierarchies, A2A delegation, or MCP-chained tool calls. MAESTRO surfaces cross-layer emergent threats that a pure checklist approach (LLM/ASI/MCP Top 10) can miss.

**Do NOT replace** the LLM/ASI/MCP/DASF framework checklist with MAESTRO — run both. MAESTRO is the deep-dive overlay for complex agentic systems.

---

## The Four Agentic Factors

MAESTRO organises threats around four properties that make agentic AI uniquely risky. Use these as lenses when assessing each layer:

| Factor | Description | Key Risk |
|--------|-------------|----------|
| **Non-Determinism** | LLMs produce variable outputs for identical inputs | Unpredictable agent behaviour; inconsistent policy enforcement |
| **Autonomy** | Agents act without step-by-step human approval | Errors and compromises propagate without intervention opportunity |
| **Agent Identity Management** | Agents authenticate to services and each other | Credential theft, impersonation, privilege escalation across agent chains |
| **Agent-to-Agent Communication** | Agents share context, delegate tasks, pass data | Poisoned information propagates; rogue agents inject malicious data |

---

## The 7 MAESTRO Layers

Map every component of the assessed system to one or more layers before performing threat analysis.

| Layer | Name | What It Covers | Key Assets at Risk |
|-------|------|----------------|--------------------|
| **1** | Foundation Models | LLMs and other ML models powering agents | Model weights, training data, inference outputs |
| **2** | Data Operations | RAG pipelines, vector databases, data retrieval, embeddings | Knowledge base integrity, embedding accuracy, retrieval fidelity |
| **3** | Agent Frameworks | Agent orchestration software, workflow definitions, tool integrations, plugin systems, inter-agent protocols | Workflow logic, tool invocation, agent state |
| **4** | Deployment Infrastructure | Cloud/on-prem servers, network, service accounts, APIs | Compute access, credential stores, network paths |
| **5** | Evaluation & Observability | Logging, monitoring, anomaly detection, audit trails, HITL review processes | Log integrity, anomaly detection accuracy, oversight mechanisms |
| **6** | Security & Compliance *(vertical)* | Access control policies, dynamic policy engines, identity management, regulatory compliance | Policy enforcement, RBAC, compliance posture |
| **7** | Agent Ecosystem | Other agents in the system, human users, external services, agent registries/marketplaces | Inter-agent trust, ecosystem integrity, supply chain |

> **Note:** Layer 6 (Security & Compliance) is a **vertical layer** — it spans all other layers and defines the security requirements that must be satisfied across the entire system.

---

## Core Threat Taxonomy (ASI T1–T17)

These are the base threats that MAESTRO maps to layers. They align with the OWASP Agentic Top 10 (ASI01–ASI10). Use ASI IDs in the Risk Register; use T-IDs for cross-reference with MAESTRO layer analysis.

| T-ID | Threat Name | OWASP ASI Equivalent | Primary Layer |
|------|------------|----------------------|---------------|
| T1 | Memory Poisoning | ASI06 | Layer 2/3 |
| T2 | Tool Misuse | ASI02 | Layer 3 |
| T3 | Privilege Compromise | ASI03 | Layer 4/6 |
| T4 | Resource Overload | ASI10 / LLM10 | Layer 4 |
| T5 | Cascading Hallucination Attacks | ASI08 / LLM09 | Layer 1 |
| T6 | Intent Breaking & Goal Manipulation | ASI01 / LLM01 | Layer 1/3 |
| T7 | Misaligned & Deceptive Behaviours | ASI09 | Layer 3 |
| T8 | Repudiation & Untraceability | ASI10 | Layer 5 |
| T9 | Data Exfiltration | LLM02 | Layer 2/3 |
| T10 | Overwhelming Human-in-the-Loop (HITL) | ASI09 | Layer 5 |
| T11 | Unexpected RCE and Code Attacks | ASI05 / LLM05 | Layer 3/4 |
| T12 | Agent Communication Poisoning | ASI07 | Layer 7 |
| T13 | Rogue Agents in Multi-Agent Systems | ASI10 | Layer 7 |
| T14 | Sampling/Inference Manipulation | LLM04 | Layer 1/2 |
| T15 | Prompt Injection | LLM01 / ASI01 | Layer 1/3 |
| T16 | Model Inconsistency Leading to Variable Decisions | LLM09 | Layer 1 |
| T17 | Semantic Drift in Embeddings | LLM08 | Layer 2 |

---

## MAESTRO-Extended Threats

MAESTRO's layer-based analysis regularly surfaces threats **beyond** the core T1–T17 taxonomy. These are system-specific extensions discovered during the layer mapping exercise. Common categories include:

| Category | Examples | Layer |
|----------|---------|-------|
| **RAG-specific exploitation** | T18 – RAG Input Manipulation for Policy Bypass; T28 – RAG Data Exfiltration | 2 |
| **Framework integrity** | T19 – Unintended Workflow Execution; T20 – Framework Vulnerability to Code Injection; T21 – Inconsistent Workflow State | 3 |
| **Infrastructure exposure** | T22 – Service Account Exposure | 4 |
| **Observability evasion** | T23 – Selective Log Manipulation | 5 |
| **Policy engine failure** | T24 – Dynamic Policy Enforcement Failure | 6 |
| **Ecosystem-level disruption** | T25 – Workflow Disruption via Dependency Exploitation | 7 |
| **MCP-specific** | T39 – Unintended Resource Consumption via MCP; T40 – MCP Client Impersonation | 3/4 |

---

## MAESTRO Layer Analysis Process

### Step 1 — Create the Layer Mapping Table

For the assessed system, map every component to its MAESTRO layer:

```
MAESTRO Layer | System Components & Features          | Notes
--------------|----------------------------------------|-----------------------------
1. Foundation | LLM model(s) used; inference config    | Which model, hosted where?
2. Data Ops   | RAG pipeline; vector DB; data sources  | Who can write to the KB?
3. Frameworks | Agent orchestration; tools; plugins    | What tools have write access?
4. Infra      | Cloud env; network; service accounts   | How are credentials managed?
5. Eval/Obs   | Logging; anomaly detection; HITL       | Is logging centralised/immutable?
6. Sec/Comp   | Access control; policy engine; RBAC    | Is policy enforcement dynamic?
7. Ecosystem  | Other agents; humans; external systems | A2A protocols? Registries?
```

### Step 2 — Layer-by-Layer Threat Identification

For each layer:
1. Identify which of the T1–T17 threats apply to the components in that layer
2. Check for system-specific extended threats (Tx) using the four agentic factors as lenses
3. Note the **agentic factor(s)** driving each threat (Non-Determinism / Autonomy / Identity / A2A)

### Step 3 — Cross-Layer Threat Scenarios

Identify threats that only emerge from the **interaction between layers**. Structure each scenario as:

```
Layers Involved: Layer X + Layer Y (+ Layer Z)
Threat: [Name]
Scenario: [How the attack chain spans layers]
Agentic Factors: [Which factors enable the propagation]
ASI/LLM/MCP IDs: [Map to existing threat IDs for Risk Register]
```

**Common high-value cross-layer combinations:**

| Layer Combination | Typical Emergent Threat |
|-------------------|------------------------|
| L1 + L2 + L3 | Hallucination-driven data corruption via RAG and tool misuse |
| L3 + L4 + L6 | Privilege escalation via framework vulnerability and infrastructure weakness |
| L2 + L3 + L7 | Misinformation propagation via shared knowledge base and agent communication |
| L3 + L5 + L6 | Selective log manipulation to evade anomaly detection |
| L7 + L2 + L3 | Agent A DoS attack on Agent B via compromised framework + outdated RAG data |
| L1 + L3 (MCP) | Tool hijacking and parameter pollution via prompt injection |

### Step 4 — Map Extended Threats to Risk Register

For any MAESTRO-extended threats (Tx) not already captured in the ASI/LLM/MCP checklist:
- Assign a risk register entry
- Reference the T-ID (e.g., T19) alongside the closest OWASP ID (e.g., ASI02)
- Note source as `MAESTRO` in the framework column

---

## When to Apply MAESTRO in Phase 2

**Trigger conditions — apply MAESTRO deep-dive when ANY of the following:**

- Multi-agent architecture: orchestrator agent directing one or more sub-agents
- A2A delegation or agent chaining (output of one agent feeds into another)
- Three or more MCP servers connected in a workflow
- Shared RAG knowledge base accessible by multiple agents
- Autonomous execution of multi-step workflows without per-step human approval
- High Impact classification with agentic components

**When NOT to apply:** Single-agent with tool-use only (standard ASI/MCP checklist is sufficient); Low Impact use cases.

---

## Integration with GIC Phase 2 Threat Modeling

MAESTRO runs **after** the ASI checklist (Step 2) and **before** DASF (Step 4) in Phase 2. Use the following approach:

1. Complete the ASI Top 10 checklist as normal — this establishes the baseline agentic threat coverage
2. If MAESTRO triggers apply, create the Layer Mapping Table for the assessed system
3. Run layer-by-layer analysis — check for extended threats not surfaced by the ASI checklist
4. Run cross-layer scenarios — check for emergent threats from layer interactions
5. Any new threats found go into the Risk Register with source `MAESTRO + T-ID`
6. For threats already captured by ASI/LLM/MCP IDs, add the MAESTRO T-ID as a cross-reference note (do not create duplicate entries)

---

## Quick Checklist: Cross-Layer Threat Indicators

Use these as conversation prompts during the assessment to surface cross-layer risks:

- Does a compromise at Layer 1 (hallucination) get amplified by Layer 2 (RAG retrieval) and acted upon by Layer 3 (autonomy)?
- Can Layer 3 (agent framework) be used to tamper with Layer 5 (logs), bypassing Layer 6 (controls)?
- Can a compromised agent in Layer 7 (ecosystem) poison Layer 2 (shared knowledge base), affecting other agents?
- Does Layer 4 (infrastructure) weakness allow credential theft that enables Layer 3 (agent) to exceed its intended permissions (Layer 6)?
- Can non-determinism in Layer 1 cause Layer 3 (workflow) to enter a runaway loop consuming Layer 4 (compute) resources?
