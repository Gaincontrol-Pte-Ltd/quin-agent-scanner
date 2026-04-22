# OWASP Top 10 for Agentic Applications 2026 — Quick Reference

**Source:** OWASP GenAI Security Project — Agentic Security Initiative (genai.owasp.org)
**Version:** 2026 (December 2025)
**Full document:** `OWASP_Agentic_Top10_2026.pdf` (in this folder)

Use this framework **in addition to** the OWASP LLM Top 10 whenever the assessed system uses agentic AI, MCP servers, tool-use, plugins, or multi-agent architectures.

---

## When to Apply

Apply the OWASP Agentic Top 10 during Phase 2 (Threat Modeling) when ANY of the following is true:
- The "Agent Assessment" sheet in the questionnaire is populated
- Gen AI questionnaire Q8 = Yes (agents / MCPs in use)
- Gen AI questionnaire Q9 indicates the model can make changes (not just content generation)
- The system uses multi-agent orchestration, A2A protocols, or tool-calling chains

---

## The Agentic Top 10

| ID | Threat | Description | Key Risk Indicators |
|---|---|---|---|
| **ASI01** | **Agent Goal Hijack** | Attackers manipulate agent objectives through prompt injection, poisoned data, or malicious tools to redirect the agent's planning and reasoning toward adversarial goals | Direct user input → agent; RAG from external sources; no input validation |
| **ASI02** | **Tool Misuse & Exploitation** | Agents invoke tools in unintended, harmful, or exploitable ways — over-permissioned tools, unvalidated parameters, or tools that expose sensitive operations | Broad tool permissions; no parameter validation at tool boundary; tools with write access |
| **ASI03** | **Identity & Privilege Abuse** | Agents operate with overly broad permissions, inherit user credentials without scoping, or escalate privileges across tool calls and sessions | Agent uses user's full credentials; no per-action scoping; shared service accounts |
| **ASI04** | **Agentic Supply Chain Vulnerabilities** | Compromised models, tools, plugins, libraries, or MCP servers introduce malicious behavior into the agent ecosystem | Third-party MCP servers; community plugins; unverified tool sources; no SBOM/AIBOM |
| **ASI05** | **Unexpected Code Execution (RCE)** | Agents generate or execute code in environments without adequate sandboxing, allowing arbitrary command execution | Code execution capability; no sandboxing; shell access; dynamic code generation |
| **ASI06** | **Memory & Context Poisoning** | Attackers inject malicious content into agent memory, conversation history, RAG context, or shared state to persistently influence agent behavior | Persistent memory across sessions; shared RAG knowledge base; writable context stores |
| **ASI07** | **Insecure Inter-Agent Communication** | Flaws in protocols between agents (MCP, A2A) allow consent bypass, context hijacking, or unauthorized delegation between agents | Multi-agent systems; MCP server chains; A2A delegation; no authentication between agents |
| **ASI08** | **Cascading Failures** | Errors, hallucinations, or compromises in one agent propagate through chains of dependent agents, amplifying impact across the system | Agent chains; no circuit breakers; no error isolation; outputs of one agent feed into another |
| **ASI09** | **Human-Agent Trust Exploitation** | Agents exploit or erode the trust relationship with users — presenting manipulated information, reducing skepticism, or coercing actions through social engineering | Customer-facing agents; persuasive output; no human-in-the-loop for high-impact actions |
| **ASI10** | **Rogue Agents** | Agents behave unpredictably or maliciously due to compromised models, adversarial fine-tuning, or emergent behaviors not anticipated during design | Fine-tuned models; third-party agents; limited behavioral monitoring; no kill switch |

---

## Cross-Reference: OWASP Agentic Top 10 ↔ OWASP LLM Top 10 (2025 IDs)

| Agentic (ASI) | Related LLM Threat (2025) | Agentic Amplification |
|---|---|---|
| ASI01 (Goal Hijack) | LLM01:2025 (Prompt Injection) | Injection shifts long-term reasoning, not just single responses |
| ASI02 (Tool Misuse) | LLM06:2025 (Excessive Agency) | Tools have broader scope and real-world write access in agentic systems |
| ASI03 (Privilege Abuse) | LLM06:2025 (Excessive Agency) | Agents inherit and escalate user privileges across tool chains |
| ASI04 (Supply Chain) | LLM03:2025 (Supply Chain) | Agentic ecosystems have larger attack surface (MCP servers, A2A, plugins) |
| ASI05 (RCE) | LLM05:2025 (Improper Output Handling) | Agents can execute generated code, not just render output |
| ASI06 (Memory Poisoning) | LLM04:2025 (Data and Model Poisoning) | Persistent memory creates ongoing manipulation, not just training-time risk |
| ASI07 (Inter-Agent Comms) | — (New category) | No direct LLM parallel — unique to multi-agent architectures |
| ASI08 (Cascading Failures) | — (New category) | No direct LLM parallel — unique to agent chains |
| ASI09 (Trust Exploitation) | LLM09:2025 (Misinformation) | Agentic trust is deeper — agents act autonomously on user's behalf |
| ASI10 (Rogue Agents) | LLM06:2025 (Excessive Agency) | Rogue behavior is emergent and harder to detect than excess permissions |

> **Note:** LLM07:2023 Insecure Plugin Design has been removed in the 2025 edition — its content is now covered under LLM06:2025 Excessive Agency. Old cross-references to LLM07:2023 should be updated to LLM06:2025.

---

## How to Use in Phase 2 Threat Modeling

For each ASI threat:
1. Check whether the system architecture includes the relevant agentic component (tool use, multi-agent, MCP, memory, code execution)
2. If the component exists, mark as **Applicable** and reference the questionnaire evidence (Section 1 Q5, Section 2 responses, or clarification responses)
3. If ASI07/ASI08 apply (multi-agent/cascading), this usually elevates the overall risk tier
4. Cross-reference with the corresponding LLM threat — score the **higher** of the two if both apply

For detailed attack scenarios and mitigations, read the full PDF: `OWASP_Agentic_Top10_2026.pdf`
