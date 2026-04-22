# Quin Risk Framework — Threats & Controls

<!--
  GENERATED FILE — DO NOT EDIT BY HAND.
  Source of truth: src/quin_scanner/rules/risk_taxonomy.yaml
  Regenerate:       python scripts/generate_risk_framework_docs.py
  Drift check:      python scripts/generate_risk_framework_docs.py --check
-->

This document is generated from the Quin risk taxonomy. It catalogs the
threats Quin's scanner reasons about and the controls it recommends, with
evidence grounded in:

- OWASP LLM Top 10 (2025)
- OWASP Agentic AI Top 10 Vulnerabilities
- OWASP MCP Top 10
- OWASP MAESTRO multi-agent threat model
- Databricks AI Security Framework (DASF) v3.0

Scanner reports deep-link into this file. Each control label in a Quin HTML
report (e.g. `C003: Access Control & Least Privilege`) links to the matching
`#c003` anchor below. Each risk signal with a known threat renders a small
`↗` icon that links to the matching `#t001` anchor.

---

## How to read this catalog

- **Threats** (T0NN) describe *what can go wrong*. Each threat has a plain-language
  description, a list of Key Risk Indicators (KRIs) the scanner looks for,
  representative attack patterns, and a set of recommended controls.
- **Controls** (C0NN) describe *what to do about it*. Each control has a description,
  concrete implementation guidance, and the common pitfalls that make controls
  fail to land even when they are nominally in place.

Threats and controls cross-reference each other: every threat links to its
recommended controls, and every control lists the threats it helps mitigate.

---

## Threats


<a id="t001"></a>
### T001 — Input Manipulation & Prompt Injection

- **Category:** Input Manipulation
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C001: Input Validation & Filtering](#c001), [C002: Output Validation & Handling](#c002), [C003: Access Control & Least Privilege](#c003), [C006: Human Oversight & Approval Gates](#c006), [C008: Agent Governance & Boundaries](#c008)

**Description.** Attackers craft inputs — direct or indirect via retrieved content — that override the model's system instructions, hijack its goals, or coerce it into emitting unsafe tool calls. In agentic systems the blast radius extends beyond a single response: an injected instruction can trigger tool invocations, data exfiltration, or multi-step workflows that the original user never requested.

**Why it matters.** Prompt injection is the #1 risk in the OWASP LLM Top 10 because LLMs cannot reliably distinguish system instructions from untrusted content appearing in the same context window. Any surface that feeds external text (RAG corpora, emails, web pages, tool outputs, document uploads) is a potential injection vector, and the model's helpfulness works against you once an attacker seeds an instruction.

**Key risk indicators.**

- User input reaches the model without sanitization
- Agent retrieves external content (RAG, web, email, documents)
- Model output triggers downstream actions or tool calls
- Retrieved content treated as instructions rather than passive data
- No validation that planned tool calls align with original user goals
- System instructions and untrusted content merged indistinguishably in context

**Representative attack patterns.**

- Direct prompt injection ("Ignore previous instructions and…")
- Indirect injection via poisoned RAG documents, web pages, or emails
- Multimodal injection hidden in images, audio, or metadata
- Goal manipulation that reshapes the agent's objective across turns
- Payload smuggling through tool call responses or subagent outputs

**References.**

- [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)
- [OWASP Agentic AI — ASI01 Goal Manipulation](https://genai.owasp.org/resource/agentic-ai-top-10-vulnerabilities-2025/) — local copy: [`docs/OWASP-Agentic-Top10-Reference.md`](OWASP-Agentic-Top10-Reference.md)

---

<a id="t002"></a>
### T002 — Sensitive Data Exposure

- **Category:** Data Exposure
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C005: Data Protection & Classification](#c005), [C003: Access Control & Least Privilege](#c003), [C007: Monitoring, Logging & Observability](#c007), [C010: Infrastructure Security](#c010), [C013: Transparency & AI Governance](#c013)

**Description.** LLM-based systems can leak sensitive data through several distinct channels: the model itself (trained on or fine-tuned with sensitive content), the prompt pipeline (system prompts with secrets, hard-coded credentials in MCP configs), the context store (cross-session memory, shared vector stores), and operational surfaces (verbose error messages and debug logs).

**Why it matters.** Unlike traditional data leaks, exposure here is often indirect — a model reconstructs sensitive content from learned patterns, or an agent pulls a tenant's data into another tenant's context. Remediation is hard: retraining or re-embedding is costly, and once a secret has been surfaced in an LLM response it must be treated as compromised.

**Key risk indicators.**

- PII or sensitive data in training data, fine-tuning datasets, or RAG knowledge bases
- System prompts containing credentials, connection strings, or internal URLs
- Hard-coded credentials in MCP server configurations
- API keys or tokens stored in conversational memory across sessions
- Debug logs containing unredacted secrets
- Shared context stores across users or tenants without isolation

**Representative attack patterns.**

- Prompt extraction to recover system prompts and embedded secrets
- Membership inference attacks revealing training-set membership
- Cross-tenant RAG leakage via missing namespace isolation
- Memory scraping of long-lived conversational state
- Reflected disclosure through verbose errors or debug echo

**References.**

- [OWASP LLM02 — Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)
- [Databricks DASF — Data Classification & Protection Controls](https://www.databricks.com/resources/whitepaper/databricks-ai-security-framework-dasf) — local copy: [`docs/Databricks-DASF-Reference.md`](Databricks-DASF-Reference.md)

---

<a id="t003"></a>
### T003 — AI Supply Chain Compromise

- **Category:** Supply Chain
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C004: Supply Chain Security](#c004), [C011: Model & Data Integrity](#c011), [C009: Testing & Adversarial Evaluation](#c009), [C010: Infrastructure Security](#c010)

**Description.** The AI supply chain spans foundation model weights, fine-tuning datasets, embedding models, Python and JS packages, MCP servers, tool definitions, and remote schemas. A compromise at any point — a backdoored model on a public hub, a typosquatted package, a malicious MCP server installed by a developer — can implant long-lived, hard-to-detect behavior inside the running agent.

**Why it matters.** Supply chain attacks are especially dangerous for AI because model artefacts and schemas are opaque: a vulnerable dependency or a poisoned LoRA adapter rarely triggers obvious runtime errors. Without SBOM/AI-BOM discipline and provenance verification, the first signal of compromise is often the exfiltration itself.

**Key risk indicators.**

- Third-party models used without provenance verification
- MCP servers or plugins from unverified community sources
- No SBOM or AI-BOM maintained
- Tool schemas fetched remotely without integrity verification
- Dependencies not pinned to verified versions
- No multi-person approval for schema or tool registry changes

**Representative attack patterns.**

- Backdoored or trojaned model weights on public hubs
- Dependency confusion and typosquatted AI packages
- Malicious MCP servers installed via one-click community registries
- Remote tool schemas that change shape to smuggle new behavior
- Compromise of build pipelines shipping model artefacts

**References.**

- [OWASP LLM03 — Supply Chain](https://genai.owasp.org/llmrisk/llm03-supply-chain/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)
- [OWASP MCP02 — Malicious Server Distribution](https://genai.owasp.org/resource/agentic-ai-owasp-mcp-top-10/) — local copy: [`docs/OWASP-MCP-Top10-Reference.md`](OWASP-MCP-Top10-Reference.md)

---

<a id="t004"></a>
### T004 — Data & Model Integrity Poisoning

- **Category:** Data Integrity
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C011: Model & Data Integrity](#c011), [C005: Data Protection & Classification](#c005), [C007: Monitoring, Logging & Observability](#c007), [C009: Testing & Adversarial Evaluation](#c009), [C010: Infrastructure Security](#c010)

**Description.** Poisoning attacks corrupt the data an AI system learns from or retrieves: training sets, fine-tuning corpora, RAG knowledge bases, embeddings stores, and persistent agent memory. The attacker's goal is usually to implant a trigger — a specific phrase, context, or embedding neighborhood — that causes the model or agent to misbehave in deployment while passing general evaluation.

**Why it matters.** Traditional data integrity controls (checksums, ACLs) are necessary but insufficient for AI: a RAG document passing content filters can still reshape retrieval results, and a fine-tuning record with clean schema can introduce a backdoor. Poisoning targets the long tail of behavior that standard QA rarely covers.

**Key risk indicators.**

- Training/fine-tuning data from unvetted or publicly scraped sources
- RAG knowledge base populated without content validation
- No data provenance tracking or integrity verification
- Persistent agent memory across sessions without sanitization
- Shared vector stores across users/tenants without namespace isolation
- No anomaly detection on embedding drift

**Representative attack patterns.**

- Targeted backdoor triggers inserted into fine-tuning data
- RAG poisoning via publicly editable sources (wikis, support forums)
- Memory injection persisted across sessions
- Embedding-space attacks that shift retrieval rankings
- Label-flipping on human-in-the-loop correction data

**References.**

- [OWASP LLM04 — Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)
- [OWASP MAESTRO — Data Operations layer](https://cloudsecurityalliance.org/research/working-groups/ai-safety-initiative/) — local copy: [`docs/OWASP-MAESTRO-Reference.md`](OWASP-MAESTRO-Reference.md)

---

<a id="t005"></a>
### T005 — Unsafe Output & Code Execution

- **Category:** Output Safety
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C002: Output Validation & Handling](#c002), [C010: Infrastructure Security](#c010), [C006: Human Oversight & Approval Gates](#c006), [C008: Agent Governance & Boundaries](#c008)

**Description.** LLM output is attacker-controllable when the model can be prompted or nudged. Systems that render, execute, or interpret that output without handling it as untrusted — rendering HTML verbatim, executing generated SQL, running generated shell commands, auto-applying code patches — convert a text-level issue into remote code execution, stored XSS, or data loss.

**Why it matters.** The defining pattern of agentic systems is "LLM output drives an action." That makes output safety a first-class concern, not a UI polish problem. Every sink (browser, shell, database, filesystem, tool call) needs the same assumption: the text came from an adversary.

**Key risk indicators.**

- LLM output rendered directly in browsers without encoding
- LLM-generated SQL or commands executed without parameterization
- Agent constructs shell commands by concatenating user/external input
- Code execution capability without sandboxing
- Tool wrappers using eval(), exec(), or shell=True
- No allowlisting of permitted commands at tool boundaries

**Representative attack patterns.**

- Stored XSS via LLM responses rendered in a web UI
- SQL injection from LLM-generated query strings
- Command injection through shell-exec tool wrappers
- Path traversal in file-system tools accepting LLM-chosen paths
- Arbitrary code execution through unsandboxed code-interpreter tools

**References.**

- [OWASP LLM05 — Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="t006"></a>
### T006 — Excessive Permissions & Privilege Abuse

- **Category:** Access Control
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C003: Access Control & Least Privilege](#c003), [C006: Human Oversight & Approval Gates](#c006), [C008: Agent Governance & Boundaries](#c008), [C010: Infrastructure Security](#c010), [C007: Monitoring, Logging & Observability](#c007)

**Description.** Agents and plugins often run with broader permissions than they need: a read-only analytics agent given write access, an MCP tool with delete scope when list would do, a shared service account used by every agent in the system. When an injection or bug causes the agent to misbehave, the blast radius equals whatever the underlying credential can touch.

**Why it matters.** In traditional software, excessive privilege is contained by the application's own logic. In agentic systems, the LLM *is* the logic — and it can be talked into using every permission it has. Least privilege therefore must be enforced at the credential boundary, not trusted to the model.

**Key risk indicators.**

- Agent has access to tools beyond its defined purpose
- Extensions with broad permissions (read+write+delete when only read needed)
- No human-in-the-loop for high-impact or irreversible actions
- Agent uses high-privileged service accounts rather than user-scoped credentials
- MCP tool permissions broader than required
- Dev/test permissions left active in production
- No mutual authentication between agents and MCP servers
- Shared service accounts across multiple agents

**Representative attack patterns.**

- Confused deputy attacks exploiting shared service accounts
- Privilege escalation through tool chaining
- Cross-tenant access via over-broad MCP scopes
- Persistence via background tasks the agent can schedule
- Exploitation of stale dev credentials left in prod configs

**References.**

- [OWASP LLM06 — Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)
- [OWASP MCP05 — Excessive Permissions](https://genai.owasp.org/resource/agentic-ai-owasp-mcp-top-10/) — local copy: [`docs/OWASP-MCP-Top10-Reference.md`](OWASP-MCP-Top10-Reference.md)

---

<a id="t007"></a>
### T007 — AI Misinformation & Hallucination

- **Category:** Output Reliability
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C002: Output Validation & Handling](#c002), [C006: Human Oversight & Approval Gates](#c006), [C009: Testing & Adversarial Evaluation](#c009), [C013: Transparency & AI Governance](#c013)

**Description.** LLMs generate fluent, confident text regardless of whether the underlying claim is true. In customer-facing, decision-support, or code-generation contexts, confidently-wrong output can drive real downstream harm: wrong medical guidance, fabricated citations, non-existent API calls, or insecure generated code patterns.

**Why it matters.** Unlike other risks here, hallucination is a *default behavior* rather than an attack. Mitigation is not a single control but a stack: grounding via RAG, output verification, clear AI-content labeling, and — above all — never letting a single hallucinated output drive an irreversible action without a validation gate.

**Key risk indicators.**

- Customer-facing applications where outputs influence decisions
- High-stakes contexts (financial, medical, legal, operational)
- No RAG grounding or verification of model outputs
- AI-generated code integrated without review
- Agent outputs fed into other agents without validation
- No clear labeling of AI-generated content

**Representative attack patterns.**

- Package hallucination leading to dependency-confusion attacks
- Fabricated citations passed through to end users
- Hallucinated API endpoints invoked via generated code
- Amplification through agent-to-agent hand-off without verification
- Silent quality regression when grounding sources go stale

**References.**

- [OWASP LLM09 — Misinformation](https://genai.owasp.org/llmrisk/llm09-misinformation/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="t008"></a>
### T008 — Resource Abuse & Service Disruption

- **Category:** Availability
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C012: Rate Limiting & Resource Management](#c012), [C007: Monitoring, Logging & Observability](#c007), [C010: Infrastructure Security](#c010)

**Description.** LLMs are expensive, slow, and consumption-billed. That makes them an attractive target for denial-of-wallet (DoW) and denial-of-service attacks: long-context inputs that inflate tokens, adversarial prompts that force maximum output, and crawl-style extraction that copies model behavior into a competitor product.

**Why it matters.** Unlike CPU-bound DoS, a DoW attack can burn a monthly budget in minutes while leaving the service technically "up." Rate limiting, input/output size caps, and cost anomaly detection are as important as availability monitoring.

**Key risk indicators.**

- Externally accessible APIs without rate limiting
- Cloud-hosted models on consumption-based billing
- No input size limits or processing timeouts
- Logprobs or logit_bias exposed in API responses
- Unrestricted output volume enabling model extraction
- No anomaly detection on usage patterns

**Representative attack patterns.**

- Denial-of-wallet attacks via long prompts or maximum-token responses
- Model extraction via systematic querying to clone behavior
- Tool call amplification loops that recurse agent tools
- Context-window flooding to crowd out legitimate usage
- Abuse of exposed logprobs to accelerate extraction

**References.**

- [OWASP LLM10 — Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="t009"></a>
### T009 — Inter-Agent Communication Compromise

- **Category:** Agent Communication
- **Applies to:** multi_agent
- **Recommended controls:** [C003: Access Control & Least Privilege](#c003), [C007: Monitoring, Logging & Observability](#c007), [C010: Infrastructure Security](#c010), [C008: Agent Governance & Boundaries](#c008)

**Description.** In multi-agent systems, agents talk to agents — often over a tool protocol like MCP or a custom A2A channel. Without mutual authentication, message integrity, and per-step authorization, a compromised or impersonated agent can inject instructions into the shared workflow, escalate privileges, or exfiltrate the collective context.

**Why it matters.** Single-agent threat models miss this entire layer. MAESTRO calls it the Agent Frameworks layer, and notes that most "emergent" multi-agent failures trace back to missing identity and authorization guarantees at the message boundary.

**Key risk indicators.**

- Multi-agent systems with A2A delegation
- No mutual authentication between agents
- Agents sharing context without authorization controls
- MCP server chains without per-step permission validation
- No agent identity verification in orchestrator-to-sub-agent communication

**Representative attack patterns.**

- Agent impersonation via spoofed identity tokens
- Man-in-the-middle on unauthenticated A2A channels
- Replay attacks on stateless tool-call protocols
- Confused-deputy delegation across trust boundaries
- Silent context leakage when sibling agents share a store

**References.**

- [OWASP MAESTRO — Agent Frameworks layer](https://cloudsecurityalliance.org/research/working-groups/ai-safety-initiative/) — local copy: [`docs/OWASP-MAESTRO-Reference.md`](OWASP-MAESTRO-Reference.md)
- [OWASP MCP04 — Unauthenticated Server Communication](https://genai.owasp.org/resource/agentic-ai-owasp-mcp-top-10/) — local copy: [`docs/OWASP-MCP-Top10-Reference.md`](OWASP-MCP-Top10-Reference.md)

---

<a id="t010"></a>
### T010 — Cascading & Emergent Failures

- **Category:** System Resilience
- **Applies to:** agentic_ai, multi_agent
- **Recommended controls:** [C008: Agent Governance & Boundaries](#c008), [C006: Human Oversight & Approval Gates](#c006), [C007: Monitoring, Logging & Observability](#c007), [C009: Testing & Adversarial Evaluation](#c009)

**Description.** In agent chains, the output of one step is the input of the next. A small error — a hallucinated entity, an off-by-one result, a flaky tool response — can compound through the chain, producing a confidently-wrong final answer that no single step flagged. Cyclical or self-modifying chains add a further risk: runaway loops.

**Why it matters.** Cascading failure is the mode that makes "the agent did the wrong thing" genuinely hard to debug, because no component failed in isolation. Defenses must be structural: circuit breakers, per-step validation, step budgets, and explicit stop conditions.

**Key risk indicators.**

- Agent chains where output of one feeds into another
- No circuit breakers or error isolation between agents
- No per-step validation in multi-step workflows
- Agents operating without output verification gates
- Cyclical agent execution paths (Level 3 autonomy)

**Representative attack patterns.**

- Error amplification through uncorrected intermediate outputs
- Runaway loops due to missing step budgets
- Deadlock or livelock between peer agents
- Positive-feedback hallucination reinforcement
- Silent degradation when an upstream tool's schema drifts

**References.**

- [OWASP Agentic AI — ASI06 Cascading Hallucination](https://genai.owasp.org/resource/agentic-ai-top-10-vulnerabilities-2025/) — local copy: [`docs/OWASP-Agentic-Top10-Reference.md`](OWASP-Agentic-Top10-Reference.md)

---

<a id="t011"></a>
### T011 — Rogue Agent Behavior

- **Category:** Agent Governance
- **Applies to:** agentic_ai, multi_agent
- **Recommended controls:** [C008: Agent Governance & Boundaries](#c008), [C007: Monitoring, Logging & Observability](#c007), [C009: Testing & Adversarial Evaluation](#c009), [C006: Human Oversight & Approval Gates](#c006)

**Description.** "Rogue agent" covers the spectrum from an agent acting outside its intended goals (due to drift, injection, or misaligned fine-tuning) to an agent that is fundamentally untrusted (supplied by a third party, based on unvetted weights, or integrated without behavioral review). Without runtime behavioral monitoring and a kill switch, misbehavior can persist unnoticed.

**Why it matters.** Agent governance is the "people and process" layer of AI security: who owns each agent, what it's allowed to do, how you know it's still doing that, and how you stop it if it's not. The control equivalent to a revocable credential for traditional systems is a scoped, monitored, kill-switchable agent identity.

**Key risk indicators.**

- Fine-tuned models from untrusted sources
- Third-party agents integrated without behavioral validation
- Limited runtime behavioral monitoring
- No kill switch or forced shutdown mechanism
- Agent can modify its own instructions or goals
- Fully autonomous execution (Level 3 autonomy)

**Representative attack patterns.**

- Malicious fine-tunes with dormant trigger-activated behavior
- Goal drift across long-running sessions
- Self-modification of system prompts or policy files
- Tool-registry tampering to grant the agent new capabilities
- Persistence across restarts via poisoned memory

**References.**

- [OWASP Agentic AI — ASI09 Unexpected RCE and Code Attacks](https://genai.owasp.org/resource/agentic-ai-top-10-vulnerabilities-2025/) — local copy: [`docs/OWASP-Agentic-Top10-Reference.md`](OWASP-Agentic-Top10-Reference.md)

---

<a id="t012"></a>
### T012 — Insufficient Observability & Audit

- **Category:** Observability
- **Applies to:** standard_ai, agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C007: Monitoring, Logging & Observability](#c007), [C006: Human Oversight & Approval Gates](#c006), [C009: Testing & Adversarial Evaluation](#c009)

**Description.** If you cannot reconstruct what an agent decided, which tools it called, on whose behalf, and what data it saw, you cannot do incident response, compliance review, or even basic debugging. Observability for AI systems requires more than application logs: it requires tamper-evident records of prompts, tool calls, context changes, and policy decisions.

**Why it matters.** Every mature control in this catalog depends on observability — anomaly detection, human review, governance, and incident response all read from the same trace. Without it, every other control is operating blind.

**Key risk indicators.**

- No centralized logging of MCP tool invocations
- No record of context changes in agent memory
- Logs mutable or accessible to agents themselves
- No anomaly detection on tool usage patterns
- No integration with SIEM or security monitoring
- Human reviewers overwhelmed by alert volume

**Representative attack patterns.**

- Log tampering from inside the agent's own execution context
- Evidence gaps enabling plausible deniability for misuse
- Alert fatigue abused to hide real anomalies
- SIEM bypass via unlogged side channels (direct DB calls, etc.)
- Silent failure of pipeline telemetry

**References.**

- [Databricks DASF — Monitoring & Observability Controls](https://www.databricks.com/resources/whitepaper/databricks-ai-security-framework-dasf) — local copy: [`docs/Databricks-DASF-Reference.md`](Databricks-DASF-Reference.md)

---

<a id="t013"></a>
### T013 — Unmanaged AI Infrastructure

- **Category:** AI Governance
- **Applies to:** mcp_enabled, multi_agent
- **Recommended controls:** [C004: Supply Chain Security](#c004), [C007: Monitoring, Logging & Observability](#c007), [C010: Infrastructure Security](#c010), [C013: Transparency & AI Governance](#c013)

**Description.** Shadow AI — undocumented agents, unregistered MCP servers, AI endpoints running on arbitrary ports — is now a standard governance problem. Teams spin up agents for experiments; experiments become production; production becomes security-critical. Without a registry and standard controls, security teams cannot answer "what AI do we run?"

**Why it matters.** You cannot secure what you cannot enumerate. An unmanaged AI endpoint is an unaudited privilege-holder with data access and external reach. Governance here is not paperwork — it is the prerequisite for applying every other control.

**Key risk indicators.**

- No central registry or inventory of all AI/MCP instances
- Teams deploy AI systems without security review
- MCP services running on unusual ports outside standard infrastructure
- Security team cannot enumerate all active AI endpoints
- No access controls or logging on unofficial deployments

**Representative attack patterns.**

- Shadow deployments bypassing security review
- Endpoint sprawl that outgrows the asset inventory
- Unauthorized tools silently added to an agent's registry
- Abandoned experiments retaining prod credentials
- Policy drift between documented and actual behavior

**References.**

- [OWASP MCP01 — Unmanaged Server Sprawl](https://genai.owasp.org/resource/agentic-ai-owasp-mcp-top-10/) — local copy: [`docs/OWASP-MCP-Top10-Reference.md`](OWASP-MCP-Top10-Reference.md)

---

<a id="t014"></a>
### T014 — Human-AI Trust Manipulation

- **Category:** Trust & Safety
- **Applies to:** agentic_ai, mcp_enabled, multi_agent
- **Recommended controls:** [C006: Human Oversight & Approval Gates](#c006), [C013: Transparency & AI Governance](#c013), [C009: Testing & Adversarial Evaluation](#c009), [C007: Monitoring, Logging & Observability](#c007)

**Description.** Agents that speak fluently, cite sources, and act on the user's behalf create a trust surface that can be exploited in both directions: attackers use the agent to deceive customers or employees (phishing, fraud), and users defer to agent output without verification, rubber-stamping decisions that needed scrutiny.

**Why it matters.** This is the failure mode regulators care most about. Even a technically-secure agent can cause harm if users cannot tell AI output apart from human, or if human-in-the-loop reviewers are so overloaded that their approvals are meaningless. Trust is a first-order design problem, not a UX afterthought.

**Key risk indicators.**

- Customer-facing agents with persuasive output capability
- Agents handling financial transactions or official communications
- No human-in-the-loop for high-impact actions
- Agent can send external communications as the organization
- Users trained to trust AI outputs without verification
- HITL reviewers overloaded, creating approval fatigue

**Representative attack patterns.**

- Agent-driven phishing against the organization's own users
- Automated social engineering at scale
- Approval fatigue turning HITL into a rubber stamp
- Impersonation of official communications channels
- Users over-trusting confident-but-wrong agent output

**References.**

- [OWASP MAESTRO — Agent Ecosystem layer](https://cloudsecurityalliance.org/research/working-groups/ai-safety-initiative/) — local copy: [`docs/OWASP-MAESTRO-Reference.md`](OWASP-MAESTRO-Reference.md)

---


## Controls


<a id="c001"></a>
### C001 — Input Validation & Filtering

- **Mitigates:** [T001: Input Manipulation & Prompt Injection](#t001)

**Description.** Validate and sanitize everything that enters the model's context — user messages, tool outputs, retrieved documents, uploaded files, and system-composed prompts — before it reaches the LLM.

**Why it matters.** Prompt injection is a context-merging problem. Filtering alone will not stop a determined attacker, but layered with segregation and allowlisting it raises the cost of attack and catches the unsophisticated cases that drive most incidents.

**How to implement.**

- Enforce explicit allowlists for permitted input shapes and lengths
- Strip or escape control-style tokens (role tags, system directives) from untrusted content
- Segregate system instructions, trusted context, and untrusted content into clearly labeled channels
- Run injection-pattern detectors (dedicated LLM judges or regex heuristics) on retrieved content
- Reject or quarantine inputs that exceed size or entropy thresholds

**Common pitfalls.**

- Relying on a single prompt-injection classifier as a silver bullet
- Filtering only user input while leaving tool-output / RAG content untreated
- Stripping content that attackers simply re-encode (base64, homoglyphs)
- Losing the filter when the prompt is refactored into a new codepath

**References.**

- [OWASP LLM01 — Mitigation section](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c002"></a>
### C002 — Output Validation & Handling

- **Mitigates:** [T001: Input Manipulation & Prompt Injection](#t001), [T005: Unsafe Output & Code Execution](#t005), [T007: AI Misinformation & Hallucination](#t007)

**Description.** Treat every byte of LLM output as untrusted. Encode before render, parameterize before query, sandbox before execute, and validate structured outputs against a schema before acting on them.

**Why it matters.** Most "LLM vulnerabilities" that end in RCE or XSS are really output-handling bugs: the model produced adversarial text and the next stage trusted it. Output handling turns a prompt-injection incident into a contained, recoverable one.

**How to implement.**

- Context-appropriate encoding at every sink (HTML escape, SQL parameters, shell-safe argv)
- Schema-validate structured outputs (JSON, tool-call args) before acting
- Sandbox any LLM-driven code execution (restricted runtime, network, filesystem)
- Strip or flag hallucinated identifiers (API endpoints, package names) before use
- Require human review for outputs that drive irreversible actions

**Common pitfalls.**

- Rendering Markdown from the LLM directly into a web UI without sanitization
- Passing LLM output to shell=True or eval() "because it's a tool wrapper"
- Trusting JSON shape because the LLM said "here is valid JSON"
- Silently dropping invalid output instead of alerting and falling back

**References.**

- [OWASP LLM05 — Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c003"></a>
### C003 — Access Control & Least Privilege

- **Mitigates:** [T001: Input Manipulation & Prompt Injection](#t001), [T002: Sensitive Data Exposure](#t002), [T006: Excessive Permissions & Privilege Abuse](#t006), [T009: Inter-Agent Communication Compromise](#t009)

**Description.** Scope every credential, tool, and dataset to the minimum required for the agent's specific purpose, and re-evaluate that scope regularly. Prefer user-impersonation flows over shared service accounts.

**Why it matters.** The LLM cannot be trusted to self-limit. Least privilege at the credential boundary is the only reliable way to contain a successful prompt injection, a misconfigured tool, or a compromised upstream.

**How to implement.**

- Issue per-agent, per-purpose credentials scoped to specific resources
- Propagate end-user identity through tool calls (on-behalf-of flows)
- Use mutual authentication for agent-to-agent and agent-to-MCP channels
- Review and prune tool permissions on a scheduled cadence
- Separate dev/test/prod credentials and enforce environment isolation

**Common pitfalls.**

- Giving every agent a single "admin" service account for convenience
- Copying a broad dev credential into production
- Granting write+delete where list+read would do
- Forgetting that shared context stores need their own ACL model

**References.**

- [OWASP LLM06 — Excessive Agency mitigations](https://genai.owasp.org/llmrisk/llm06-excessive-agency/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c004"></a>
### C004 — Supply Chain Security

- **Mitigates:** [T003: AI Supply Chain Compromise](#t003), [T013: Unmanaged AI Infrastructure](#t013)

**Description.** Treat model weights, adapters, datasets, embedding models, Python/JS packages, MCP servers, and tool schemas as supply-chain artefacts: identified, pinned, scanned, signed, and recorded in an AI-BOM.

**Why it matters.** AI supply-chain compromises are stealthy and long-lived. An AI-BOM that tracks artefact provenance is the minimum requirement for detection and recall when a trusted source turns out to be compromised.

**How to implement.**

- Maintain an AI-BOM covering models, adapters, datasets, and tool servers
- Pin and verify checksums/signatures for model and dataset downloads
- Vet MCP servers and plugins via a central registry with review
- Scan Python/JS dependencies for CVEs and typosquatting
- Require multi-party approval for changes to tool or schema registries

**Common pitfalls.**

- A `pip install some-agent-thing` with no pin, no review, no signature
- Trusting a public model hub's `verified` badge as a security claim
- Skipping the AI-BOM because the team only uses one model today
- Letting remote tool schemas mutate between deploys

**References.**

- [OWASP LLM03 — Supply Chain mitigations](https://genai.owasp.org/llmrisk/llm03-supply-chain/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c005"></a>
### C005 — Data Protection & Classification

- **Mitigates:** [T002: Sensitive Data Exposure](#t002), [T004: Data & Model Integrity Poisoning](#t004)

**Description.** Classify training, fine-tuning, RAG, memory, and log data by sensitivity, and apply commensurate encryption, masking, redaction, and retention controls across the AI lifecycle.

**Why it matters.** LLMs blur the line between "data" and "behavior": a sensitive record ingested into fine-tuning or a vector store stops behaving like a row in a database and starts behaving like a pattern the model can reproduce. Classification is the prerequisite for making sane retention and exposure decisions.

**How to implement.**

- Classify data before ingestion; refuse to ingest unclassified sensitive data
- Redact PII and secrets from prompts, responses, and logs
- Encrypt at rest and in transit; scope decryption keys to the AI service
- Isolate vector stores and memory by tenant/user with enforced namespaces
- Enforce retention limits on logs, context, and long-term memory

**Common pitfalls.**

- Assuming "it's just a RAG doc" exempts content from classification
- Letting debug logs capture raw prompts with embedded secrets
- Sharing a single vector store across tenants
- Keeping context indefinitely because "we might want it later"

**References.**

- [Databricks DASF — Data Classification & Protection](https://www.databricks.com/resources/whitepaper/databricks-ai-security-framework-dasf) — local copy: [`docs/Databricks-DASF-Reference.md`](Databricks-DASF-Reference.md)

---

<a id="c006"></a>
### C006 — Human Oversight & Approval Gates

- **Mitigates:** [T001: Input Manipulation & Prompt Injection](#t001), [T005: Unsafe Output & Code Execution](#t005), [T006: Excessive Permissions & Privilege Abuse](#t006), [T007: AI Misinformation & Hallucination](#t007), [T010: Cascading & Emergent Failures](#t010), [T011: Rogue Agent Behavior](#t011), [T012: Insufficient Observability & Audit](#t012), [T014: Human-AI Trust Manipulation](#t014)

**Description.** Route high-impact, irreversible, or ambiguous actions through a human reviewer with enough context to decide meaningfully. Design approval systems to resist fatigue, not just to exist.

**Why it matters.** "Human in the loop" is a load-bearing control in almost every AI threat model, but it only works if the human has time, context, and stakes. Poorly designed gates become rubber stamps — worse than no gate at all, because they produce false assurance.

**How to implement.**

- Define a written policy for which actions require human approval
- Present reviewers with the full decision context (prompt, tools, inputs)
- Rate-limit approval requests per reviewer to resist fatigue
- Differentiate "review and approve" from "notified after the fact"
- Track reviewer accuracy and calibration over time

**Common pitfalls.**

- Requiring approval so often that reviewers auto-click
- Presenting only the summarized action, not the underlying prompt/data
- Using the same HITL queue for low- and high-stakes actions
- Treating "manager added to cc" as oversight

**References.**

- [OWASP Agentic AI — HITL design guidance](https://genai.owasp.org/resource/agentic-ai-top-10-vulnerabilities-2025/) — local copy: [`docs/OWASP-Agentic-Top10-Reference.md`](OWASP-Agentic-Top10-Reference.md)

---

<a id="c007"></a>
### C007 — Monitoring, Logging & Observability

- **Mitigates:** [T002: Sensitive Data Exposure](#t002), [T004: Data & Model Integrity Poisoning](#t004), [T006: Excessive Permissions & Privilege Abuse](#t006), [T008: Resource Abuse & Service Disruption](#t008), [T009: Inter-Agent Communication Compromise](#t009), [T010: Cascading & Emergent Failures](#t010), [T011: Rogue Agent Behavior](#t011), [T012: Insufficient Observability & Audit](#t012), [T013: Unmanaged AI Infrastructure](#t013), [T014: Human-AI Trust Manipulation](#t014)

**Description.** Produce tamper-evident, queryable records of prompts, tool calls, context changes, model outputs, and policy decisions — and route them into the same SIEM and anomaly-detection stack as the rest of the business.

**Why it matters.** Observability is not "logs on a dashboard" — it is the substrate for incident response, compliance, and every other control that depends on detecting deviation. Without it, you are secure on paper and blind in practice.

**How to implement.**

- Log every tool invocation with agent identity, user identity, and parameters
- Capture prompt + response pairs (with redaction) for audit
- Store logs outside the agent's own write access (append-only, tamper-evident)
- Feed AI telemetry into SIEM / detection pipelines alongside app telemetry
- Instrument cost, latency, and anomaly metrics per agent and tool

**Common pitfalls.**

- Letting agents write to their own audit trail
- Logging so verbosely that signal drowns in noise
- Capturing secrets in logs by default
- Treating AI telemetry as separate from security telemetry

**References.**

- [Databricks DASF — Monitoring Controls](https://www.databricks.com/resources/whitepaper/databricks-ai-security-framework-dasf) — local copy: [`docs/Databricks-DASF-Reference.md`](Databricks-DASF-Reference.md)

---

<a id="c008"></a>
### C008 — Agent Governance & Boundaries

- **Mitigates:** [T001: Input Manipulation & Prompt Injection](#t001), [T005: Unsafe Output & Code Execution](#t005), [T006: Excessive Permissions & Privilege Abuse](#t006), [T009: Inter-Agent Communication Compromise](#t009), [T010: Cascading & Emergent Failures](#t010), [T011: Rogue Agent Behavior](#t011)

**Description.** Give each agent a named owner, a scoped mission, explicit tool allowlist, step/time budgets, circuit breakers, and a kill switch. Governance is structural, not aspirational.

**Why it matters.** Agentic systems fail in modes (goal drift, cascading loops, unbounded tool calls) that do not exist in traditional software. Structural bounds — budgets, breakers, and stop controls — are the only reliable way to keep those modes survivable.

**How to implement.**

- Define per-agent scope, tool allowlist, and escalation policy as code
- Enforce step and time budgets per agent invocation
- Add circuit breakers between agents so one failure does not cascade
- Implement a fast, auditable kill switch that stops the agent and its subagents
- Require review for changes to agent scope, tools, or policy

**Common pitfalls.**

- Writing scope in a README but enforcing nothing at runtime
- No kill switch, or one that requires a redeploy
- Step budgets in the prompt (advisory) instead of the runtime (enforced)
- Letting an agent modify its own policy file

**References.**

- [OWASP Agentic AI — Agent boundary guidance](https://genai.owasp.org/resource/agentic-ai-top-10-vulnerabilities-2025/) — local copy: [`docs/OWASP-Agentic-Top10-Reference.md`](OWASP-Agentic-Top10-Reference.md)

---

<a id="c009"></a>
### C009 — Testing & Adversarial Evaluation

- **Mitigates:** [T003: AI Supply Chain Compromise](#t003), [T004: Data & Model Integrity Poisoning](#t004), [T007: AI Misinformation & Hallucination](#t007), [T010: Cascading & Emergent Failures](#t010), [T011: Rogue Agent Behavior](#t011), [T012: Insufficient Observability & Audit](#t012), [T014: Human-AI Trust Manipulation](#t014)

**Description.** Red-team the system against prompt injection, data poisoning, output abuse, and agent-governance failures as a standing practice — not a pre-launch checkbox.

**Why it matters.** AI systems drift: prompts change, models update, tools are added, RAG corpora grow. A one-time pen test ages out in weeks. Continuous adversarial evaluation catches regressions before real attackers do.

**How to implement.**

- Maintain a regression suite of known prompt-injection and jailbreak patterns
- Run adversarial evaluation as part of CI for prompts, tools, and fine-tunes
- Red-team multi-agent workflows (not just single-agent behavior)
- Track evaluation metrics over time and alert on regressions
- Commission periodic external red-team engagements

**Common pitfalls.**

- Running evals only at launch, never again
- Testing only happy-path prompts; no adversarial corpus
- Evaluating the model in isolation, ignoring the prompt + tool stack
- Treating eval failures as "model problems, not our problem"

**References.**

- [OWASP LLM Top 10 — evaluation guidance](https://genai.owasp.org/llm-top-10/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c010"></a>
### C010 — Infrastructure Security

- **Mitigates:** [T002: Sensitive Data Exposure](#t002), [T003: AI Supply Chain Compromise](#t003), [T004: Data & Model Integrity Poisoning](#t004), [T005: Unsafe Output & Code Execution](#t005), [T006: Excessive Permissions & Privilege Abuse](#t006), [T008: Resource Abuse & Service Disruption](#t008), [T009: Inter-Agent Communication Compromise](#t009), [T013: Unmanaged AI Infrastructure](#t013)

**Description.** Apply standard cloud, network, identity, and platform hardening to AI workloads: isolated runtimes, network segmentation, secrets management, patching, and image hygiene. AI is not an excuse to skip the basics.

**Why it matters.** Most real-world AI breaches start at the infrastructure layer: a leaked key, an unsegmented network, a vulnerable container. The AI-specific threats layer on top of unresolved foundational risks.

**How to implement.**

- Run AI workloads in isolated, network-segmented environments
- Use a secrets manager; forbid credentials in prompts, code, or configs
- Keep model-serving and tool-runtime images patched and minimal
- Apply egress controls to restrict where agents can reach
- Harden MCP servers with auth, TLS, and network ACLs

**Common pitfalls.**

- So-called temporary API keys in .env files that stick around
- MCP servers on public networks with no authentication
- Treating a model container like a black box that just works
- Letting AI egress traffic bypass the standard proxy/filter

**References.**

- [Databricks DASF — Infrastructure Security Controls](https://www.databricks.com/resources/whitepaper/databricks-ai-security-framework-dasf) — local copy: [`docs/Databricks-DASF-Reference.md`](Databricks-DASF-Reference.md)

---

<a id="c011"></a>
### C011 — Model & Data Integrity

- **Mitigates:** [T003: AI Supply Chain Compromise](#t003), [T004: Data & Model Integrity Poisoning](#t004)

**Description.** Verify provenance and integrity of models, datasets, and embeddings at ingest time and continuously; detect drift and tampering; keep signed, reproducible records.

**Why it matters.** Poisoning and supply-chain attacks require a notion of "ground truth" to detect against. Integrity controls — hashes, signatures, drift detection — are the detective layer that makes prevention enforceable.

**How to implement.**

- Pin and checksum every model and dataset artefact
- Sign fine-tuning datasets and track their inputs in the AI-BOM
- Monitor embedding distribution and retrieval-quality metrics for drift
- Review RAG corpus changes through a pull-request-style process
- Periodically re-verify remote tool schemas against stored hashes

**Common pitfalls.**

- Downloading models over HTTP with no verification
- Accepting fine-tuning data submissions with no schema review
- No baseline metrics, so drift has nothing to compare against
- Letting the RAG corpus evolve freely and silently

**References.**

- [OWASP LLM04 — Data and Model Poisoning mitigations](https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c012"></a>
### C012 — Rate Limiting & Resource Management

- **Mitigates:** [T008: Resource Abuse & Service Disruption](#t008)

**Description.** Protect AI surfaces with input/output size caps, request rate limits, cost budgets, and anomaly detection tied to both user and agent identity.

**Why it matters.** Consumption-billed LLMs make denial-of-wallet attacks economically asymmetric: an attacker spends pennies to cost you thousands. Rate limiting is an availability *and* cost control.

**How to implement.**

- Enforce per-user, per-agent, and global request rate limits
- Cap max input and output token counts at the gateway
- Set hard monthly budgets with automatic shutoff on overshoot
- Alert on cost/latency anomalies per agent or tool
- Gate expensive tools (long-context, code execution) behind stricter limits

**Common pitfalls.**

- Rate-limiting only at the user level, not the agent level
- No output cap, enabling model-extraction-by-maximum-response
- Alerts on anomalies but no automatic action
- Forgetting that subagents multiply effective request rate

**References.**

- [OWASP LLM10 — Unbounded Consumption mitigations](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c013"></a>
### C013 — Transparency & AI Governance

- **Mitigates:** [T002: Sensitive Data Exposure](#t002), [T007: AI Misinformation & Hallucination](#t007), [T013: Unmanaged AI Infrastructure](#t013), [T014: Human-AI Trust Manipulation](#t014)

**Description.** Disclose AI use clearly, document model and data lineage, maintain policies for acceptable use, and report on AI risk to the people who own it.

**Why it matters.** Governance is how AI controls survive organizational change. A risk register, an owned-by-someone registry, and a transparent disclosure practice turn ad-hoc controls into durable ones.

**How to implement.**

- Label AI-generated content clearly in customer-facing surfaces
- Maintain a registry of AI systems with owner, purpose, data, and risk rating
- Publish acceptable-use, privacy, and escalation policies for each system
- Report AI risk (exposure, incidents, mitigations) to an owning executive
- Align governance artefacts with applicable regulations (NIST AI RMF, EU AI Act)

**Common pitfalls.**

- An AI policy that lives only as a slide deck
- Governance artefacts that go stale within a quarter
- No single owner accountable for each AI system
- Disclosure framed as legal CYA, not user-serving transparency

**References.**

- [OWASP LLM Top 10 — governance guidance](https://genai.owasp.org/llm-top-10/) — local copy: [`docs/OWASP-LLM-Top10.md`](OWASP-LLM-Top10.md)

---

<a id="c014"></a>
### C014 — Incident Response & Recovery

- **Mitigates:** _(no threats currently reference this control)_

**Description.** Extend the existing incident-response playbook to cover AI-specific failure modes: prompt injection, data poisoning, model compromise, rogue agent behavior, and runaway cost events.

**Why it matters.** AI incidents look different from classic ones — the "compromise" may be a pattern in a vector store, not a shell on a host. Response procedures must include rollback paths that traditional playbooks do not: re-embedding, retraining, and model rollback.

**How to implement.**

- Define AI-specific incident categories and severity levels
- Document rollback paths (model version, RAG snapshot, tool registry)
- Include AI components in tabletop exercises
- Maintain a forensic log retention policy that covers prompts and tool calls
- Define a communications plan for AI-specific disclosures

**Common pitfalls.**

- Treating "the model said something wrong" as a product bug, not an incident
- No way to roll back a fine-tune or RAG update quickly
- Forensic logs discarded before the incident is discovered
- IR playbook never updated once an AI system is in prod

**References.**

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

---


## Maintenance notes

This file is regenerated from `src/quin_scanner/rules/risk_taxonomy.yaml`.

- Edit prose, references, and KRIs in the YAML, then run
  `python scripts/generate_risk_framework_docs.py` to refresh this file.
- CI runs `python scripts/generate_risk_framework_docs.py --check` to fail
  pull requests whose YAML and Markdown have drifted out of sync.
- Anchors are stable: `#t001`..`#t014` for threats and `#c001`..`#c014` for
  controls. External links (including the HTML scan report) depend on those
  anchors — do not rename them without coordinating a downstream migration.
