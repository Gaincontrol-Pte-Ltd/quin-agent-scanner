# OWASP Top 10 for Model Context Protocol (MCP) — Quick Reference

**Source:** OWASP MCP Security Project — https://owasp.org/www-project-mcp-top-10/
**Version:** v0.1 (Beta, 2025) — Living document, actively evolving
**Project Lead:** Vandana Verma Sehgal
**License:** CC BY-NC-SA 4.0

Use this framework during **Phase 2 (Threat Modeling)** whenever the assessed system uses MCP servers, MCP-based tool orchestration, or multi-agent architectures. Apply in addition to OWASP LLM Top 10 and OWASP Agentic Top 10 for complete MCP coverage.

---

## What is MCP?

The Model Context Protocol (MCP) defines the operational and behavioral interface between AI models and the external tools, data sources, and services they interact with. MCP governs how agents discover tools, invoke functions, share context, and authenticate — making it a high-value attack surface distinct from the LLM layer itself.

---

## When to Apply

Apply OWASP MCP Top 10 during Phase 2 when ANY of the following is true:
- The system uses MCP servers or MCP-based tool orchestration
- Agents invoke external APIs, databases, file systems, or shell commands via MCP
- The system uses multi-agent communication (A2A protocols, orchestration layers)
- Third-party MCP plugins or community tools are integrated
- Section 1 Q5 or Section 2 questionnaire responses indicate MCP usage

---

## The MCP Top 10

### MCP01:2025 — Token Mismanagement & Secret Exposure

**Description:** Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs expose systems to unauthorized access. MCP's stateful architecture creates unique risk: tokens can be inadvertently stored, indexed, or retrieved later through user prompts, system recalls, or log inspection.

**Key Risk Indicators:**
- Hard-coded credentials in MCP server configurations or tool definitions
- API keys or tokens stored in conversational memory across sessions
- Debug logs or telemetry containing unredacted secrets
- Long-lived tokens without rotation policies
- Static shared service accounts instead of user-scoped credentials

**Attack Scenarios:**
- User prompts the model about a past session; the model reproduces stored API keys from memory
- Attacker accesses debug logs and extracts tokens used by the MCP server
- Malicious prompt poisons shared context, triggering secret disclosure during an unrelated query

**Prevention and Mitigation Strategies:**
1. Use secure vault storage (e.g., HashiCorp Vault, AWS Secrets Manager) — never hard-code secrets in configs or schemas
2. Enforce short-lived, scoped tokens with automated rotation
3. Isolate sensitive data from model memory — use ephemeral credentials that expire after each session
4. Protect logs with access controls; implement log redaction before storage
5. Establish governance policies for credential lifecycle management (issuance, rotation, revocation)

**Cross-reference:** LLM07:2025 (System Prompt Leakage), LLM02:2025 (Sensitive Information Disclosure), ASI03 (Identity & Privilege Abuse)

---

### MCP02:2025 — Privilege Escalation via Scope Creep

**Description:** Loosely defined permissions expand over time, allowing agents excessive capabilities that enable unauthorized actions such as repository modification, data exfiltration, or destructive writes. Permissions granted for development or testing purposes are often never formally revoked.

**Key Risk Indicators:**
- MCP tool permissions broader than required for the agent's current purpose
- Permissions from development/test phases left active in production
- No automated review or expiry mechanism for granted scopes
- Agents can perform write/delete operations when only read is required

**Attack Scenarios:**
- An agent granted read access for summarization retains write access from a previous testing phase and overwrites production data
- Lateral movement: an agent exploits accumulated scopes to pivot from one tool to a higher-privileged connected system

**Prevention and Mitigation Strategies:**
1. Enforce least-privilege design at tool definition time — scope each tool permission to the minimum required operation
2. Implement automated scope expiry — unused permissions should expire after a defined period
3. Conduct regular access reviews before production deployment and periodically thereafter
4. Separate permission profiles for dev/test vs. production environments
5. Monitor and alert on permission usage patterns inconsistent with the agent's stated purpose

**Cross-reference:** LLM06:2025 (Excessive Agency), ASI03 (Identity & Privilege Abuse)

---

### MCP03:2025 — Tool Poisoning

**Description:** Adversaries compromise MCP tools, schemas, or their outputs by injecting malicious, misleading, or biased context to manipulate model behavior. This includes schema poisoning (tampering with the contract that defines tool behavior so benign operations map to destructive actions), tool shadowing (replacing a legitimate tool with a malicious lookalike), and rug pulls (legitimate tools turning malicious after deployment).

**Key Risk Indicators:**
- Tool schemas fetched remotely without integrity verification
- Tool registries without access controls or multi-person approval gates
- CI/CD pipelines that auto-promote schema changes without attestation
- No runtime schema validation before tool execution
- Community or third-party tools without provenance verification

**Attack Scenarios:**
- Schema poisoning: an attacker modifies a schema so a `list_files` call maps internally to `delete_all_files`; the agent executes the malicious action while audit logs show a seemingly valid operation
- Tool shadowing: a malicious MCP server registers a tool with the same name as a legitimate one; the agent invokes the attacker's version
- Rug pull: a vetted third-party MCP plugin updates maliciously post-deployment

**Prevention and Mitigation Strategies:**
1. Implement signed schemas with cryptographic integrity verification — reject unsigned or unverified schemas
2. Use immutable, version-controlled tool registries with multi-person approval required for changes
3. Enforce strict access controls on tool and schema registries
4. Apply semantic policy enforcement — validate that declared schema semantics match actual behavior at runtime
5. Maintain complete provenance tracking for all tool versions
6. Implement runtime guardrails that prevent immediate schema-driven execution of destructive operations without human approval
7. On compromise: revoke affected versions, revert to validated schema hashes, rotate credentials, and forensically analyze affected agents

**Cross-reference:** LLM03:2025 (Supply Chain), ASI04 (Agentic Supply Chain Vulnerabilities), ASI02 (Tool Misuse)

---

### MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering

**Description:** Compromised dependencies, libraries, or packages used by MCP servers or agents can alter agent behavior or introduce execution-level backdoors. This extends traditional software supply chain risk to the AI/MCP layer.

**Key Risk Indicators:**
- MCP server dependencies not pinned to verified versions
- No Software Bill of Materials (SBOM) or AI-BOM for MCP deployments
- Third-party MCP plugins installed without security review
- No dependency integrity monitoring in CI/CD pipelines
- Unverified packages from community registries

**Attack Scenarios:**
- A compromised npm/PyPI package used by an MCP server exfiltrates tool invocation parameters to an attacker-controlled endpoint
- A typosquatted MCP plugin is installed by a developer and introduces a backdoor

**Prevention and Mitigation Strategies:**
1. Implement signed components — verify signatures for all dependencies and MCP plugins
2. Maintain an SBOM and AI-BOM for all MCP deployments; review on every update
3. Pin dependency versions; use lock files and hash verification
4. Deploy dependency monitoring tools with continuous vulnerability scanning
5. Review all third-party MCP plugins before installation; prefer community-vetted sources with provenance
6. Sandbox MCP server execution to limit blast radius if a dependency is compromised

**Cross-reference:** LLM03:2025 (Supply Chain), ASI04 (Agentic Supply Chain Vulnerabilities)

---

### MCP05:2025 — Command Injection & Execution

**Description:** AI agents in MCP environments can be exploited through command injection, where untrusted input — from user prompts, retrieved documents, or third-party tool outputs — gets constructed into system commands, shell scripts, or API calls without proper validation or sanitization.

**Key Risk Indicators:**
- Agent constructs shell commands or SQL queries by concatenating user/external input
- Tool wrappers pass unsanitized agent outputs to `exec()`, `subprocess.run(shell=True)`, or `eval()`
- No allowlisting of permitted commands at the tool boundary
- Auto-execution of model-generated code without human review
- Failure to escape special characters in command parameters

**Attack Scenarios:**
- Shell injection: user requests log listing with embedded `; cat /etc/passwd`; agent generates compound command exposing system files
- SQL injection: prompt embeds `'; DROP TABLE users;--`; agent constructs and executes the destructive query through string interpolation
- Chained execution: operators like `&&`, `|`, or `;` combine commands enabling arbitrary code execution

**Prevention and Mitigation Strategies:**
1. Implement command allowlists — reject any command not explicitly permitted; block shell metacharacters
2. Use parameterized execution APIs — never construct commands via string concatenation; use parameterized SQL and subprocess argument lists
3. Disable `eval()` and `shell=True` in all tool wrappers
4. Sandbox tool execution in containers or VMs with resource limits, timeouts, and network restrictions
5. Execute with least privilege — run as non-root; restrict environment variable access
6. Require human approval before execution of destructive or irreversible operations
7. Maintain audit trails of all command executions

**Detection Indicators:** Shell metacharacters in logs, unexpected privilege escalation, sensitive file access patterns, suspicious syscall behavior, resource consumption spikes

**Cross-reference:** LLM05:2025 (Improper Output Handling), ASI05 (Unexpected Code Execution / RCE), LLM01:2025 (Prompt Injection)

---

### MCP06:2025 — Intent Flow Subversion (Prompt Injection via Contextual Payloads)

**Description:** Malicious instructions embedded in retrieved context (documents, tool outputs, RAG results, external data) hijack agent intent toward attacker objectives. Unlike direct prompt injection, the attack occurs when the model retrieves a resource containing hidden instructions that override the user's original goal. The model treats retrieved text as authoritative instructions rather than passive data.

**Key Risk Indicators:**
- Retrieved content treated as potential instructions rather than passive data
- No validation that planned tool calls align with original user goals before execution
- Agent generates revised execution plans without human oversight
- System instructions, user intent, and untrusted external content are merged indistinguishably in the context window
- No "untrusted content" tagging or context provenance tracking

**Attack Scenarios:**
- Repository manipulation: a document contains hidden instructions embedded as security language that triggers the agent to delete a branch when the user only asked for a code review
- Tool-output poisoning: a status-check tool returns content that redirects the agent into unauthorized data exports

**Prevention and Mitigation Strategies:**
1. Anchor user goals — use relevance scoring and policy decision points to validate that tool calls match the original user intent
2. Independent verification — use an isolated guardrail model to verify planned actions against original goals before execution
3. Treat MCP-retrieved content as untrusted by default — never execute instructions found in retrieved data without validation
4. Tag context provenance — label retrieved content as `[UNTRUSTED_CONTEXT]` to enforce passive interpretation rules
5. Detect intent drift — alert when agent plans diverge significantly from original intent; require human re-authentication for high-impact actions

**Cross-reference:** LLM01:2025 (Prompt Injection), ASI01 (Agent Goal Hijack), ASI06 (Memory & Context Poisoning)

---

### MCP07:2025 — Insufficient Authentication & Authorization

**Description:** MCP servers, tools, and agents that fail to properly verify identities or enforce access controls expose critical attack paths. In multi-agent ecosystems, weak or missing identity validation allows unauthorized agents to impersonate legitimate services, escalate privileges, or bypass access boundaries.

**Key Risk Indicators:**
- No mutual authentication between agents and MCP servers
- MCP endpoints accessible without authentication
- No role-based access controls (RBAC) on tool invocations
- Shared service accounts used across multiple agents
- No session management or token validation on MCP server endpoints

**Attack Scenarios:**
- A rogue agent registers with an MCP server without authentication and gains access to all available tools
- A compromised agent impersonates a higher-privilege peer agent to escalate its capabilities
- Lateral movement: an agent with access to one MCP server leverages the lack of authorization to access connected services

**Prevention and Mitigation Strategies:**
1. Implement strong mutual identity verification for all agent-to-MCP-server interactions (mTLS, signed JWTs)
2. Enforce role-based access controls (RBAC) on all tool invocations — agents should only access tools within their defined role
3. Use short-lived, user-scoped credentials rather than shared service accounts
4. Apply the principle of least privilege at every authentication boundary
5. Implement session management — invalidate tokens after defined periods or on anomaly detection

**Cross-reference:** LLM06:2025 (Excessive Agency), ASI03 (Identity & Privilege Abuse), ASI07 (Insecure Inter-Agent Communication)

---

### MCP08:2025 — Lack of Audit and Telemetry

**Description:** Limited or absent logging of MCP tool invocations, agent decisions, context changes, and inter-agent communications impedes detection and incident response. Without immutable audit trails, unauthorized actions or data access may go completely undetected, and forensic investigation after an incident becomes impossible.

**Key Risk Indicators:**
- No centralized logging of MCP tool invocations and their parameters
- No record of context changes (what was written to/read from agent memory)
- Logs are mutable or accessible to the agents themselves
- No anomaly detection on tool usage patterns
- No integration with SIEM or security monitoring systems

**Attack Scenarios:**
- An attacker uses an agent to exfiltrate data through a series of tool calls; without audit logs, the breach is only discovered weeks later during a manual review
- A compromised agent modifies its own log entries to hide malicious actions

**Prevention and Mitigation Strategies:**
1. Maintain immutable audit trails documenting all tool invocations, their parameters, and outcomes
2. Log all context read/write events including agent ID, context ID, and timestamp
3. Store logs out-of-band — agents should have no write access to their own audit logs
4. Integrate with SIEM/XDR systems for real-time monitoring and alerting
5. Implement behavioral baselines — alert on deviations in tool call frequency, parameter patterns, or data volume
6. Retain logs for a period aligned with incident response and compliance requirements

**Cross-reference:** ASI08 (Cascading Failures), DASF controls on logging and monitoring

---

### MCP09:2025 — Shadow MCP Servers

**Description:** Unauthorized MCP deployments created by developers for convenience operate outside organizational security governance, often using default credentials, permissive configurations, or unsecured APIs. These rogue instances expose sensitive capabilities like data retrieval and tool execution without proper security controls, creating compliance risk and an unmonitored attack surface.

**Key Risk Indicators:**
- No central registry or inventory of all active MCP server instances
- Teams deploy MCP servers without security review or approval
- MCP services running on unusual ports outside standard infrastructure
- Security team cannot enumerate all active MCP instances
- No access controls or logging on unofficial deployments

**Attack Scenarios:**
- A developer's test MCP server with default credentials is indexed by a search engine and accessed by an attacker who uses it to reach production data
- An external attacker exploits a vulnerable framework version on an unpatched shadow MCP server
- A malicious plugin installed on a shadow MCP server contaminates production pipelines when output is inadvertently reused

**Prevention and Mitigation Strategies:**
1. Central registry — require all MCP instances to register through CI/CD pipelines with mandatory metadata (owner, purpose, data classification)
2. Continuous network scanning — deploy automated discovery tools to detect unauthorized MCP deployments on a weekly or more frequent basis
3. Configuration templates — publish and enforce secure default configurations requiring authentication and logging
4. IAM integration — mandate central identity providers and network segmentation; block unapproved endpoints at the network layer
5. Behavioral monitoring — alert on anomalous MCP traffic patterns and configuration drift from approved baselines
6. Developer education — provide approved sandbox environments for experimentation to reduce the shadow MCP incentive
7. Policy enforcement — integrate MCP governance into acceptable use policies with explicit consequences
8. Incident response — include shadow MCP detection in threat-hunting playbooks

**Cross-reference:** ASI04 (Agentic Supply Chain), LLM03:2025 (Supply Chain), LLM07:2025 (System Prompt Leakage)

---

### MCP10:2025 — Context Injection & Over-Sharing

**Description:** Sensitive information from one task, user, agent, or tenant leaks to another when agent context windows or shared vector stores lack proper isolation. The risk has two components: context injection (malicious content embedded in shared memory that persistently manipulates agent behavior) and over-sharing (context reused across isolated systems, violating data compartmentalization).

**Key Risk Indicators:**
- Agents or services share a common context buffer or vector store across users or tenants
- Context persists across sessions without TTL or auto-purge policies
- Sensitive data not classified or tagged before storage in shared context
- No per-agent/per-user namespace isolation in the vector database
- Multi-agent systems share context repositories without authorization controls

**Attack Scenarios:**
- Cross-team data leak: support and marketing agents share infrastructure; marketing agent inadvertently retrieves sensitive customer support transcripts
- Multi-tenant context bleed: inadequate vector store isolation allows one tenant's internal documents to appear in another tenant's retrieval results
- Persistent injection: attacker embeds persistent instructions in a shared context store, affecting multiple future agent sessions

**Prevention and Mitigation Strategies:**
1. Ephemeral context design — implement short-lived, session-specific contexts with automatic deletion post-task; avoid persistent memory unless explicitly governed
2. Isolation architecture — create separate namespace contexts for each user, agent, workflow, and tenant; restrict direct inter-agent memory access
3. Data classification — tag all context data (Public / Internal / Confidential / Restricted); prevent lower-trust agents from accessing higher-classification contexts
4. TTL and auto-purge policies — define context expiration timelines (session-end, 30 min, 24 hours max) with automated enforcement
5. Sanitization and redaction — scan and remove PII, secrets, tokens, and system identifiers before context storage using automated classification pipelines
6. Human approval controls — require review before sensitive context is exported, summarized, or shared across agents
7. Comprehensive logging — document all context read/write and purge events; integrate with SIEM/XDR
8. Injection detection — use pattern-detection models to block prompt-like content patterns attempting to persist in shared memory

**Cross-reference:** ASI06 (Memory & Context Poisoning), LLM08:2025 (Vector and Embedding Weaknesses), LLM01:2025 (Prompt Injection), LLM02:2025 (Sensitive Information Disclosure)

---

## Quick Reference Table

| ID | Threat | Severity Drivers | Apply When |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | Credentials in memory/logs; long-lived tokens | Any MCP deployment with API access |
| MCP02 | Privilege Escalation via Scope Creep | Overpermissioned tools; no scope expiry | Agents with tool/write access |
| MCP03 | Tool Poisoning | Remote schema fetching; no integrity checks | Third-party tools; community plugins |
| MCP04 | Supply Chain Attacks & Dependency Tampering | Unverified dependencies; no SBOM | Any MCP server with third-party packages |
| MCP05 | Command Injection & Execution | Shell/eval access; user input in commands | Tools that execute system commands or code |
| MCP06 | Intent Flow Subversion | Untrusted content in context; no intent anchoring | RAG-enabled agents; agents reading external data |
| MCP07 | Insufficient Authentication & Authorization | Unauthenticated MCP endpoints; shared accounts | All MCP server deployments |
| MCP08 | Lack of Audit and Telemetry | No centralized logging; mutable logs | All MCP deployments (always applicable) |
| MCP09 | Shadow MCP Servers | No inventory; dev deployments without governance | Organizations with multiple teams using MCP |
| MCP10 | Context Injection & Over-Sharing | Shared context stores; no TTL; no namespacing | Multi-user, multi-tenant, or multi-agent systems |

---

## Cross-Reference: OWASP MCP Top 10 ↔ OWASP LLM Top 10 (2025) ↔ OWASP Agentic Top 10

| MCP Threat | Related LLM (2025) | Related Agentic (ASI) | Combined Risk |
|---|---|---|---|
| MCP01 (Token Mismanagement) | LLM02, LLM07 | ASI03 | Credential theft via prompt; system prompt leakage |
| MCP02 (Scope Creep) | LLM06 | ASI03 | Escalating permissions enable unauthorized agentic actions |
| MCP03 (Tool Poisoning) | LLM03 | ASI02, ASI04 | Poisoned tools corrupt agentic decision-making at scale |
| MCP04 (Supply Chain) | LLM03 | ASI04 | MCP-layer supply chain amplifies agent ecosystem risk |
| MCP05 (Command Injection) | LLM05 | ASI05 | Agents execute injected code with elevated privileges |
| MCP06 (Intent Flow Subversion) | LLM01 | ASI01, ASI06 | Persistent goal hijack across agent sessions |
| MCP07 (Auth & AuthZ) | LLM06 | ASI03, ASI07 | Unauthorized agents gain full tool access |
| MCP08 (Lack of Audit) | — | ASI08 | Cascading failures go undetected without telemetry |
| MCP09 (Shadow MCP Servers) | LLM03, LLM07 | ASI04 | Unmonitored servers bypass all security controls |
| MCP10 (Context Injection) | LLM01, LLM02, LLM08 | ASI06 | Cross-session and cross-tenant data leakage at scale |

---

## How to Use in Phase 2 Threat Modeling

Apply MCP Top 10 as **Layer 4** of the threat modeling scan (after OWASP LLM, OWASP Agentic, and DASF), triggered specifically when MCP servers or MCP-based tool orchestration is confirmed.

For each MCP threat:
1. Check whether the system architecture exposes the relevant MCP component (tool schemas, context stores, MCP endpoints, CLI/shell access)
2. If the component exists, mark as **Applicable** and note supporting evidence from the questionnaire
3. If MCP09 (Shadow MCP) is flagged, always escalate — shadow servers undermine all other controls
4. Cross-reference with the corresponding LLM and Agentic threats using the table above; score the **highest** applicable severity
5. Record MCP threat IDs in the Threat Applicability Table alongside LLM and ASI IDs using the prefix `MCP`
