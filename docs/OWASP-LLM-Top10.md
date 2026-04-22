# OWASP LLM Top 10 — 2025 Edition Quick Reference

**Source:** OWASP Top 10 for Large Language Model Applications
**Version:** 2025 (published November 18, 2024)
**Full document:** `OWASP_LLM_Top10_2025.pdf` (in this folder)
**URL:** https://genai.owasp.org

Use this reference during **Phase 2 (Threat Modeling)** to assess applicability of each LLM threat, and during **Phase 5 (Remediation)** to source specific mitigations.

---

## Key Changes from 2023 → 2025

| Change | Detail |
|---|---|
| **LLM07 NEW** | System Prompt Leakage — added as standalone entry |
| **LLM08 NEW** | Vector and Embedding Weaknesses — RAG-specific risks |
| **LLM02 renamed** | Sensitive Information Disclosure (was LLM06) |
| **LLM03 renamed** | Supply Chain (was LLM05, expanded) |
| **LLM04 renamed** | Data and Model Poisoning (was LLM03, expanded from Training Data Poisoning) |
| **LLM05 renamed** | Improper Output Handling (was LLM02, same concept) |
| **LLM06 renamed** | Excessive Agency (was LLM08, same concept) |
| **LLM09 renamed** | Misinformation (was LLM09 Overreliance, expanded) |
| **LLM10 renamed** | Unbounded Consumption (was LLM04 Model DoS, expanded to include model extraction/theft) |
| **LLM07:2023 REMOVED** | Insecure Plugin Design — merged into LLM06 Excessive Agency |
| **LLM10:2023 REMOVED** | Model Theft — merged into LLM10 Unbounded Consumption and LLM03 Supply Chain |

---

## LLM01:2025 Prompt Injection

**Description:** Prompt injection occurs when user inputs alter the LLM's behavior or output in unintended ways. Attacks can be direct (user manipulates their own prompt) or indirect (malicious content embedded in external data sources the model retrieves, such as documents, web pages, or tool outputs). Multimodal prompt injection via images, audio, or video is an emerging variant.

**Key Risk Factors:**
- User input passed directly to model without sanitization
- Agent retrieves external content (RAG, web browsing, email reading)
- Model output used to trigger downstream actions or tool calls
- Insufficient privilege separation between user instructions and external data

**Prevention and Mitigation Strategies:**
1. Constrain model behavior — define expected behavior precisely in system prompts and enforce it with external guardrails
2. Validate output formats — require structured outputs and validate before passing downstream
3. Input/output filtering — use a secondary guard model or classifier to evaluate inputs before they reach the main model
4. Privilege control and least privilege — limit what the model can access and do; separate user-supplied data from system instructions
5. Human approval for high-risk actions — require human-in-the-loop for consequential or irreversible operations
6. Segregate external content — clearly mark and isolate content retrieved from external sources; treat as untrusted
7. Adversarial testing — red-team the system for prompt injection vulnerabilities, including indirect injection via documents and RAG

**Assessment Notes:** Always applicable when user input reaches the model. Severity amplified in agentic systems — cross-reference with ASI01 (Agent Goal Hijack) for combined scoring.

---

## LLM02:2025 Sensitive Information Disclosure

**Description:** LLMs may inadvertently reveal sensitive information including PII, proprietary algorithms, financial records, health records, confidential business data, or security credentials. This can occur through training data memorization, system prompt leakage, or the model inferring and disclosing information from context.

**Key Risk Factors:**
- PII or sensitive data present in training data or fine-tuning datasets
- Sensitive data in RAG knowledge bases accessible without proper access controls
- System prompts containing credentials, connection strings, or internal logic
- Insufficient data classification and access governance at the model layer

**Prevention and Mitigation Strategies:**
1. Data sanitization — scrub PII and sensitive data from training data and RAG content
2. Access controls — implement role-based access controls on knowledge bases and retrieval systems; apply need-to-know
3. Federated learning — train on distributed data without centralizing sensitive information
4. Differential privacy — apply noise to training data to prevent memorization of individual records
5. Transparency and disclosure — communicate to users what data the model was trained on and its limitations
6. Homomorphic encryption — encrypt sensitive data used in computations where feasible
7. Tokenization and redaction — tokenize or redact PII before submission to external LLM APIs; apply Zero Data Retention agreements with vendors

**Assessment Notes:** Cross-reference with Section 1 Q5 (data classification) and Section 2 questions on data security controls. High-severity when Sensitive Personal data or Secret Data is involved (triggers High Impact tier).

---

## LLM03:2025 Supply Chain

**Description:** LLM supply chain vulnerabilities span the entire lifecycle: training data sources, pre-trained models, fine-tuning datasets, third-party plugins and extensions, model repositories, and deployment infrastructure. Compromised components can introduce backdoors, biases, or vulnerabilities that persist through deployment.

**Key Risk Types:**
1. Vulnerable third-party packages in training or serving environments
2. Licensing risks from training data or model weights
3. Use of outdated or deprecated models with known vulnerabilities
4. Vulnerable pre-trained models (poisoned base models from public repositories)
5. Weak model provenance — no signature or verification of model source
6. Vulnerable LoRA adapters or fine-tuning datasets from untrusted sources
7. Exploitation through collaborative model development processes
8. On-device LLM supply chain risks (edge deployments)
9. Unclear or unfavorable vendor terms and conditions on data use

**Prevention and Mitigation Strategies:**
1. Maintain a Software Bill of Materials (SBOM) and AI Bill of Materials (AI-BOM)
2. Verify model digital signatures and checksums before deployment
3. Pin model versions — avoid floating version references in production
4. Perform vendor security reviews before integrating third-party models, plugins, or data sources
5. Red-team pre-trained models for backdoors, biases, and unexpected behaviors before use
6. Use model repositories with verified provenance (e.g., signed artifacts)
7. Review and enforce licensing terms for training data and model weights
8. Implement peer review processes for MCP servers and third-party plugins (cross-reference ASI04)
9. Use sandboxed execution for untrusted tools or model components

**Assessment Notes:** Cross-reference with Section 2 responses on third-party model SBOMs and MCP server sources. Link to ASI04 (Agentic Supply Chain) when agentic components are present.

---

## LLM04:2025 Data and Model Poisoning

**Description:** Data and model poisoning involves the manipulation of training data, fine-tuning datasets, or embedding data to introduce vulnerabilities, backdoors, or biases into the model. Poisoning can occur at any stage of the AI lifecycle — pre-training, fine-tuning, or RAG embedding — and may be intentional (by malicious actors with data access) or unintentional (from unvetted data sources).

**Key Risk Factors:**
- Training or fine-tuning data sourced from unvetted or publicly scraped sources
- No data provenance tracking or integrity verification
- RAG knowledge base populated without content validation
- Insider access to training pipelines
- Collaborative or federated training with unverified participants

**Prevention and Mitigation Strategies:**
1. Data provenance tracking — maintain full lineage from raw source to training dataset
2. Anomaly detection on training data — detect statistical outliers and unexpected patterns that may indicate poisoning
3. Sandboxing training pipelines — isolate training infrastructure from production environments
4. Data Version Control (DVC) — track and audit all changes to training datasets
5. RAG grounding validation — validate content ingested into knowledge bases before vectorization
6. Adversarial testing of fine-tuned models — test for backdoors, unexpected behaviors, and bias amplification
7. Supply chain audits for training data — review licensing, provenance, and integrity of all data sources
8. Minimal fine-tuning privilege — restrict who can initiate fine-tuning jobs and on what data
9. Human review of synthetic training data before use
10. Monitor model output drift post-deployment for signs of poisoning effects

**Assessment Notes:** Cross-reference with DASF 2.x (Data Preparation risks) and DASF 4.x–5.x (Training risks). If Section 2 indicates data is used for training/fine-tuning, this is a High Impact trigger.

---

## LLM05:2025 Improper Output Handling

**Description:** Improper Output Handling refers to insufficient validation, sanitization, and handling of LLM-generated outputs before they are passed to downstream components or systems. Since LLM-generated content can be controlled through prompt input, this vulnerability is similar to providing users indirect access to additional functionality. Successful exploitation can lead to XSS, CSRF, SSRF, privilege escalation, or remote code execution.

**Key Risk Factors:**
- LLM output rendered directly in a web browser without encoding (XSS risk)
- LLM-generated SQL queries executed without parameterization (SQL injection risk)
- LLM output used to construct file paths without sanitization (path traversal risk)
- LLM-generated code executed directly in a shell or eval function (RCE risk)
- Third-party extensions that do not validate LLM outputs before acting on them

**Prevention and Mitigation Strategies:**
1. Zero-trust approach — treat model output as untrusted user input; apply full input validation on responses before passing to backend functions
2. Follow OWASP ASVS guidelines for input validation and sanitization
3. Encode model output before rendering — use context-appropriate encoding (HTML for web, SQL escaping for database queries)
4. Implement context-aware output encoding based on where LLM output will be used
5. Use parameterized queries or prepared statements for all database operations involving LLM output
6. Employ strict Content Security Policies (CSP) to mitigate XSS risks from LLM-generated content
7. Implement robust logging and monitoring to detect unusual patterns in LLM outputs

**Assessment Notes:** Applies whenever LLM output is consumed by another system, rendered in a UI, or passed to code execution environments. Distinct from LLM06 (Excessive Agency) — this concerns scrutiny of what the model outputs; Excessive Agency concerns what actions the system takes.

---

## LLM06:2025 Excessive Agency

**Description:** Excessive Agency occurs when an LLM-based system is granted more capabilities, permissions, or autonomy than necessary, enabling damaging actions in response to unexpected, ambiguous, or manipulated LLM outputs. Root causes are: excessive functionality (unnecessary tools/extensions), excessive permissions (overprivileged access to downstream systems), and excessive autonomy (no human approval for consequential actions). This entry subsumes the former Insecure Plugin Design (LLM07:2023).

**Key Risk Factors:**
- Agent has access to tools it doesn't need for its defined purpose
- Extensions with broad permissions (e.g., read+write+delete when only read is needed)
- No human-in-the-loop for high-impact or irreversible actions
- Agent uses high-privileged service account rather than user-scoped credentials
- LLM plugin uses open-ended commands (e.g., shell access) rather than scoped functions

**Prevention and Mitigation Strategies:**
1. Minimize extensions — only expose tools and extensions the agent actually needs
2. Minimize extension functionality — limit each extension to the minimum operations required
3. Avoid open-ended extensions — prefer scoped functions over shell commands or generic URL fetchers
4. Minimize extension permissions — grant extensions only the minimum permissions on downstream systems (e.g., read-only where only read is needed)
5. Execute extensions in user's context — use OAuth with minimum required scope; avoid shared high-privilege service accounts
6. Require user approval — implement human-in-the-loop for high-impact actions (e.g., send email, delete file, post to social media)
7. Complete mediation — enforce authorization at the downstream system level, not relying solely on the LLM to decide what is allowed
8. Sanitize LLM inputs and outputs — follow OWASP ASVS; use SAST and DAST/IAST in development pipelines

**Assessment Notes:** Cross-reference with ASI02 (Tool Misuse), ASI03 (Privilege Abuse), and DASF 13.1–13.15 (Agents — Core risks). Always applicable when agent/MCP/tool-use is present. Triggers Medium Impact tier (or High if automated actions with no human in loop).

---

## LLM07:2025 System Prompt Leakage

**Description:** NEW in 2025. System prompt leakage refers to the risk that system prompts used to configure LLM behavior contain sensitive information that can be extracted by adversarial users. The real security risk is not the disclosure of prompt wording itself — it is that developers have embedded credentials, security-critical logic, or role/permission information in the system prompt, treating it as a security control when it is not. Attackers use leaked prompts to facilitate further attacks.

**Key Risk Types:**
1. Exposure of sensitive functionality — system prompt contains API keys, database credentials, or internal architecture details
2. Exposure of internal rules — prompt reveals decision-making logic or business rules attackers can exploit to bypass controls
3. Revealing filtering criteria — prompt reveals what content is blocked, allowing crafted evasion inputs
4. Disclosure of permissions and user roles — prompt reveals role structures enabling privilege escalation attacks

**Prevention and Mitigation Strategies:**
1. Separate sensitive data from system prompts — never embed API keys, credentials, connection strings, or role/permission structures in system prompts; externalize to secure systems
2. Avoid reliance on system prompts for strict behavior control — use external systems for deterministic security enforcement, not LLM system prompt instructions
3. Implement guardrails — use an independent system outside the LLM to inspect output and verify compliance with expectations
4. Enforce security controls independently from the LLM — use separate agents with least privilege for tasks requiring different access levels; never delegate authorization decisions to the LLM

**Assessment Notes:** Apply when the system uses LLMs with custom system prompts, especially when those prompts control access to tools, data, or functionality. Cross-reference with LLM01 (Prompt Injection) — leaked prompt contents enable more targeted injection attacks.

---

## LLM08:2025 Vector and Embedding Weaknesses

**Description:** NEW in 2025. Weaknesses in how vectors and embeddings are generated, stored, or retrieved present significant security risks in RAG-based LLM systems. They can be exploited to inject harmful content, manipulate model outputs, or access sensitive information stored in the vector database.

**Key Risk Types:**
1. Unauthorized access and data leakage — inadequate access controls allow users to retrieve embeddings containing sensitive data; cross-tenant leakage in shared vector databases
2. Cross-context information leaks and federation knowledge conflict — in multi-tenant environments, embeddings from one user/tenant may be inadvertently retrieved by another; data from multiple sources may conflict
3. Embedding inversion attacks — attackers reconstruct source information from embedding vectors, compromising data confidentiality
4. Data poisoning attacks — intentional or unintentional malicious content introduced into the RAG knowledge base affects retrieval and model outputs
5. Behavior alteration — retrieval augmentation can inadvertently alter foundational model behavior (e.g., reducing empathy or changing response tone)

**Prevention and Mitigation Strategies:**
1. Permission and access control — implement fine-grained, permission-aware vector and embedding stores; enforce strict logical and access partitioning by user/tenant/data classification
2. Data validation and source authentication — implement robust data validation pipelines for knowledge sources; audit for hidden content and poisoning; accept data only from verified sources
3. Data review for combination and classification — when combining data from multiple sources, review thoroughly; tag and classify content to control access levels and prevent mismatch
4. Monitoring and logging — maintain immutable logs of retrieval activities to detect suspicious behavior

**Assessment Notes:** Apply when the system uses RAG, vector databases, or embedding-based retrieval. Always check for multi-tenant deployments where cross-context leakage is a material risk. Cross-reference with LLM04 (Data and Model Poisoning) for poisoning of the RAG knowledge base.

---

## LLM09:2025 Misinformation

**Description:** Misinformation occurs when LLMs produce false or misleading information that appears credible. The primary cause is hallucination — the model generates content that sounds correct but is fabricated. A related issue is overreliance, where users place excessive trust in LLM outputs without independent verification. This can lead to security breaches, reputational damage, and legal liability.

**Key Risk Types:**
1. Factual inaccuracies — model produces incorrect statements leading to harmful decisions (e.g., Air Canada chatbot lawsuit)
2. Unsupported claims — model generates baseless assertions in high-stakes contexts (legal, medical, financial)
3. Misrepresentation of expertise — model misleads users about its level of knowledge or certainty
4. Unsafe code generation — model suggests insecure or nonexistent code libraries, introducing vulnerabilities when integrated

**Prevention and Mitigation Strategies:**
1. Retrieval-Augmented Generation (RAG) — use verified external knowledge bases to ground model responses and reduce hallucination
2. Model fine-tuning — apply parameter-efficient tuning (PET) and chain-of-thought prompting to improve factual accuracy
3. Cross-verification and human oversight — require human review for high-stakes outputs; implement fact-checking processes; train reviewers to avoid overreliance on AI
4. Automatic validation mechanisms — implement automated tools to validate key outputs in high-stakes environments
5. Risk communication — clearly communicate to users the model's limitations and potential for misinformation in the UI
6. Secure coding practices — establish code review processes to verify AI-generated code before integration, particularly library dependencies
7. User interface design — label AI-generated content clearly; integrate content filters; be specific about intended use case limitations
8. Training and education — provide users with training on LLM limitations and the need for independent verification

**Assessment Notes:** Particularly important for customer-facing applications and use cases where LLM output influences consequential decisions (financial, medical, legal, operational). Cross-reference with Comp. Q12 (human-in-the-loop) and ASI09 (Human-Agent Trust Exploitation).

---

## LLM10:2025 Unbounded Consumption

**Description:** Unbounded Consumption occurs when an LLM application allows excessive or uncontrolled inference requests, enabling denial of service (DoS), economic losses (Denial of Wallet / DoW), and model theft through extraction. This entry expands the former Model DoS (LLM04:2023) to also cover model extraction and IP theft through excessive API use.

**Key Risk Types:**
1. Variable-length input flood — overloading the LLM with numerous inputs of varying lengths to exploit processing inefficiencies
2. Denial of Wallet (DoW) — generating excessive operations to exploit pay-per-use cloud AI billing, causing unsustainable financial burdens
3. Continuous input overflow — sending inputs exceeding the context window to cause excessive resource use
4. Resource-intensive queries — crafting inputs designed to trigger maximally expensive computations
5. Model extraction via API — collecting sufficient outputs to replicate a partial or functional shadow model
6. Functional model replication — using the target model to generate synthetic training data for fine-tuning a functionally equivalent model
7. Side-channel attacks — exploiting input filtering techniques to harvest model weights or architectural information

**Prevention and Mitigation Strategies:**
1. Input validation — enforce strict size limits on all inputs
2. Limit exposure of logits and logprobs — restrict or obfuscate `logit_bias` and `logprobs` in API responses
3. Rate limiting — apply per-user and per-source request rate limits and quotas
4. Resource allocation management — monitor and cap resources per user or request dynamically
5. Timeouts and throttling — set processing timeouts for resource-intensive operations
6. Sandbox techniques — restrict the LLM's access to network resources, internal services, and APIs; mitigates insider threats and side-channel attacks
7. Comprehensive logging, monitoring, and anomaly detection — continuously monitor resource usage patterns
8. Watermarking — embed watermarks in outputs to detect unauthorized use or model replication
9. Graceful degradation — design for partial functionality under heavy load rather than complete failure
10. Limit queued actions and scale robustly — implement dynamic scaling and load balancing with action queue limits
11. Adversarial robustness training — train models to detect and resist adversarial queries and extraction attempts
12. Access controls — implement RBAC and least privilege for access to model repositories and training environments
13. Centralized ML model inventory — maintain a governed model registry for all production models

**Assessment Notes:** Always applicable for externally exposed APIs. DoW risk is especially relevant for cloud-hosted models on consumption billing. Model extraction risk increases when logprobs are exposed or output volume is unrestricted.

---

## Quick Reference Table

| ID | Threat (2025) | Prior ID (2023) | Status | Apply When |
|---|---|---|---|---|
| LLM01 | Prompt Injection | LLM01 | Unchanged | User input reaches model; agent retrieves external content |
| LLM02 | Sensitive Information Disclosure | LLM06 | Renumbered | Sensitive/PII data in training data, RAG, or system prompts |
| LLM03 | Supply Chain | LLM05 | Expanded | Third-party models, plugins, training data, MCP servers |
| LLM04 | Data and Model Poisoning | LLM03 | Expanded | Training/fine-tuning/RAG data from external or unvetted sources |
| LLM05 | Improper Output Handling | LLM02 | Renumbered | LLM output consumed by downstream systems, UI, or code execution |
| LLM06 | Excessive Agency | LLM08 | Expanded | Agent/tool-use present; subsumes former Insecure Plugin Design |
| LLM07 | System Prompt Leakage | — | NEW | Custom system prompt, especially with credentials or access logic |
| LLM08 | Vector and Embedding Weaknesses | — | NEW | RAG-based systems, vector databases, embedding stores |
| LLM09 | Misinformation | LLM09 | Renamed/Expanded | High-stakes outputs; customer-facing applications; code generation |
| LLM10 | Unbounded Consumption | LLM04 | Expanded | Externally accessible API; cloud billing; high-volume use |
