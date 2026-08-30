from __future__ import annotations

import json
from collections.abc import Callable

from quin_scanner.llm.base import BaseLLMProvider
from quin_scanner.models import (
    AgentProfile,
    ClassificationResult,
    EvidenceRef,
    ModelUsage,
    RiskIndicator,
    SynthesisResult,
    ToolUsage,
)
from quin_scanner.risk_taxonomy import build_threat_reference, filter_threats
from quin_scanner.rules.kri_predicates import EvidenceFacts

_SYSTEM_PROMPT = """\
You are an AI application analyst. Given scanner evidence from a repository, produce a \
structured JSON report. Reply with JSON only — no markdown fences, no explanation.

Output schema:
{
  "is_ai_application": <bool>,
  "framework": "<primary AI framework name, or 'unknown'>",
  "summary": "<2-3 sentence narrative suitable for a developer report>",
  "risk_signals": [
    {
      "signal": "<Key Risk Indicator text from the THREAT REFERENCE>",
      "threat_id": "<T0NN — the threat this KRI belongs to>",
      "recommended_controls": ["<control ID: control name>"],
      "evidence_refs": [
        {"file_path": "<scanner-found path>", "line_number": <int or null>, "scanner": "<scanner name>"}
      ]
    }
  ],
  "agents": [
    {
      "name": "<agent name>",
      "agent_type": "<supervisor|utility|worker|unknown>",
      "goal": "<one sentence>",
      "capabilities": ["<capability>"],
      "risk_signals": [
        {
          "signal": "<Key Risk Indicator text from the THREAT REFERENCE>",
          "threat_id": "<T0NN — the threat this KRI belongs to>",
          "recommended_controls": ["<control ID: control name>"],
          "evidence_refs": [
            {"file_path": "<scanner-found path>", "line_number": <int or null>, "scanner": "<scanner name>"}
          ]
        }
      ],
      "skills": ["<skill/playbook name — instructional workflows only>"],
      "tools": ["<tool name — executable functions only>"],
      "source_file": "<file path>"
    }
  ],
  "tool_usages": [
    {
      "tool_name": "<tool name>",
      "tool_type": "<tool_definition|skill|mcp_tool>",
      "service_category": "<category from the list below>",
      "source_file": "<file path>",
      "line_number": <int or null>
    }
  ]
}

Rules:
- agent_type must be one of: supervisor, utility, worker, unknown

- framework: Identify the PRIMARY AI framework the repo is built WITH (not a dependency it
  uses). Use the FRAMEWORK CANDIDATE (rule-based) in the evidence as your anchor. If the
  candidate is more specific than what you detect, prefer your detection. If the candidate
  is 'unknown', derive from all available evidence. NEVER return 'unknown' if any framework
  evidence is present — use 'LangChain', 'CrewAI', 'AutoGen', 'OpenAI Agents SDK',
  'Anthropic Agent SDK', 'Google ADK', 'Strands Agents', 'Microsoft Agent Framework',
  'LangChain Deep Agents', 'Agno', 'Mastra',
  'LlamaIndex', 'Haystack', 'Semantic Kernel', 'PromptFlow', 'Flowise', 'LangGraph',
  'MCP', 'Vercel AI SDK', or the best name you can
  infer. Do NOT name a transitive dependency (e.g. if LangChain is used by Flowise, the
  framework is 'Flowise', not 'LangChain').

- summary: Written for a developer reading a scan report — focus on what the system does,
  not how the scanner works. The summary MUST be a non-empty string of 2-4 sentences.
  Lead with the framework and what the repo does (use the README content if available in
  the scanner findings). If evidence is sparse, use: "<framework> repository that uses
  AI capabilities including: <capability_tags>." NEVER return an empty string, null, or
  a summary that mentions the scanner itself. Do not write "insufficient evidence" —
  always produce a best-effort description.

- risk_signals (repo-level): Cross-cutting risks that apply to the system as a whole and
  cannot be meaningfully attributed to any single agent. Use ONLY Key Risk Indicators
  from the THREAT REFERENCE below. Do NOT invent indicators outside the reference.
  Only flag a KRI when there is supporting evidence in the scanner findings.
  For each KRI: (1) set threat_id to the T0NN heading under which the KRI appears in the
  THREAT REFERENCE, and (2) include the recommended_controls listed for that threat.

  ALLOWED at repo level (cross-cutting in nature):
    * Supply chain (T003): pinning, SBOM, provenance, dependency hygiene
    * Resource abuse (T008): rate limiting, consumption-based billing exposure, model extraction
    * Observability (T012): centralized logging, anomaly detection, SIEM integration
    * Governance / unmanaged AI (T013): registry of agents, deploy review, port sprawl
    * System-wide data exposure (T002): system prompts containing secrets, hard-coded credentials in
      MCP/configuration, shared context stores without tenant isolation
    * System-wide infrastructure (T005): code execution capability without sandboxing as a platform property

  FORBIDDEN at repo level (must be per-agent only):
    * Any KRI whose subject is "Agent <verb>" — these belong on the specific agent doing the verb.
      Examples NOT allowed at repo level: "Agent retrieves external content", "Agent constructs
      shell commands by concatenating user/external input", "Agent has access to tools beyond its
      defined purpose", "Agent outputs fed into other agents without validation",
      "Agents handling financial transactions or official communications".
    * Any KRI describing a per-agent capability or output behavior — "Customer-facing applications
      where outputs influence decisions", "No RAG grounding or verification of model outputs",
      "Model output triggers downstream actions or tool calls", "Agent chains where output of one
      feeds into another", "No per-step validation in multi-step workflows".

  DO NOT DUPLICATE: If a KRI is going to appear on a specific agent's risk_signals (because that
  agent's evidence triggered it), do NOT also include it at the repo level. The repo-level list is
  reserved for risks that exist independently of any single agent.

- evidence_refs: For EVERY risk_signal you emit (repo-level and per-agent), include at least one
  evidence_ref pointing to a scanner finding from the Evidence block. Each ref MUST cite a
  file_path that appears in the Evidence (under "Scanner summaries", "AGENT INSTANCES",
  "TOOL DEFINITIONS", or "EXTERNAL SERVICES"). Do NOT invent file paths. The line_number is
  optional but use it when the Evidence block provides one. The scanner field is the name shown
  in brackets in the Evidence block (e.g. "ToolDefinitionScanner", "PromptDiscoveryScanner",
  "AgentInstanceScanner"). If you cannot ground a signal in a specific finding, omit the signal
  rather than fabricating an evidence_ref.

- risk_signals (per-agent): Agent-specific risks based on that agent's capabilities,
  tools, and permissions. Use ONLY Key Risk Indicators from the THREAT REFERENCE below.
  Do NOT invent indicators outside the reference.
  Only flag a KRI when there is supporting evidence for THAT SPECIFIC agent.
  For each KRI: (1) set threat_id to the T0NN heading under which the KRI appears in the
  THREAT REFERENCE, and (2) include the recommended_controls listed for that threat.

- agents: Populate using AGENT INSTANCES (rule-based) in the evidence as the PRIMARY source.
  For each instance, set name from the instance name, description/goal from surrounding
  comments or config description field if present. If AGENT INSTANCES is empty, infer agents
  from class names in code pattern findings (e.g. AssistantAgent, UserProxyAgent, Agent
  class instantiations). Return [] only if there is truly no agent evidence whatsoever.

- tools vs skills vs MCP — three distinct layers of agent capability:
  * Tools (tool_type="tool_definition"): Executable functions that agents invoke — API calls,
    code execution, file operations, database queries. Decorated functions (@tool,
    @function_tool), class-based tools (BaseTool subclasses), registered tool calls.
  * Skills (tool_type="skill"): Packaged instructional workflows — markdown or text files
    that teach an agent HOW to perform a task. Found in skills/, playbooks/, recipes/,
    instructions/ directories. These are NOT executable code — they are playbooks/recipes.
  * MCP tools (tool_type="mcp_tool"): References to MCP (Model Context Protocol) server
    connections. Configured in mcp.json, claude_desktop_config.json, etc. These represent
    the protocol connection layer, not executable tools.
  Set tool_type for each tool_usage entry accordingly. When uncertain, default to
  "tool_definition".

- agents[].tools: ONLY list executable tool/function names. Do NOT include skill/playbook
  references or MCP server names.
- agents[].skills: ONLY list skill/playbook references — instructional markdown files or
  packaged workflow names. Do NOT include executable tool names or MCP server names.

- tool_usages: Populate using TOOL DEFINITIONS (rule-based) and EXTERNAL SERVICES
  (rule-based) in the evidence as the PRIMARY source. You may add additional tools
  discovered from code analysis, but NEVER add model names or package names.
  Return [] only if there is truly no tool evidence.

- tool_usages MUST NOT contain LLM model names (e.g. gpt-4, gpt-4o, claude-3-sonnet,
  dall-e-3, llama-3, gemini-1.5-pro, text-embedding-ada-002). Those belong in model_usages
  only. tool_usages MUST NOT contain raw dependency/package names (e.g. faiss-cpu,
  qdrant-client, chromadb) unless they are explicitly registered as named tools in the code.
  Tools are functions, classes, or plugins that agents INVOKE to perform actions — not the
  models they call or the libraries they import.

- service_category: Classify EVERY tool_usage entry into one of these categories based on
  what the tool DOES (infer from its name, context, and surrounding code):
  * "web_search" — search engines, SERP queries (e.g. google_search, tavily_search)
  * "web_browsing" — page fetching, scraping, crawling (e.g. browse_url, scrape_page)
  * "code_execution" — running code, sandboxes, REPLs (e.g. execute_code, run_python)
  * "vector_database" — vector store operations (e.g. query_vectors, upsert_embeddings)
  * "database" — SQL/NoSQL/graph DB operations (e.g. run_query, neo4j_search)
  * "communication" — messaging, email, notifications (e.g. send_slack, send_email)
  * "document_processing" — PDF/DOCX parsing, OCR (e.g. parse_pdf, extract_text)
  * "image_generation" — image creation/editing (e.g. text_to_image, generate_image)
  * "voice_audio" — TTS, STT, audio processing (e.g. text_to_speech, transcribe)
  * "embeddings" — text-to-embedding operations (e.g. text_to_embedding, embed_text)
  * "data_processing" — data transformation, feature engineering, analytics
  * "file_operations" — file read/write/management (e.g. read_file, write_file)
  * "api_integration" — external HTTP/REST API calls (e.g. http_request, call_api)
  * "orchestration" — planning, routing, delegation (e.g. plan, delegate_task)
  * "tool_management" — tool registration, schema management (e.g. register_tool)
  * "testing" — test helpers, validation tools (e.g. validate, run_test)
  * "other" — only if none of the above categories fit
  Every tool_usage MUST have a non-empty service_category. NEVER leave it blank.

- tool_usages: repo-wide tool/function references not already captured per agent

- model role: For each model_usage in the evidence, classify the role field:
  * "embedding" — model name contains "embed" or "text-embedding", or file path contains
    "embed" or "embedding"
  * "reranker" — model name or file path contains "rerank"
  * "image-generation" — model name contains "image", "vision", "imagen", or "dall-e"
  * "primary" — the main LLM used for generation/chat (default for unclassified models)
  * "unknown" — only if role truly cannot be determined from any context clue
  NOTE: "unknown" should be rare. Default to "primary" when unsure.

- capability_tags: ONLY include a tag when there is DIRECT evidence in the findings.
  Do NOT infer tags from directory names alone (e.g. a "memory/" directory is not
  sufficient for "memory" without code evidence). Do NOT include "fine-tuning" unless
  there is a training loop or fine-tuning API call. Do NOT include "voice-ai" unless
  there are audio/speech API calls. Do NOT include "embeddings" unless embedding APIs
  or vector stores are explicitly used.
"""


def _build_evidence_block(
    scanner_summaries: list[dict],
    model_usages: list[ModelUsage],
    capability_tags: list[str],
    framework_candidate: str = "unknown",
    agent_instances: list[dict] | None = None,
    tool_definitions: list[dict] | None = None,
    external_services: list[dict] | None = None,
    threat_reference: str = "",
) -> str:
    lines: list[str] = []

    lines.append(f"FRAMEWORK CANDIDATE (rule-based): {framework_candidate}")
    lines.append("Confirm if correct, or override with a more specific framework name.\n")

    lines.append(f"Capability tags: {', '.join(capability_tags) if capability_tags else 'none'}")

    if model_usages:
        lines.append("\nModel usages:")
        for m in model_usages[:30]:  # cap at 30 to avoid flooding the context
            lines.append(
                f"  - {m.provider}/{m.model_name} ({m.role}) at {m.file_path}:{m.line_number}"
            )

    if agent_instances:
        lines.append("\n--- AGENT INSTANCES (rule-based) ---")
        for a in agent_instances:
            lines.append(f"  - \"{a['name']}\" ({a['source_file']}:{a.get('line', '')}, conf {a.get('confidence', 0):.2f})")

    if tool_definitions:
        lines.append("\n--- TOOL DEFINITIONS (rule-based) ---")
        for t in tool_definitions:
            lines.append(f"  - \"{t['name']}\" ({t['decorator']} at {t['source_file']}:{t.get('line', '')})")

    if external_services:
        lines.append("\n--- EXTERNAL SERVICES (rule-based) ---")
        for s in external_services:
            lines.append(f"  - {s['name']} ({s['category']}) at {s['source_file']}:{s.get('line', '')}")

    lines.append("\nScanner summaries:")
    for s in scanner_summaries:
        lines.append(f"\n  [{s['scanner']}] — {s['artifact_count']} artifact(s)")
        for f in s.get("top_artifacts", []):
            tag = f.get("tag", "")
            conf = f.get("confidence", 0.0)
            text = f.get("text", "")
            loc = f"{f.get('file', '')}:{f.get('line', '')}"
            lines.append(f"    • [{tag}] {loc} (conf {conf:.2f}): {text}")

    if threat_reference:
        lines.append(f"\n{threat_reference}")

    return "\n".join(lines)


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _parse_evidence_refs(raw: list | None) -> list[EvidenceRef]:
    """Parse evidence_refs from LLM JSON. Tolerant: drops malformed entries silently."""
    if not isinstance(raw, list):
        return []
    out: list[EvidenceRef] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        file_path = (item.get("file_path") or "").strip()
        scanner = (item.get("scanner") or "").strip()
        source_url = (item.get("source_url") or "").strip()
        line = item.get("line_number")
        try:
            line_number = int(line) if line is not None else None
            if line_number is not None and line_number <= 0:
                line_number = None
        except (TypeError, ValueError):
            line_number = None
        # An evidence ref needs at least a file path or a source URL to be useful.
        if not file_path and not source_url:
            continue
        out.append(EvidenceRef(
            file_path=file_path,
            line_number=line_number,
            scanner=scanner,
            source_url=source_url,
        ))
    return out


def _parse_risk_signals(raw_signals: list) -> list[RiskIndicator]:
    """Parse risk_signals from LLM JSON — handles both new dict format and legacy string format."""
    result: list[RiskIndicator] = []
    for item in raw_signals:
        if isinstance(item, dict):
            signal = item.get("signal", "")
            controls = item.get("recommended_controls", [])
            threat_id = item.get("threat_id") or None
            sev_raw = (item.get("severity") or "medium").strip().lower()
            severity = sev_raw if sev_raw in _VALID_SEVERITIES else "medium"
            evidence_refs = _parse_evidence_refs(item.get("evidence_refs"))
            if signal:
                result.append(RiskIndicator(
                    signal=signal,
                    recommended_controls=controls,
                    threat_id=threat_id,
                    severity=severity,
                    evidence_refs=evidence_refs,
                ))
        elif isinstance(item, str) and item:
            # Legacy format: plain string
            result.append(RiskIndicator(signal=item, recommended_controls=[], threat_id=None))
    return result


def _parse_synthesis_response(raw: str) -> SynthesisResult:
    """Parse LLM JSON into SynthesisResult. Falls back gracefully on errors."""
    raw = raw.strip()

    # Strip markdown code fences
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    # Find the first '{' in case the model added preamble text
    brace_idx = raw.find("{")
    if brace_idx > 0:
        raw = raw[brace_idx:]

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return SynthesisResult(
            is_ai_application=False,
            framework="unknown",
            summary="",
            agents=[],
            tool_usages=[],
        )

    agents: list[AgentProfile] = []
    for a in data.get("agents", []):
        if not isinstance(a, dict):
            continue
        agents.append(AgentProfile(
            name=a.get("name", "UnknownAgent"),
            agent_type=a.get("agent_type", "unknown"),
            goal=a.get("goal", ""),
            capabilities=a.get("capabilities", []),
            risk_signals=_parse_risk_signals(a.get("risk_signals", [])),
            skills=a.get("skills", []),
            tools=a.get("tools", []),
            source_file=a.get("source_file", ""),
        ))

    _VALID_TOOL_TYPES = {"tool_definition", "external_service", "skill", "mcp_tool"}
    tool_usages: list[ToolUsage] = []
    for t in data.get("tool_usages", []):
        if not isinstance(t, dict):
            continue
        raw_type = t.get("tool_type", "tool_definition")
        tool_type = raw_type if raw_type in _VALID_TOOL_TYPES else "tool_definition"
        tool_usages.append(ToolUsage(
            tool_name=t.get("tool_name", ""),
            tool_type=tool_type,
            service_category=t.get("service_category", ""),
            source_file=t.get("source_file", ""),
            line_number=t.get("line_number"),
        ))

    repo_risk_signals = _parse_risk_signals(data.get("risk_signals", []))

    return SynthesisResult(
        is_ai_application=bool(data.get("is_ai_application", False)),
        framework=data.get("framework", "unknown") or "unknown",
        summary=data.get("summary", ""),
        agents=agents,
        tool_usages=tool_usages,
        risk_signals=repo_risk_signals,
    )


class SynthesisAgent:
    """Single-call LLM synthesis: turns pre-summarised scanner evidence into a unified report."""

    def __init__(self, provider: BaseLLMProvider) -> None:
        self._provider = provider

    def synthesize(
        self,
        scanner_summaries: list[dict],
        model_usages: list[ModelUsage],
        capability_tags: list[str],
        on_progress: Callable[[str], None] | None = None,
        framework_candidate: str = "unknown",
        agent_instances: list[dict] | None = None,
        tool_definitions: list[dict] | None = None,
        external_services: list[dict] | None = None,
        classification: ClassificationResult | None = None,
        evidence_facts: EvidenceFacts | None = None,
    ) -> SynthesisResult:
        if on_progress:
            on_progress("Building evidence bundle...")

        # Build threat reference from classification result
        threat_reference = ""
        if classification:
            filtered = filter_threats(
                classification.system_types,
                threat_ids=classification.relevant_threats,
            )
            if filtered:
                threat_reference = build_threat_reference(filtered, facts=evidence_facts)

        evidence = _build_evidence_block(
            scanner_summaries,
            model_usages,
            capability_tags,
            framework_candidate=framework_candidate,
            agent_instances=agent_instances,
            tool_definitions=tool_definitions,
            external_services=external_services,
            threat_reference=threat_reference,
        )
        prompt = f"{_SYSTEM_PROMPT}\n\nEvidence:\n{evidence}"

        if on_progress:
            on_progress("Calling LLM for synthesis...")

        raw = self._provider.generate(prompt)

        if on_progress:
            on_progress("Parsing synthesis result...")

        return _parse_synthesis_response(raw)
