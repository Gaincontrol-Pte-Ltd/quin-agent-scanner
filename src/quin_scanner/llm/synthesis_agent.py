from __future__ import annotations

import json
from collections.abc import Callable

from quin_scanner.llm.base import BaseLLMProvider
from quin_scanner.redaction import redact_secrets
from quin_scanner.models import (
    AgentEnrichment,
    ClassificationResult,
    EvidenceRef,
    LLMInferredItem,
    ModelUsage,
    RiskIndicator,
    SynthesisResult,
)
from quin_scanner.risk_taxonomy import build_threat_reference, filter_threats
from quin_scanner.rules.kri_predicates import EvidenceFacts

# Tool service categories: the prompt lists them and the parser accepts only these, from this one tuple.
SERVICE_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("web_search", "search engines, SERP queries (e.g. google_search, tavily_search)"),
    ("web_browsing", "page fetching, scraping, crawling (e.g. browse_url, scrape_page)"),
    ("code_execution", "running code, sandboxes, REPLs (e.g. execute_code, run_python)"),
    ("vector_database", "vector store operations (e.g. query_vectors, upsert_embeddings)"),
    ("database", "SQL/NoSQL/graph DB operations (e.g. run_query, neo4j_search)"),
    ("communication", "messaging, email, notifications (e.g. send_slack, send_email)"),
    ("document_processing", "PDF/DOCX parsing, OCR (e.g. parse_pdf, extract_text)"),
    ("image_generation", "image creation/editing (e.g. text_to_image, generate_image)"),
    ("voice_audio", "TTS, STT, audio processing (e.g. text_to_speech, transcribe)"),
    ("embeddings", "text-to-embedding operations (e.g. text_to_embedding, embed_text)"),
    ("data_processing", "data transformation, feature engineering, analytics"),
    ("file_operations", "file read/write/management (e.g. read_file, write_file)"),
    ("api_integration", "external HTTP/REST API calls (e.g. http_request, call_api)"),
    ("orchestration", "planning, routing, delegation (e.g. plan, delegate_task)"),
    ("tool_management", "tool registration, schema management (e.g. register_tool)"),
    ("testing", "test helpers, validation tools (e.g. validate, run_test)"),
    ("other", "only if none of the above categories fit"),
)
_VALID_SERVICE_CATEGORIES = frozenset(name for name, _ in SERVICE_CATEGORIES)

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
  "enrichment": {
    "<agent id exactly as listed in AGENT INVENTORY>": {
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
      ]
    }
  },
  "tool_enrichment": {
    "<tool id exactly as listed in TOOL INVENTORY>": {"service_category": "<category from the list below>"}
  },
  "suggested_agents": [
    {"name": "<agent name>", "evidence": "<why you believe this is an agent>", "file": "<scanner-found path>"}
  ],
  "suggested_tools": [
    {"name": "<tool name>", "evidence": "<why you believe this is a tool>", "file": "<scanner-found path>"}
  ]
}

Rules:
- agent_type must be one of: supervisor, utility, worker, unknown

- framework: Identify the PRIMARY AI framework the repo is built WITH (not a dependency it
  uses). When the FRAMEWORK CANDIDATE is not 'unknown', return it unchanged unless the
  evidence clearly shows a different primary framework. If the candidate is 'unknown',
  derive it from all available evidence. NEVER return 'unknown' if any framework
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
  file_path that appears in the Evidence (under "Scanner summaries", "AGENT INVENTORY" or
  "TOOL INVENTORY"). Do NOT invent file paths. The line_number is
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

- The AGENT INVENTORY and TOOL INVENTORY are verified by static analysis and are FIXED. You cannot add,
  remove, rename, merge or split agents or tools. Refer to them only by their id, exactly as listed.

- enrichment: one entry per inventory agent you have evidence about, keyed by its id. agent_type, goal
  (one sentence, from surrounding comments, prompts or configuration) and capabilities describe that agent.
  Per-agent risk_signals follow the per-agent rules above. Omit agents you know nothing about.

- tool_enrichment: for inventory tools, classify service_category by what the tool DOES (infer from its
  name and context) into one of:
<<SERVICE_CATEGORIES>>
  Do not include tools that already show a category in the TOOL INVENTORY.

- suggested_agents / suggested_tools: agents or tools you believe exist but that are NOT in the
  inventories (for example agents built by a factory function). Each needs a file path that appears in the
  Evidence and a short reason. These are reported as unverified. Never suggest model names (gpt-4o,
  claude-3-sonnet, ...) or package names (faiss-cpu, chromadb, ...) as tools. Return [] when there are none.

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
""".replace(
    "<<SERVICE_CATEGORIES>>\n",
    "".join(f'  * "{name}" — {description}\n' for name, description in SERVICE_CATEGORIES),
)


def _build_evidence_block(
    scanner_summaries: list[dict],
    model_usages: list[ModelUsage],
    capability_tags: list[str],
    framework_candidate: str = "unknown",
    agent_inventory: list[dict] | None = None,
    tool_inventory: list[dict] | None = None,
    threat_reference: str = "",
) -> str:
    lines: list[str] = []

    lines.append(f"FRAMEWORK CANDIDATE (rule-based): {framework_candidate}")
    lines.append("Confirm it, or name the framework if the candidate is unknown.\n")

    lines.append(f"Capability tags: {', '.join(capability_tags) if capability_tags else 'none'}")

    if model_usages:
        lines.append("\nModel usages:")
        for m in model_usages[:30]:  # cap at 30 to avoid flooding the context
            lines.append(
                f"  - {m.provider}/{m.model_name} ({m.role}) at {m.file_path}:{m.line_number}"
            )

    if agent_inventory:
        lines.append("\n--- AGENT INVENTORY (verified; enrich by id, never rename or add) ---")
        for a in agent_inventory:
            tools = ", ".join(a["tools"]) or "none"
            skills = ", ".join(a.get("skills") or []) or "none"
            lines.append(
                f"  - id={a['id']} name=\"{a['name']}\" scope={a['scope']} instances={a['instances']} "
                f"instructions={a['instructions']} tools=[{tools}] skills=[{skills}] file={a['file']}"
            )

    if tool_inventory:
        lines.append("\n--- TOOL INVENTORY (verified) ---")
        for t in tool_inventory:
            category = f" category={t['category']}" if t["category"] else ""
            lines.append(
                f"  - id={t['id']} name=\"{t['name']}\" type={t['type']}{category} at {t['file']}:{t['line'] or ''}"
            )

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


_VALID_AGENT_TYPES = {"supervisor", "utility", "worker", "unknown"}


# Free text from the LLM is capped by truncation (after redaction, so a cut never exposes part of a secret).
_MAX_GOAL = 500
_MAX_NAME = 200
_MAX_EVIDENCE = 500
_MAX_FILE = 500
_MAX_CAPABILITY = 100


def _clean_text(value: object, limit: int) -> str:
    """A string field from the LLM: non-strings become empty, secrets are redacted, the result is capped."""
    if not isinstance(value, str):
        return ""
    return redact_secrets(value.strip())[:limit]


def _clean_list(value: object, limit: int) -> list[str]:
    """A list of LLM strings, each cleaned by :func:`_clean_text`; empties are dropped."""
    if not isinstance(value, list):
        return []
    return [text for text in (_clean_text(item, limit) for item in value) if text]


def _parse_suggestions(raw: object) -> list[LLMInferredItem]:
    if not isinstance(raw, list):
        return []
    items: list[LLMInferredItem] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _clean_text(item.get("name"), _MAX_NAME)
        if name:
            items.append(LLMInferredItem(
                name=name,
                evidence=_clean_text(item.get("evidence"), _MAX_EVIDENCE),
                file=_clean_text(item.get("file"), _MAX_FILE),
            ))
    return items


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
        )

    enrichment: dict[str, AgentEnrichment] = {}
    raw_enrichment = data.get("enrichment")
    if isinstance(raw_enrichment, dict):
        for agent_id, fields in raw_enrichment.items():
            if not isinstance(fields, dict):
                continue
            agent_type = fields.get("agent_type", "unknown")
            raw_capabilities = fields.get("capabilities")
            raw_signals = fields.get("risk_signals")
            enrichment[str(agent_id)] = AgentEnrichment(
                agent_type=agent_type if isinstance(agent_type, str) and agent_type in _VALID_AGENT_TYPES else "unknown",
                goal=_clean_text(fields.get("goal"), _MAX_GOAL),
                capabilities=_clean_list(raw_capabilities, _MAX_CAPABILITY),
                risk_signals=_parse_risk_signals(raw_signals if isinstance(raw_signals, list) else []),
            )

    tool_enrichment: dict[str, str] = {}
    raw_tools = data.get("tool_enrichment")
    if isinstance(raw_tools, dict):
        for tool_id, fields in raw_tools.items():
            category = fields.get("service_category") if isinstance(fields, dict) else None
            if isinstance(category, str) and category in _VALID_SERVICE_CATEGORIES:
                tool_enrichment[str(tool_id)] = category

    return SynthesisResult(
        is_ai_application=bool(data.get("is_ai_application", False)),
        framework=_clean_text(data.get("framework"), _MAX_NAME) or "unknown",
        summary=data.get("summary", ""),
        enrichment=enrichment,
        tool_enrichment=tool_enrichment,
        suggested_agents=_parse_suggestions(data.get("suggested_agents")),
        suggested_tools=_parse_suggestions(data.get("suggested_tools")),
        risk_signals=_parse_risk_signals(data.get("risk_signals", [])),
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
        agent_inventory: list[dict] | None = None,
        tool_inventory: list[dict] | None = None,
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
            agent_inventory=agent_inventory,
            tool_inventory=tool_inventory,
            threat_reference=threat_reference,
        )
        prompt = f"{_SYSTEM_PROMPT}\n\nEvidence:\n{evidence}"

        if on_progress:
            on_progress("Calling LLM for synthesis...")

        raw = self._provider.generate(prompt)

        if on_progress:
            on_progress("Parsing synthesis result...")

        return _parse_synthesis_response(raw)
