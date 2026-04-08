from __future__ import annotations

import json
from collections.abc import Callable

from quin_scanner.llm.base import BaseLLMProvider
from quin_scanner.models import AgentProfile, ModelUsage, SynthesisResult, ToolUsage

_SYSTEM_PROMPT = """\
You are an AI application analyst. Given scanner evidence from a repository, produce a \
structured JSON report. Reply with JSON only — no markdown fences, no explanation.

Output schema:
{
  "is_ai_application": <bool>,
  "framework": "<primary AI framework name, or 'unknown'>",
  "summary": "<2-3 sentence narrative suitable for a developer report>",
  "agents": [
    {
      "name": "<agent name>",
      "agent_type": "<supervisor|utility|worker|unknown>",
      "goal": "<one sentence>",
      "capabilities": ["<capability>"],
      "risk_signals": ["<risk>"],
      "skills": ["<skill reference>"],
      "tools": ["<tool name>"],
      "source_file": "<file path>"
    }
  ],
  "tool_usages": [
    {
      "tool_name": "<tool name>",
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
  'Anthropic Agent SDK', 'Google ADK', 'LlamaIndex', 'Haystack', 'Semantic Kernel',
  'PromptFlow', 'Flowise', 'LangGraph', 'MCP', 'Vercel AI SDK', or the best name you can
  infer. Do NOT name a transitive dependency (e.g. if LangChain is used by Flowise, the
  framework is 'Flowise', not 'LangChain').

- summary: Written for a developer reading a scan report — focus on what the system does,
  not how the scanner works. The summary MUST be a non-empty string of 2-4 sentences.
  Lead with the framework and what the repo does (use the README content if available in
  the scanner findings). If evidence is sparse, use: "<framework> repository that uses
  AI capabilities including: <capability_tags>." NEVER return an empty string, null, or
  a summary that mentions the scanner itself. Do not write "insufficient evidence" —
  always produce a best-effort description.

- agents: Populate using AGENT INSTANCES (rule-based) in the evidence as the PRIMARY source.
  For each instance, set name from the instance name, description/goal from surrounding
  comments or config description field if present. If AGENT INSTANCES is empty, infer agents
  from class names in code pattern findings (e.g. AssistantAgent, UserProxyAgent, Agent
  class instantiations). Return [] only if there is truly no agent evidence whatsoever.

- tool_usages: Populate using TOOL DEFINITIONS (rule-based) in the evidence as the PRIMARY
  source. If empty, infer from 'tool-use' capability evidence and code patterns referencing
  tool functions. Return [] only if there is truly no tool evidence.

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

    lines.append("\nScanner summaries:")
    for s in scanner_summaries:
        lines.append(f"\n  [{s['scanner']}] — {s['finding_count']} finding(s)")
        for f in s.get("top_findings", []):
            tag = f.get("tag", "")
            conf = f.get("confidence", 0.0)
            text = f.get("text", "")
            loc = f"{f.get('file', '')}:{f.get('line', '')}"
            lines.append(f"    • [{tag}] {loc} (conf {conf:.2f}): {text}")

    return "\n".join(lines)


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
            risk_signals=a.get("risk_signals", []),
            skills=a.get("skills", []),
            tools=a.get("tools", []),
            source_file=a.get("source_file", ""),
        ))

    tool_usages: list[ToolUsage] = []
    for t in data.get("tool_usages", []):
        if not isinstance(t, dict):
            continue
        tool_usages.append(ToolUsage(
            tool_name=t.get("tool_name", ""),
            source_file=t.get("source_file", ""),
            line_number=t.get("line_number"),
        ))

    return SynthesisResult(
        is_ai_application=bool(data.get("is_ai_application", False)),
        framework=data.get("framework", "unknown") or "unknown",
        summary=data.get("summary", ""),
        agents=agents,
        tool_usages=tool_usages,
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
    ) -> SynthesisResult:
        if on_progress:
            on_progress("Building evidence bundle...")

        evidence = _build_evidence_block(
            scanner_summaries,
            model_usages,
            capability_tags,
            framework_candidate=framework_candidate,
            agent_instances=agent_instances,
            tool_definitions=tool_definitions,
        )
        prompt = f"{_SYSTEM_PROMPT}\n\nEvidence:\n{evidence}"

        if on_progress:
            on_progress("Calling LLM for synthesis...")

        raw = self._provider.generate(prompt)

        if on_progress:
            on_progress("Parsing synthesis result...")

        return _parse_synthesis_response(raw)
