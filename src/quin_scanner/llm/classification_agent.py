"""ClassificationAgent — Pass 1: classifies system type and relevant threats."""
from __future__ import annotations

import json
from collections.abc import Callable

from quin_scanner.llm.base import BaseLLMProvider
from quin_scanner.models import ClassificationResult
from quin_scanner.risk_taxonomy import build_threat_summary, filter_threats, load_taxonomy

_SYSTEM_PROMPT = """\
You are an AI security classifier. Given scanner evidence from a repository, \
classify the system type and identify which threat categories are relevant.

System types (select ALL that apply):
- standard_ai: Non-agentic LLM applications (chatbots, summarizers, content generators)
- agentic_ai: Autonomous agents with tool-use and decision-making capability
- mcp_enabled: Systems using MCP servers, MCP-based tool orchestration
- multi_agent: Multi-agent architectures with agent-to-agent communication

Rules:
- Every AI application is at minimum "standard_ai"
- "agentic_ai" requires tool-use or autonomous decision-making evidence
- "mcp_enabled" requires MCP configuration or MCP server/client evidence
- "multi_agent" requires multiple named agents or agent-to-agent communication
- Select relevant threats based on the system types AND the specific evidence observed
- Include a threat only if the evidence suggests the system has characteristics that \
make it susceptible to that threat

Reply with JSON only — no markdown fences, no explanation.
{{
  "system_types": ["<type>", ...],
  "relevant_threats": ["T001", "T002", ...]
}}

{threat_summary}
"""

# Default fallback: standard_ai with all universally-applicable threats
_FALLBACK_TYPES = ["standard_ai"]


def _get_fallback_threats() -> list[str]:
    """Return threat IDs that apply to standard_ai systems."""
    threats = filter_threats(["standard_ai"])
    return [t.id for t in threats]


def _build_evidence_block(
    scanner_summaries: list[dict],
    capability_tags: list[str],
) -> str:
    """Build a compact evidence block for classification."""
    lines: list[str] = []
    lines.append(f"Capability tags: {', '.join(capability_tags) if capability_tags else 'none'}")

    for s in scanner_summaries:
        lines.append(f"\n[{s['scanner']}] — {s['artifact_count']} artifact(s)")
        for f in s.get("top_artifacts", []):
            tag = f.get("tag", "")
            text = f.get("text", "")
            lines.append(f"  [{tag}] {text}")

    return "\n".join(lines)


def _parse_classification_response(raw: str) -> ClassificationResult | None:
    """Parse LLM JSON into ClassificationResult. Returns None on failure."""
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
        return None

    system_types = data.get("system_types", [])
    relevant_threats = data.get("relevant_threats", [])

    if not isinstance(system_types, list) or not isinstance(relevant_threats, list):
        return None

    # Validate system types
    valid_types = {"standard_ai", "agentic_ai", "mcp_enabled", "multi_agent"}
    system_types = [t for t in system_types if t in valid_types]
    if not system_types:
        return None

    # Validate threat IDs
    tax = load_taxonomy()
    valid_ids = {t.id for t in tax.threats}
    relevant_threats = [t for t in relevant_threats if t in valid_ids]

    return ClassificationResult(
        system_types=system_types,
        relevant_threats=relevant_threats,
    )


class ClassificationAgent:
    """Pass 1: lightweight LLM call to classify system type and relevant threats."""

    def __init__(self, provider: BaseLLMProvider) -> None:
        self._provider = provider

    def classify(
        self,
        scanner_summaries: list[dict],
        capability_tags: list[str],
        on_progress: Callable[[str], None] | None = None,
    ) -> ClassificationResult:
        if on_progress:
            on_progress("Classifying system type and relevant threats...")

        threat_summary = build_threat_summary()
        prompt = _SYSTEM_PROMPT.format(threat_summary=threat_summary)
        evidence = _build_evidence_block(scanner_summaries, capability_tags)
        full_prompt = f"{prompt}\n\nEvidence:\n{evidence}"

        raw = self._provider.generate(full_prompt)

        result = _parse_classification_response(raw)
        if result is None:
            if on_progress:
                on_progress("Classification parse failed — using fallback.")
            return ClassificationResult(
                system_types=_FALLBACK_TYPES,
                relevant_threats=_get_fallback_threats(),
            )

        if on_progress:
            on_progress(
                f"Classified as: {', '.join(result.system_types)} "
                f"({len(result.relevant_threats)} threats)"
            )
        return result
