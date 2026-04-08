from __future__ import annotations

import json
from abc import ABC, abstractmethod

from quin_scanner.models import AgentIntentSummary

ANALYSIS_PROMPT = """\
You are a security analyst reviewing AI agent system prompts. Analyze the following system prompt
and return a JSON object with this exact structure:

{{
  "agent_name": "<inferred name or 'UnknownAgent'>",
  "goal": "<one sentence describing what this agent does>",
  "capabilities": ["<capability1>", "<capability2>"],
  "risk_signals": ["<risk1>", "<risk2>"]
}}

Capabilities examples: web-search, file-read, file-write, code-execution, email-send,
database-access, api-calls, image-generation, summarization, question-answering.

Risk signals examples: has internet access, writes files, executes code, sends emails,
accesses databases, no input validation, broad permissions, can call external APIs.

Return ONLY the JSON object, no other text.

System prompt to analyze:
---
{system_prompt}
---
"""


def parse_llm_json(raw: str) -> AgentIntentSummary:
    """Parse LLM JSON response into AgentIntentSummary. Handles markdown fences."""
    raw = raw.strip()
    # Strip markdown code fences if present
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    data = json.loads(raw.strip())
    return AgentIntentSummary(
        prompt_location="",  # filled in by LLMAnalyzer
        agent_name=data.get("agent_name", "UnknownAgent"),
        goal=data.get("goal", ""),
        capabilities=data.get("capabilities", []),
        risk_signals=data.get("risk_signals", []),
    )


class BaseLLMProvider(ABC):
    """All LLM provider adapters implement this interface."""

    @abstractmethod
    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        """Analyze a system prompt and return a structured intent summary."""
        ...

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a raw prompt and return the model's text response."""
        ...
