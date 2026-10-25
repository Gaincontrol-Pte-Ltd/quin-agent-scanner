from __future__ import annotations

import anthropic

from quin_scanner.models import AgentIntentSummary
from quin_scanner.llm.base import ANALYSIS_PROMPT, BaseLLMProvider, parse_llm_json


class AnthropicProvider(BaseLLMProvider):
    """LLM provider backed by the Anthropic API (Claude)."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-haiku-4-5-20251001",
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        return parse_llm_json(self.generate(ANALYSIS_PROMPT.format(system_prompt=system_prompt[:4000])))

    def generate(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=16384,
            messages=[{"role": "user", "content": prompt}],
            # anthropic>=2 removed `temperature` from the method signature (the API still honours it
            # for models that predate the change); extra_body sends the same JSON on every SDK version.
            extra_body={"temperature": 0},
        )
        return response.content[0].text if response.content else "{}"
