from __future__ import annotations

from openai import OpenAI

from quin_scanner.models import AgentIntentSummary
from quin_scanner.llm.base import ANALYSIS_PROMPT, BaseLLMProvider, parse_llm_json


class OpenAIProvider(BaseLLMProvider):
    """LLM provider backed by the OpenAI API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        base_url: str | None = None,
    ) -> None:
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model

    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        return parse_llm_json(self.generate(ANALYSIS_PROMPT.format(system_prompt=system_prompt[:4000])))

    def generate(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=16384,
        )
        return response.choices[0].message.content or "{}"
