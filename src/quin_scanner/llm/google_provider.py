from __future__ import annotations

from google import genai
from google.genai import types

from quin_scanner.models import AgentIntentSummary
from quin_scanner.llm.base import ANALYSIS_PROMPT, BaseLLMProvider, parse_llm_json


class GoogleProvider(BaseLLMProvider):
    """LLM provider backed by Google Generative AI (Gemini) via google-genai SDK."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.0-flash",
    ) -> None:
        self._client = genai.Client(api_key=api_key)
        self._model = model

    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        return parse_llm_json(self.generate(ANALYSIS_PROMPT.format(system_prompt=system_prompt[:4000])))

    def generate(self, prompt: str) -> str:
        response = self._client.models.generate_content(
            model=self._model,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0, max_output_tokens=16384),
        )
        return response.text if response.text else "{}"
