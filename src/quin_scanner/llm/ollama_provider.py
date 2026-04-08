from __future__ import annotations

from openai import OpenAI

from quin_scanner.models import AgentIntentSummary
from quin_scanner.llm.base import ANALYSIS_PROMPT, BaseLLMProvider, parse_llm_json

_DEFAULT_BASE_URL = "http://localhost:11434/v1"


class OllamaProvider(BaseLLMProvider):
    """LLM provider backed by a local Ollama instance (OpenAI-compatible API).

    Requires Ollama running locally: https://ollama.com
    Default model: llama3.2 — pull with `ollama pull llama3.2`

    Custom base URL (e.g. remote Ollama):
        OllamaProvider(model="llama3.2", base_url="http://myserver:11434/v1")
    """

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        # Ollama's OpenAI-compatible endpoint accepts any non-empty string as api_key
        self._client = OpenAI(api_key="ollama", base_url=base_url)
        self._model = model

    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        return parse_llm_json(self.generate(ANALYSIS_PROMPT.format(system_prompt=system_prompt[:4000])))

    def generate(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        return response.choices[0].message.content or "{}"
