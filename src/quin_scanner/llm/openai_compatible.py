"""OpenAI-compatible LLM provider for any endpoint implementing the OpenAI chat API."""
from __future__ import annotations
from openai import OpenAI
from .base import BaseLLMProvider, parse_llm_json, ANALYSIS_PROMPT
from ..models import AgentIntentSummary


class OpenAICompatibleProvider(BaseLLMProvider):
    """Any endpoint implementing the OpenAI chat completions API.

    Compatible with: vLLM, LiteLLM, Azure OpenAI, AWS Bedrock (via gateway),
    LocalAI, text-generation-inference, and others.
    """

    def __init__(self, base_url: str, api_key: str, model: str):
        self.model = model
        self.client = OpenAI(base_url=base_url, api_key=api_key)

    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary:
        return parse_llm_json(self.generate(ANALYSIS_PROMPT.format(system_prompt=system_prompt)))

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=16384,
        )
        return response.choices[0].message.content or ""
