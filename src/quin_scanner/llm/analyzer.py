from __future__ import annotations

import json
import time
from collections.abc import Callable

from quin_scanner.models import AgentIntentSummary, ScanFinding
from quin_scanner.llm.base import BaseLLMProvider

_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # seconds; doubles each attempt (1s, 2s, 4s)

_VALIDATION_SYSTEM_PROMPT = (
    "You are a classifier. Given text extracted from a file, determine whether it "
    "is a real agent system prompt — instructions that define an AI agent's role, "
    "persona, or behavior. Reply with JSON only, no markdown fences:\n"
    '{"is_prompt": true, "reason": "brief reason"}'
)


class LLMAnalyzer:
    """Iterates over prompt findings and calls the LLM provider for each."""

    def __init__(self, provider: BaseLLMProvider) -> None:
        self._provider = provider
        self._errors: list[str] = []

    @property
    def errors(self) -> list[str]:
        """Errors accumulated during the last analyze() call."""
        return list(self._errors)

    def analyze(
        self,
        prompt_findings: list[ScanFinding],
        capability_tags: list[str] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> list[AgentIntentSummary]:
        """Analyze each prompt finding and return intent summaries."""
        self._errors = []
        results: list[AgentIntentSummary] = []
        total = len(prompt_findings)

        for i, finding in enumerate(prompt_findings, 1):
            try:
                summary = self._call_with_retry(finding.match_text)
                summary.prompt_location = (
                    f"{finding.file_path}:{finding.line_number}"
                    if finding.line_number
                    else finding.file_path
                )
                results.append(summary)
            except Exception as exc:
                location = (
                    f"{finding.file_path}:{finding.line_number}"
                    if finding.line_number
                    else finding.file_path
                )
                self._errors.append(f"{location}: {type(exc).__name__}: {exc}")
            if on_progress:
                on_progress(i, total)
        return results

    def validate_findings(
        self,
        findings: list[ScanFinding],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> list[ScanFinding]:
        """Return only findings the LLM confirms are real agent system prompts.

        Fails open: if the LLM call errors or the response is ambiguous, the finding is kept.
        """
        validated = []
        total = len(findings)
        for i, finding in enumerate(findings, 1):
            if self._validate_one(finding.match_text):
                validated.append(finding)
            if on_progress:
                on_progress(i, total)
        return validated

    def _validate_one(self, text: str) -> bool:
        """Ask the LLM whether text is a real agent system prompt. Returns True to keep."""
        prompt = (
            f"{_VALIDATION_SYSTEM_PROMPT}\n\nText to classify:\n{text[:1000]}"
        )
        for attempt in range(_MAX_RETRIES):
            try:
                raw = self._provider.generate(prompt)
                raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
                data = json.loads(raw)
                return bool(data.get("is_prompt", True))
            except Exception:
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))
        return True  # fail open after exhausted retries

    def _call_with_retry(self, match_text: str) -> AgentIntentSummary:
        """Call the LLM provider with exponential backoff on transient failures."""
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return self._provider.analyze_prompt(match_text)
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))
        raise last_exc  # type: ignore[misc]
