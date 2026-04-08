from __future__ import annotations

import re
from pathlib import Path

import yaml

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

_RULES_DIR = Path(__file__).parent.parent / "rules"

# Patterns that precede system prompt strings in Python source
_PYTHON_PROMPT_PATTERNS = [
    r'system_prompt\s*=\s*["\']([^"\']+)["\']',
    r'system_prompt\s*=\s*"""([\s\S]+?)"""',
    r"system_prompt\s*=\s*'''([\s\S]+?)'''",
    r'SystemMessage\s*\(\s*content\s*=\s*["\']([^"\']+)["\']',
    r'SystemMessage\s*\(\s*content\s*=\s*"""([\s\S]+?)"""',
    r'system_message\s*=\s*["\']([^"\']+)["\']',
    r'backstory\s*=\s*["\']([^"\']+)["\']',
    r'backstory\s*=\s*"""([\s\S]+?)"""',
    r'SYSTEM_PROMPT\s*=\s*["\']([^"\']+)["\']',
    r'SYSTEM_PROMPT\s*=\s*"""([\s\S]+?)"""',
    r"SYSTEM_PROMPT\s*=\s*'''([\s\S]+?)'''",
]

# YAML keys that may contain system prompts
_YAML_PROMPT_KEYS = {
    "system_prompt",
    "system_message",
    "instructions",
    "backstory",
    "system",
    "prompt",
    "template",
    "persona",
    "description",
}

_MIN_PROMPT_LENGTH = 20
_MD_SCAN_CHARS = 2000


class PromptDiscoveryScanner(BaseScanner):
    """Extracts system prompts from Python source, YAML configs, Markdown, and template files."""

    def __init__(self) -> None:
        self._python_patterns = [
            re.compile(p, re.DOTALL) for p in _PYTHON_PROMPT_PATTERNS
        ]

        signals_data = yaml.safe_load(
            (_RULES_DIR / "prompt_signals.yaml").read_text(encoding="utf-8")
        )
        self._md_signals: list[str] = [
            s.lower() for s in signals_data.get("md_prompt_signals", [])
        ]

        exclusions_data = yaml.safe_load(
            (_RULES_DIR / "exclusions.yaml").read_text(encoding="utf-8")
        )
        self._excluded_prefixes: list[str] = exclusions_data.get("excluded_path_prefixes", [])
        self._excluded_names: set[str] = set(exclusions_data.get("excluded_file_names", []))

    def name(self) -> str:
        return "PromptDiscoveryScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._scan_python_files(accessor, file_index))
        findings.extend(self._scan_yaml_files(accessor, file_index))
        findings.extend(self._scan_prompt_files(accessor, file_index))
        findings.extend(self._scan_markdown_files(accessor, file_index))
        return findings

    def _is_excluded(self, path: str) -> bool:
        name = Path(path).name
        if name in self._excluded_names:
            return True
        return any(path.startswith(prefix) for prefix in self._excluded_prefixes)

    def _scan_python_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_by_extension(".py"):
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            for pattern in self._python_patterns:
                for match in pattern.finditer(content):
                    prompt_text = match.group(1).strip()
                    if len(prompt_text) < _MIN_PROMPT_LENGTH:
                        continue
                    lineno = content[: match.start()].count("\n") + 1
                    findings.append(
                        ScanFinding(
                            scanner_name=self.name(),
                            category="prompt",
                            file_path=path,
                            line_number=lineno,
                            match_text=prompt_text[:500],  # cap length
                            capability_tag="prompt-templates",
                            confidence=0.8,
                        )
                    )
        return findings

    def _scan_yaml_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_by_extension(".yaml") + file_index.files_by_extension(".yml"):
            if self._is_excluded(path):
                continue
            try:
                content = accessor.read_file(path)
                data = yaml.safe_load(content)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            self._extract_yaml_prompts(data, path, content, findings)
        return findings

    def _extract_yaml_prompts(
        self,
        data: dict,
        path: str,
        raw_content: str,
        findings: list[ScanFinding],
        _depth: int = 0,
    ) -> None:
        if _depth > 5:
            return
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in _YAML_PROMPT_KEYS:
                if isinstance(value, str) and len(value) >= _MIN_PROMPT_LENGTH:
                    # Find approximate line number
                    lineno = next(
                        (i + 1 for i, line in enumerate(raw_content.splitlines()) if key in line),
                        None,
                    )
                    findings.append(
                        ScanFinding(
                            scanner_name=self.name(),
                            category="prompt",
                            file_path=path,
                            line_number=lineno,
                            match_text=value[:500],
                            capability_tag="prompt-templates",
                            confidence=0.75,
                        )
                    )
            elif isinstance(value, dict):
                self._extract_yaml_prompts(value, path, raw_content, findings, _depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_yaml_prompts(item, path, raw_content, findings, _depth + 1)

    def _scan_markdown_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_by_extension(".md"):
            if self._is_excluded(path):
                continue
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            preview = content[:_MD_SCAN_CHARS].lower()
            if any(signal in preview for signal in self._md_signals):
                findings.append(
                    ScanFinding(
                        scanner_name=self.name(),
                        category="prompt",
                        file_path=path,
                        line_number=1,
                        match_text=content[:500].strip(),
                        capability_tag="prompt-templates",
                        confidence=0.8,
                    )
                )
        return findings

    def _scan_prompt_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        # .prompt, .jinja2, .j2, .mustache files anywhere; .txt/.md in prompts/ directories
        prompt_files = (
            file_index.files_by_extension(".prompt")
            + file_index.files_by_extension(".jinja2")
            + file_index.files_by_extension(".j2")
            + file_index.files_by_extension(".mustache")
        )
        prompt_files += [
            f for f in file_index.files_in_dir("prompts")
            if f.endswith(".txt") or f.endswith(".md")
        ]
        for path in prompt_files:
            try:
                content = accessor.read_file(path).strip()
            except Exception:
                continue
            if len(content) >= _MIN_PROMPT_LENGTH:
                findings.append(
                    ScanFinding(
                        scanner_name=self.name(),
                        category="prompt",
                        file_path=path,
                        line_number=1,
                        match_text=content[:500],
                        capability_tag="prompt-templates",
                        confidence=0.85,
                    )
                )
        return findings
