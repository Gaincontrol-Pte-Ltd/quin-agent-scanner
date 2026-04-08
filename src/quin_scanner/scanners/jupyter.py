from __future__ import annotations

import json
import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# Reuse import patterns from code_patterns — check for common AI imports in cell source
_AI_IMPORT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"import\s+openai|from\s+openai"), "llm-api"),
    (re.compile(r"import\s+anthropic|from\s+anthropic"), "llm-api"),
    (re.compile(r"from\s+langchain|import\s+langchain"), "llm-api"),
    (re.compile(r"from\s+langgraph|import\s+langgraph"), "multi-agent"),
    (re.compile(r"from\s+crewai|import\s+crewai"), "multi-agent"),
    (re.compile(r"from\s+autogen|import\s+autogen"), "multi-agent"),
    (re.compile(r"from\s+llama_index|import\s+llama_index"), "rag"),
    (re.compile(r"import\s+transformers|from\s+transformers"), "llm-api"),
    (re.compile(r"import\s+torch|from\s+torch"), "llm-api"),
    (re.compile(r"import\s+chromadb|import\s+pinecone|import\s+weaviate"), "rag"),
    (re.compile(r"import\s+diffusers|from\s+diffusers"), "image-gen"),
    (re.compile(r"import\s+whisper|from\s+whisper"), "voice-ai"),
    (re.compile(r"from\s+google\.generativeai|import\s+google\.generativeai"), "llm-api"),
    (re.compile(r"from\s+pydantic_ai|import\s+pydantic_ai"), "llm-api"),
    (re.compile(r"client\.chat\.completions\.create|ChatCompletion\.create"), "llm-api"),
]

# Prompt extraction patterns in notebook cells
_PROMPT_PATTERNS: list[re.Pattern] = [
    re.compile(r'system_prompt\s*=\s*["\']([^"\']{20,})["\']'),
    re.compile(r'system_prompt\s*=\s*"""([\s\S]{20,}?)"""'),
    re.compile(r'SystemMessage\s*\(\s*content\s*=\s*["\']([^"\']{20,})["\']'),
    re.compile(r'SYSTEM_PROMPT\s*=\s*["\']([^"\']{20,})["\']'),
]


class JupyterScanner(BaseScanner):
    """Detects AI usage in Jupyter notebook (.ipynb) files."""

    def name(self) -> str:
        return "JupyterScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for path in file_index.files_by_extension(".ipynb"):
            findings.extend(self._scan_notebook(accessor, path))
        return findings

    def _scan_notebook(self, accessor: RepoAccessor, path: str) -> list[ScanFinding]:
        findings = []
        try:
            raw = accessor.read_file(path)
            nb = json.loads(raw)
        except Exception:
            return findings

        cells = nb.get("cells", [])
        line_offset = 0

        for cell in cells:
            if cell.get("cell_type") not in ("code", "markdown"):
                continue
            source_lines = cell.get("source", [])
            if isinstance(source_lines, list):
                cell_source = "".join(source_lines)
            else:
                cell_source = str(source_lines)

            # Check AI imports/calls
            for pattern, tag in _AI_IMPORT_PATTERNS:
                for match in pattern.finditer(cell_source):
                    lineno = line_offset + cell_source[: match.start()].count("\n") + 1
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="code_pattern",
                        file_path=path,
                        line_number=lineno,
                        match_text=match.group(0).strip()[:200],
                        capability_tag=tag,
                        confidence=0.9,
                    ))

            # Extract prompts
            for pattern in _PROMPT_PATTERNS:
                for match in pattern.finditer(cell_source):
                    prompt_text = match.group(1).strip()
                    lineno = line_offset + cell_source[: match.start()].count("\n") + 1
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="prompt",
                        file_path=path,
                        line_number=lineno,
                        match_text=prompt_text[:500],
                        capability_tag="prompt-templates",
                        confidence=0.8,
                    ))

            line_offset += cell_source.count("\n") + 1

        return findings
