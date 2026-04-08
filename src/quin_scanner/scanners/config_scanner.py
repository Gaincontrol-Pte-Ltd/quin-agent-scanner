from __future__ import annotations

import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# API key env var patterns
_API_KEY_PATTERNS: list[tuple[str, str]] = [
    (r"OPENAI_API_KEY\s*=\s*\S+", "llm-api"),
    (r"ANTHROPIC_API_KEY\s*=\s*\S+", "llm-api"),
    (r"GOOGLE_API_KEY\s*=\s*\S+", "llm-api"),
    (r"GOOGLE_AI_KEY\s*=\s*\S+", "llm-api"),
    (r"AZURE_OPENAI_API_KEY\s*=\s*\S+", "llm-api"),
    (r"AZURE_OPENAI_ENDPOINT\s*=\s*\S+", "llm-api"),
    (r"HUGGINGFACE_API_TOKEN\s*=\s*\S+", "embeddings"),
    (r"HF_TOKEN\s*=\s*\S+", "embeddings"),
    (r"COHERE_API_KEY\s*=\s*\S+", "llm-api"),
    (r"TOGETHER_API_KEY\s*=\s*\S+", "llm-api"),
    (r"MISTRAL_API_KEY\s*=\s*\S+", "llm-api"),
    (r"GROQ_API_KEY\s*=\s*\S+", "llm-api"),
    (r"PINECONE_API_KEY\s*=\s*\S+", "rag"),
    (r"WEAVIATE_API_KEY\s*=\s*\S+", "rag"),
    (r"QDRANT_API_KEY\s*=\s*\S+", "rag"),
    (r"LANGCHAIN_API_KEY\s*=\s*\S+", "llm-api"),
    (r"LANGSMITH_API_KEY\s*=\s*\S+", "llm-api"),
]

# AI endpoint URL patterns in config files
_ENDPOINT_PATTERNS: list[tuple[str, str]] = [
    (r"api\.openai\.com", "llm-api"),
    (r"api\.anthropic\.com", "llm-api"),
    (r"generativelanguage\.googleapis\.com", "llm-api"),
    (r"openai\.azure\.com", "llm-api"),
    (r"api\.cohere\.ai", "llm-api"),
    (r"api\.together\.xyz", "llm-api"),
    (r"api\.mistral\.ai", "llm-api"),
    (r"api\.groq\.com", "llm-api"),
    (r"api\.pinecone\.io", "rag"),
    (r"\.weaviate\.network", "rag"),
]

_ENV_FILE_GLOB = ["**/.env", "**/.env.*", "**/*.env"]
_CONFIG_FILE_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}


class ConfigScanner(BaseScanner):
    """Detects AI-related environment variables and config entries."""

    def name(self) -> str:
        return "ConfigScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._scan_env_files(accessor, file_index))
        findings.extend(self._scan_config_files(accessor, file_index))
        return findings

    def _scan_env_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        env_files = set()
        for glob in _ENV_FILE_GLOB:
            env_files.update(file_index.files_matching(glob))
        for path in env_files:
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                for pattern, tag in _API_KEY_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="config",
                                file_path=path,
                                line_number=lineno,
                                match_text=self._redact(line.strip()),
                                capability_tag=tag,
                                confidence=0.9,
                            )
                        )
                        break  # one finding per line
        return findings

    def _scan_config_files(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.all_files():
            from pathlib import Path

            if Path(path).suffix not in _CONFIG_FILE_EXTENSIONS:
                continue
            # Skip lock files and node_modules
            if any(
                x in path for x in ("node_modules", "package-lock", "yarn.lock", ".venv")
            ):
                continue
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                for pattern, tag in _ENDPOINT_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="config",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=tag,
                                confidence=0.85,
                            )
                        )
                        break
        return findings

    @staticmethod
    def _redact(line: str) -> str:
        """Redact the value portion of KEY=VALUE lines."""
        if "=" in line:
            key, _, _ = line.partition("=")
            return f"{key}=<redacted>"
        return line
