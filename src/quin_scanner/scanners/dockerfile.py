from __future__ import annotations

import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# AI base images
_AI_BASE_IMAGES: list[tuple[str, str]] = [
    (r"FROM\s+nvidia/cuda", "llm-api"),
    (r"FROM\s+nvidia/pytorch", "llm-api"),
    (r"FROM\s+pytorch/pytorch", "llm-api"),
    (r"FROM\s+tensorflow/tensorflow", "llm-api"),
    (r"FROM\s+huggingface/", "llm-api"),
    (r"FROM\s+ollama/ollama", "llm-api"),
    (r"FROM\s+vllm/vllm", "llm-api"),
    (r"FROM\s+ghcr\.io/ggerganov/llama\.cpp", "llm-api"),
]

# RUN pip install / npm install patterns for AI packages
_AI_INSTALL_PATTERNS: list[tuple[str, str]] = [
    (r"pip install[^\n]*\b(openai|anthropic|langchain|crewai|autogen|llama.index|transformers|torch|diffusers|whisper|ollama)\b", "llm-api"),
    (r"npm install[^\n]*\b(openai|@anthropic-ai|langchain|@langchain)\b", "llm-api"),
    (r"RUN\s+.*huggingface", "llm-api"),
    (r"RUN\s+.*download.*model", "llm-api"),
    (r"RUN\s+.*ollama\s+pull", "llm-api"),
]

# ENV vars for AI API keys in Dockerfile
_AI_ENV_PATTERNS: list[tuple[str, str]] = [
    (r"ENV\s+OPENAI_API_KEY", "llm-api"),
    (r"ENV\s+ANTHROPIC_API_KEY", "llm-api"),
    (r"ENV\s+GOOGLE_API_KEY", "llm-api"),
    (r"ENV\s+HUGGINGFACE_API_TOKEN", "embeddings"),
    (r"ENV\s+HF_TOKEN", "embeddings"),
    (r"ENV\s+AZURE_OPENAI", "llm-api"),
]

# docker-compose service image patterns
_COMPOSE_IMAGE_PATTERNS: list[tuple[str, str]] = [
    (r"image:\s*(ollama|chromadb|qdrant|weaviate|milvus|chroma)", "rag"),
    (r"image:\s*ghcr\.io/ggerganov", "llm-api"),
    (r"image:\s*vllm", "llm-api"),
]


class DockerfileScanner(BaseScanner):
    """Detects AI indicators in Dockerfiles and docker-compose files."""

    def __init__(self) -> None:
        self._base_patterns = [(re.compile(p, re.IGNORECASE), tag) for p, tag in _AI_BASE_IMAGES]
        self._install_patterns = [(re.compile(p, re.IGNORECASE), tag) for p, tag in _AI_INSTALL_PATTERNS]
        self._env_patterns = [(re.compile(p, re.IGNORECASE), tag) for p, tag in _AI_ENV_PATTERNS]
        self._compose_patterns = [(re.compile(p, re.IGNORECASE), tag) for p, tag in _COMPOSE_IMAGE_PATTERNS]

    def name(self) -> str:
        return "DockerfileScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        dockerfile_paths = (
            file_index.files_matching("**/Dockerfile")
            + file_index.files_matching("**/Dockerfile.*")
            + file_index.files_matching("**/dockerfile")
        )
        compose_paths = (
            file_index.files_matching("**/docker-compose.yml")
            + file_index.files_matching("**/docker-compose.yaml")
            + file_index.files_matching("**/compose.yml")
            + file_index.files_matching("**/compose.yaml")
        )

        for path in dockerfile_paths:
            findings.extend(self._scan_dockerfile(accessor, path))
        for path in compose_paths:
            findings.extend(self._scan_compose(accessor, path))
        return findings

    def _scan_dockerfile(self, accessor: RepoAccessor, path: str) -> list[ScanFinding]:
        findings = []
        try:
            content = accessor.read_file(path)
        except Exception:
            return findings

        all_patterns = (
            [(p, tag, 0.95) for p, tag in self._base_patterns]
            + [(p, tag, 0.9) for p, tag in self._install_patterns]
            + [(p, tag, 0.85) for p, tag in self._env_patterns]
        )
        for pattern, tag, confidence in all_patterns:
            for match in pattern.finditer(content):
                lineno = content[: match.start()].count("\n") + 1
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category="dockerfile",
                    file_path=path,
                    line_number=lineno,
                    match_text=match.group(0).strip()[:200],
                    capability_tag=tag,
                    confidence=confidence,
                ))
        return findings

    def _scan_compose(self, accessor: RepoAccessor, path: str) -> list[ScanFinding]:
        findings = []
        try:
            content = accessor.read_file(path)
        except Exception:
            return findings

        for pattern, tag in self._compose_patterns:
            for match in pattern.finditer(content):
                lineno = content[: match.start()].count("\n") + 1
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category="dockerfile",
                    file_path=path,
                    line_number=lineno,
                    match_text=match.group(0).strip()[:200],
                    capability_tag=tag,
                    confidence=0.9,
                ))
        return findings
