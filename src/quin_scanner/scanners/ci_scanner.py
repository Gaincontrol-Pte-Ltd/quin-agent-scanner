from __future__ import annotations

import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# Patterns for AI indicators in CI/CD pipeline files
_CI_PATTERNS: list[tuple[str, str, float]] = [
    # API key environment variables set in CI
    (r"OPENAI_API_KEY\s*:", "llm-api", 0.9),
    (r"ANTHROPIC_API_KEY\s*:", "llm-api", 0.9),
    (r"AZURE_OPENAI_API_KEY\s*:", "llm-api", 0.9),
    (r"GOOGLE_API_KEY\s*:", "llm-api", 0.85),
    (r"HUGGINGFACE_API_TOKEN\s*:|HF_TOKEN\s*:", "embeddings", 0.85),
    (r"COHERE_API_KEY\s*:|MISTRAL_API_KEY\s*:|GROQ_API_KEY\s*:", "llm-api", 0.85),
    (r"PINECONE_API_KEY\s*:|WEAVIATE_API_KEY\s*:|QDRANT_API_KEY\s*:", "rag", 0.85),
    (r"LANGCHAIN_API_KEY\s*:|LANGSMITH_API_KEY\s*:", "llm-api", 0.85),
    # pip install AI packages in CI steps
    (r"pip install[^\n]*\b(openai|anthropic|langchain|crewai|autogen|transformers|llama.index)\b", "llm-api", 0.9),
    (r"npm install[^\n]*\b(openai|@anthropic-ai|langchain)\b", "llm-api", 0.9),
    # Model fine-tuning or training steps
    (r"fine.?tun", "fine-tuning", 0.8),
    (r"train.*model|model.*train", "fine-tuning", 0.75),
    (r"huggingface-cli\s+upload|push_to_hub", "fine-tuning", 0.85),
    # Uses/actions that are AI-related (GitHub Actions)
    (r"uses:\s*.*openai", "llm-api", 0.9),
    (r"uses:\s*.*langchain", "llm-api", 0.85),
    (r"uses:\s*.*huggingface", "embeddings", 0.85),
]

# CI/CD file globs to scan
_CI_GLOBS = [
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
    "**/.gitlab-ci.yml",
    "**/.gitlab-ci.yaml",
    "**/azure-pipelines.yml",
    "**/azure-pipelines.yaml",
    "**/Jenkinsfile",
    "**/.circleci/config.yml",
    "**/.circleci/config.yaml",
    "**/bitbucket-pipelines.yml",
    "**/.buildkite/pipeline.yml",
    "**/.buildkite/pipeline.yaml",
]


class CIScanner(BaseScanner):
    """Detects AI indicators in CI/CD pipeline configuration files."""

    def __init__(self) -> None:
        self._patterns = [(re.compile(p, re.IGNORECASE), tag, conf)
                          for p, tag, conf in _CI_PATTERNS]

    def name(self) -> str:
        return "CIScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        ci_paths: set[str] = set()
        for glob in _CI_GLOBS:
            ci_paths.update(file_index.files_matching(glob))

        for path in ci_paths:
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            for pattern, tag, confidence in self._patterns:
                for match in pattern.finditer(content):
                    lineno = content[: match.start()].count("\n") + 1
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="ci_pipeline",
                        file_path=path,
                        line_number=lineno,
                        match_text=match.group(0).strip()[:200],
                        capability_tag=tag,
                        confidence=confidence,
                    ))
        return findings
