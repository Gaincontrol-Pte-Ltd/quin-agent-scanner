from __future__ import annotations

import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# Terraform resource/data patterns for AI services
_TERRAFORM_PATTERNS: list[tuple[str, str, float]] = [
    (r'resource\s+"aws_sagemaker_', "llm-api", 0.95),
    (r'resource\s+"azurerm_cognitive_account"', "llm-api", 0.95),
    (r'resource\s+"azurerm_machine_learning_', "llm-api", 0.95),
    (r'resource\s+"google_vertex_ai_', "llm-api", 0.95),
    (r'resource\s+"google_ml_engine_', "llm-api", 0.9),
    (r'resource\s+"azurerm_bot_service', "llm-api", 0.9),
    (r'"openai\.azure\.com"', "llm-api", 0.9),
    (r'"api\.openai\.com"', "llm-api", 0.9),
    (r'"api\.anthropic\.com"', "llm-api", 0.9),
    (r'OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI', "llm-api", 0.85),
    (r'resource\s+"aws_lambda_function"[^}]*bedrock', "llm-api", 0.85),
    (r'"bedrock-runtime"', "llm-api", 0.9),
    (r'resource\s+"pinecone_', "rag", 0.9),
    (r'"pinecone\.io"', "rag", 0.85),
    (r'"weaviate"', "rag", 0.85),
]

# Kubernetes/Helm YAML patterns
_K8S_PATTERNS: list[tuple[str, str, float]] = [
    (r"image:\s*(ollama|vllm|chromadb|qdrant|weaviate|milvus)", "rag", 0.9),
    (r"image:\s*.*llm", "llm-api", 0.8),
    (r"name:\s*OPENAI_API_KEY", "llm-api", 0.9),
    (r"name:\s*ANTHROPIC_API_KEY", "llm-api", 0.9),
    (r"name:\s*AZURE_OPENAI", "llm-api", 0.9),
    (r"name:\s*HUGGINGFACE_API_TOKEN|name:\s*HF_TOKEN", "embeddings", 0.85),
    (r"name:\s*PINECONE_API_KEY|name:\s*WEAVIATE_API_KEY|name:\s*QDRANT_API_KEY", "rag", 0.9),
    (r"kind:\s*OpenAIService|kind:\s*AIModel", "llm-api", 0.95),
    (r"azure\.workload\.identity.*openai|openai.*azure\.workload", "llm-api", 0.9),
]


class IaCScanner(BaseScanner):
    """Detects AI service deployments in Infrastructure-as-Code files (Terraform, K8s, Helm)."""

    def __init__(self) -> None:
        self._tf_patterns = [(re.compile(p, re.IGNORECASE | re.DOTALL), tag, conf)
                             for p, tag, conf in _TERRAFORM_PATTERNS]
        self._k8s_patterns = [(re.compile(p, re.IGNORECASE), tag, conf)
                              for p, tag, conf in _K8S_PATTERNS]

    def name(self) -> str:
        return "IaCScanner"

    # Directories to skip when scanning all YAML files repo-wide
    _YAML_SKIP_DIRS = frozenset({
        "node_modules", ".venv", "venv", "vendor", "__pycache__",
        ".git", "dist", "build", ".tox", ".eggs",
    })

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        tf_paths = file_index.files_by_extension(".tf") + file_index.files_matching("**/*.tfvars")
        for path in tf_paths:
            findings.extend(self._scan_file(accessor, path, self._tf_patterns, "terraform"))

        # Scan all YAML/YML files repo-wide (not just named directories)
        all_yaml = set(
            file_index.files_matching("**/*.yaml")
            + file_index.files_matching("**/*.yml")
        )
        for path in all_yaml:
            if not self._should_skip_yaml(path):
                findings.extend(self._scan_file(accessor, path, self._k8s_patterns, "kubernetes"))

        return findings

    def _should_skip_yaml(self, path: str) -> bool:
        parts = path.replace("\\", "/").split("/")
        return any(part in self._YAML_SKIP_DIRS for part in parts)

    def _scan_file(
        self,
        accessor: RepoAccessor,
        path: str,
        patterns: list[tuple[re.Pattern, str, float]],
        category: str,
    ) -> list[ScanFinding]:
        findings = []
        try:
            content = accessor.read_file(path)
        except Exception:
            return findings

        for pattern, tag, confidence in patterns:
            for match in pattern.finditer(content):
                lineno = content[: match.start()].count("\n") + 1
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category=category,
                    file_path=path,
                    line_number=lineno,
                    match_text=match.group(0).strip()[:200],
                    capability_tag=tag,
                    confidence=confidence,
                ))
        return findings
