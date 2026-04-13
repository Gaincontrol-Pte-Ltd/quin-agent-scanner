"""Identifies LLM model usage in repository files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from quin_scanner.models import ModelUsage

if TYPE_CHECKING:
    from quin_scanner.repo_accessor import RepoAccessor
    from quin_scanner.file_index import FileIndex

# File extensions to scan
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".go", ".rs", ".java"}
_CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml"}
_ENV_EXTENSIONS = {".env"}
_ENV_NAMES = {".env"}

# Regex patterns for model name extraction
_CODE_PATTERNS = [
    # Python/JS/TS: model="gpt-4o" or model='gpt-4o'
    re.compile(r'model\s*=\s*["\']([^"\']+)["\']'),
    # Python: model_name="gpt-4o"
    re.compile(r'model_name\s*=\s*["\']([^"\']+)["\']'),
    # JS/TS: model: "gpt-4o"
    re.compile(r'model\s*:\s*["\']([^"\']+)["\']'),
    # Python dict / JSON-in-code: "model": "gpt-4o" or 'model': 'gpt-4o'
    re.compile(r'["\']model["\']\s*:\s*["\']([^"\']+)["\']'),
    # Python dict: "model_name": "gpt-4o"
    re.compile(r'["\']model_name["\']\s*:\s*["\']([^"\']+)["\']'),
    # TypeScript/JS Vercel AI SDK provider function calls: openai('gpt-4o'), anthropic('claude-...')
    re.compile(r'(?:openai|anthropic|google|mistral|groq|cohere|bedrock|azure)\s*\(\s*["\']([a-zA-Z0-9][\w.:-]{2,80})["\']'),
]

_YAML_PATTERNS = [
    # YAML: model: gpt-4o or model_name: gpt-4o
    re.compile(r'^(?:model|model_name)\s*:\s*(.+)$', re.MULTILINE),
]

_ENV_PATTERNS = [
    # .env: MODEL=gpt-4o or OPENAI_MODEL=gpt-4o etc.
    re.compile(r'^[A-Z_]*MODEL[A-Z_]*\s*=\s*(.+)$', re.MULTILINE),
]

# Routing/role detection keys in YAML
_ROUTING_KEYS = {
    "primary": "primary",
    "primary_model": "primary",
    "fallback": "fallback",
    "fallback_model": "fallback",
    "backup_model": "fallback",
    "secondary_model": "fallback",
    "embedding_model": "embedding",
    "embeddings_model": "embedding",
}

# Known provider prefixes used in colon-prefixed model strings (e.g. "openai:gpt-4o")
_COLON_PROVIDER_PREFIXES: frozenset[str] = frozenset({
    "openai", "anthropic", "google", "mistral", "groq", "cohere",
    "together", "ollama", "bedrock", "azure", "huggingface", "replicate",
})

# Provider detection by model name prefix/substring
_PROVIDER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'^(gpt-|o1-|o3-|o4-|text-embedding-|dall-e-|whisper-|tts-)', re.IGNORECASE), "openai"),
    (re.compile(r'^claude-', re.IGNORECASE), "anthropic"),
    (re.compile(r'^(gemini-|palm-)', re.IGNORECASE), "google"),
    (re.compile(r'^(llama|codellama)', re.IGNORECASE), "meta"),
    (re.compile(r'^(mistral-|mixtral-|codestral-)', re.IGNORECASE), "mistral"),
    (re.compile(r'^command-', re.IGNORECASE), "cohere"),
    (re.compile(r'^(amazon\.|dbrx|databricks-)', re.IGNORECASE), "databricks"),
]

# Known exact or prefix model name mappings
_KNOWN_MODELS: dict[str, str] = {
    # OpenAI
    "gpt-4o": "openai",
    "gpt-4o-mini": "openai",
    "gpt-4": "openai",
    "gpt-3.5-turbo": "openai",
    "o1": "openai",
    "o1-mini": "openai",
    "o3": "openai",
    "o3-mini": "openai",
    "o4-mini": "openai",
    "text-embedding-ada-002": "openai",
    "text-embedding-3-small": "openai",
    "text-embedding-3-large": "openai",
    "dall-e-3": "openai",
    "dall-e-2": "openai",
    "whisper-1": "openai",
    "tts-1": "openai",
    # Anthropic — full model IDs
    "claude-opus-4-6": "anthropic",
    "claude-sonnet-4-6": "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    "claude-haiku-4-6": "anthropic",
    "claude-3-opus-20240229": "anthropic",
    "claude-3-sonnet-20240229": "anthropic",
    "claude-3-haiku-20240307": "anthropic",
    "claude-3-5-sonnet-20241022": "anthropic",
    # Anthropic — short aliases used in agent SDK demos and config
    "claude-sonnet": "anthropic",
    "claude-haiku": "anthropic",
    "claude-opus": "anthropic",
    "claude-sonnet-4-5": "anthropic",
    "claude-opus-4-5": "anthropic",
    # Bare aliases (e.g. model="opus" in @anthropic-ai/sdk and agent SDK)
    "opus": "anthropic",
    "sonnet": "anthropic",
    "haiku": "anthropic",
    # Google
    "gemini-2.0-flash": "google",
    "gemini-1.5-pro": "google",
    "gemini-1.5-flash": "google",
    "gemini-pro": "google",
    "gemini-ultra": "google",
    # Meta/Ollama
    "llama3.2": "meta",
    "llama3.1": "meta",
    "llama3": "meta",
    "llama2": "meta",
    "codellama": "meta",
    # Mistral
    "mistral-large": "mistral",
    "mistral-medium": "mistral",
    "mistral-small": "mistral",
    "mixtral-8x7b": "mistral",
    "codestral": "mistral",
    # Cohere
    "command-r": "cohere",
    "command-r-plus": "cohere",
    # Databricks
    "dbrx-instruct": "databricks",
}


def _split_colon_prefix(model_name: str) -> tuple[str, str]:
    """Split 'provider:model' → (provider, model). Returns ('', model_name) if no valid prefix."""
    if ":" in model_name:
        prefix, _, rest = model_name.partition(":")
        if prefix.lower() in _COLON_PROVIDER_PREFIXES and rest:
            return prefix.lower(), rest
    return "", model_name


def classify_provider(model_name: str) -> str:
    """Classify a model name to a provider string."""
    if not model_name:
        return "unknown"
    # Handle colon-prefixed provider (e.g. "openai:gpt-4o-mini")
    prefix, model_name = _split_colon_prefix(model_name)
    if prefix:
        return prefix
    # Check exact match first
    lower = model_name.lower()
    if lower in _KNOWN_MODELS:
        return _KNOWN_MODELS[lower]
    # Check prefix patterns
    for pattern, provider in _PROVIDER_PATTERNS:
        if pattern.search(model_name):
            return provider
    return "unknown"


def _is_plausible_model_name(name: str) -> bool:
    """Filter out obviously non-model values like variable references, paths, etc."""
    name = name.strip()
    if not name or len(name) < 3 or len(name) > 100:
        return False
    # Skip variable references, paths, etc.
    if name.startswith("$") or name.startswith("{") or "/" in name or "\\" in name:
        return False
    # Must contain at least one letter
    if not re.search(r'[a-zA-Z]', name):
        return False
    # Skip common non-model values
    skip_values = {"none", "null", "true", "false", "undefined", "string", "your-model-here"}
    if name.lower() in skip_values:
        return False
    return True


class ModelIdentifier:
    """Scans repository files to identify LLM model usage."""

    def identify(self, accessor: "RepoAccessor", file_index: "FileIndex") -> list[ModelUsage]:
        """Scan all relevant files and return list of ModelUsage instances."""
        usages: list[ModelUsage] = []
        seen: set[tuple] = set()

        for path in file_index.all_files():
            p = Path(path)
            suffix = p.suffix.lower()
            name = p.name.lower()

            # Determine if we should scan this file
            should_scan = (
                suffix in _CODE_EXTENSIONS
                or suffix in _CONFIG_EXTENSIONS
                or suffix in _ENV_EXTENSIONS
                or name in _ENV_NAMES
                or name.startswith(".env")
            )
            if not should_scan:
                continue

            try:
                file_usages = self._scan_file_from_accessor(accessor, path)
            except Exception:
                continue

            for usage in file_usages:
                key = (usage.file_path, usage.line_number, usage.model_name)
                if key not in seen:
                    seen.add(key)
                    usages.append(usage)

        return usages

    def _scan_file_from_accessor(self, accessor: "RepoAccessor", path: str) -> list[ModelUsage]:
        """Read file via accessor and scan it."""
        content = accessor.read_file(path)
        return self._scan_content(content, path)

    def _scan_file(self, file_path: Path) -> list[ModelUsage]:
        """Scan a local file directly (used in tests)."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self._scan_content(content, str(file_path))

    def _scan_content(self, content: str, path: str) -> list[ModelUsage]:
        """Extract model usages from file content."""
        p = Path(path)
        suffix = p.suffix.lower()
        name = p.name.lower()

        if suffix in _CODE_EXTENSIONS:
            return self._scan_code(content, path)
        elif name.startswith(".env") or suffix in _ENV_EXTENSIONS:
            return self._scan_env(content, path)
        elif suffix in _CONFIG_EXTENSIONS:
            return self._scan_config(content, path)
        return []

    def _scan_code(self, content: str, path: str) -> list[ModelUsage]:
        """Scan code files for model= and model_name= patterns."""
        usages = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern in _CODE_PATTERNS:
                m = pattern.search(line)
                if m:
                    raw = m.group(1).strip()
                    provider_hint, model_name = _split_colon_prefix(raw)
                    if _is_plausible_model_name(model_name):
                        provider = provider_hint or classify_provider(model_name)
                        usages.append(ModelUsage(
                            provider=provider,
                            model_name=model_name,
                            source="code",
                            file_path=path,
                            line_number=lineno,
                            role="unknown",
                        ))
        return usages

    def _scan_env(self, content: str, path: str) -> list[ModelUsage]:
        """Scan .env files for MODEL= patterns."""
        usages = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern in _ENV_PATTERNS:
                m = pattern.match(line)
                if m:
                    model_name = m.group(1).strip().strip('"').strip("'")
                    if _is_plausible_model_name(model_name):
                        provider = classify_provider(model_name)
                        usages.append(ModelUsage(
                            provider=provider,
                            model_name=model_name,
                            source="env_var",
                            file_path=path,
                            line_number=lineno,
                            role="unknown",
                        ))
        return usages

    def _scan_config(self, content: str, path: str) -> list[ModelUsage]:
        """Scan YAML/JSON/TOML config files for model references and routing patterns."""
        suffix = Path(path).suffix.lower()
        if suffix in {".yaml", ".yml"}:
            return self._scan_yaml_config(content, path)
        elif suffix == ".json":
            return self._scan_json_config(content, path)
        else:
            # For TOML and other formats, use regex
            return self._scan_generic_config(content, path)

    def _scan_yaml_config(self, content: str, path: str) -> list[ModelUsage]:
        """Scan YAML config for model references, including routing patterns."""
        usages = []
        lines = content.splitlines()

        # Track context for routing detection
        current_role_context: str | None = None
        role_indent: int = -1

        for lineno, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # Check if this line sets a routing context
            for key, role in _ROUTING_KEYS.items():
                key_pattern = re.compile(r'^' + re.escape(key) + r'\s*:', re.IGNORECASE)
                if key_pattern.match(stripped):
                    current_role_context = role
                    role_indent = indent
                    break
            else:
                # Reset context if we've dedented past the role context
                if current_role_context and indent <= role_indent and stripped and not stripped.startswith('#'):
                    if not any(re.compile(r'^' + re.escape(k) + r'\s*:', re.IGNORECASE).match(stripped)
                               for k in _ROUTING_KEYS):
                        current_role_context = None
                        role_indent = -1

            # Match model: or model_name: on this line
            for pattern in _YAML_PATTERNS:
                m = pattern.match(stripped)
                if m:
                    model_name = m.group(1).strip().strip('"').strip("'")
                    if _is_plausible_model_name(model_name):
                        # Determine role from context
                        role = current_role_context or "unknown"

                        # Check for embedding role from key name context
                        if any(k in line.lower() for k in ["embedding_model", "embed_model"]):
                            role = "embedding"

                        provider = classify_provider(model_name)
                        usages.append(ModelUsage(
                            provider=provider,
                            model_name=model_name,
                            source="config",
                            file_path=path,
                            line_number=lineno,
                            role=role,
                        ))

        return usages

    def _scan_json_config(self, content: str, path: str) -> list[ModelUsage]:
        """Scan JSON config for model references."""
        usages = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            m = re.search(r'"(?:model|model_name)"\s*:\s*"([^"]+)"', line)
            if m:
                model_name = m.group(1).strip()
                if _is_plausible_model_name(model_name):
                    provider = classify_provider(model_name)
                    usages.append(ModelUsage(
                        provider=provider,
                        model_name=model_name,
                        source="config",
                        file_path=path,
                        line_number=lineno,
                        role="unknown",
                    ))
        return usages

    def _scan_generic_config(self, content: str, path: str) -> list[ModelUsage]:
        """Scan generic config (TOML, etc.) for model references."""
        usages = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            m = re.search(r'(?:model|model_name)\s*=\s*["\']([^"\']+)["\']', line)
            if m:
                model_name = m.group(1).strip()
                if _is_plausible_model_name(model_name):
                    provider = classify_provider(model_name)
                    usages.append(ModelUsage(
                        provider=provider,
                        model_name=model_name,
                        source="config",
                        file_path=path,
                        line_number=lineno,
                        role="unknown",
                    ))
        return usages
