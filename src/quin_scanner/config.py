from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from quin_scanner.llm.base import BaseLLMProvider

def _parse_max_signals(raw: Any) -> int | None:
    """Parse max_repo_risk_signals from YAML. Returns None to disable the cap."""
    if raw is None:
        return None
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return 10
    return None if n <= 0 else n


_ALL_SCANNERS = [
    "dependency",
    "config",
    "code_pattern",
    "file_structure",
    "framework",
    "prompt_discovery",
    "dockerfile",
    "jupyter",
    "iac",
    "ci",
    "mcp",
    "agent_instance",
    "tool_definition",
]


@dataclass
class ScannerConfig:
    llm_provider: str = "openai"
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str | None = None
    output_format: str = "json"
    enabled_scanners: list[str] = field(default_factory=lambda: list(_ALL_SCANNERS))
    no_llm: bool = False
    github_token: str | None = None
    openai_compatible_url: str | None = None
    # Vulnerability check (OSV.dev + optional LLM web search)
    vuln_check_enabled: bool = True
    vuln_search_provider: str | None = None  # "perplexity" | "gemini" | "openai" | "anthropic" | None
    vuln_search_model: str | None = None     # optional override (e.g. "sonar-pro")
    vuln_osv_timeout: float = 10.0
    vuln_web_timeout: float = 5.0
    # Web-search retries when the provider returns an empty list or throws.
    # Total attempts = vuln_web_retries + 1. Default 1 (one retry → 2 attempts)
    # mitigates LLM/web-search non-determinism without doubling cost on every
    # scan. Set to 0 to disable retry entirely.
    vuln_web_retries: int = 1
    # Cap on repo-level risk signals shown to the user. Applied AFTER the
    # severity-aware sort so the cap keeps the highest-severity entries.
    # Set to 0 or None to disable the cap.
    max_repo_risk_signals: int | None = 10

    @classmethod
    def load_from_file(cls, path: str) -> "ScannerConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        llm_cfg = data.get("llm", {})
        out_cfg = data.get("output", {})
        scan_cfg = data.get("scanners", {})

        api_key = None
        if "api_key_env" in llm_cfg:
            api_key = os.environ.get(llm_cfg["api_key_env"])
        elif "api_key" in llm_cfg:
            api_key = llm_cfg["api_key"]

        provider = llm_cfg.get("provider", "openai")

        # Fall back to env var when no key specified in config
        if api_key is None:
            api_key = _resolve_api_key(provider)

        vuln_cfg = data.get("vuln_check", {}) or {}
        vuln_provider_yaml = vuln_cfg.get("search_provider")
        # Env var always overrides YAML provider if set
        vuln_provider = os.environ.get("VULN_SEARCH_PROVIDER") or vuln_provider_yaml
        if vuln_provider == "none":
            vuln_provider = None

        return cls(
            llm_provider=provider,
            llm_model=llm_cfg.get("model", "gpt-4o-mini"),
            llm_api_key=api_key,
            output_format=out_cfg.get("format", "html"),
            enabled_scanners=scan_cfg.get("enabled", list(_ALL_SCANNERS)),
            vuln_check_enabled=bool(vuln_cfg.get("enabled", True)),
            vuln_search_provider=vuln_provider,
            vuln_search_model=vuln_cfg.get("search_model"),
            vuln_osv_timeout=float(vuln_cfg.get("osv_timeout_seconds", 10.0)),
            vuln_web_timeout=float(vuln_cfg.get("web_timeout_seconds", 5.0)),
            vuln_web_retries=max(0, int(vuln_cfg.get("web_retries", 1))),
            max_repo_risk_signals=_parse_max_signals(out_cfg.get("max_repo_risk_signals", 10)),
        )

    _BOOL_FIELDS: frozenset[str] = frozenset({"no_llm"})

    @classmethod
    def load_from_args(cls, **kwargs: Any) -> "ScannerConfig":
        cfg = cls()
        for key, value in kwargs.items():
            if value is not None and hasattr(cfg, key):
                if key in cls._BOOL_FIELDS:
                    if isinstance(value, str):
                        value = value.lower() in ("1", "true", "yes")
                    else:
                        value = bool(value)
                setattr(cfg, key, value)
        # Resolve API key: CLI flag > env var > None
        if cfg.llm_api_key is None:
            cfg.llm_api_key = _resolve_api_key(cfg.llm_provider)
        # Resolve vuln search provider from env if not set via CLI
        if cfg.vuln_search_provider is None:
            env_vsp = os.environ.get("VULN_SEARCH_PROVIDER")
            if env_vsp and env_vsp != "none":
                cfg.vuln_search_provider = env_vsp
        return cfg

    def provider_factory(self) -> BaseLLMProvider:
        """Return the configured LLM provider instance."""
        if self.openai_compatible_url:
            from quin_scanner.llm.openai_compatible import OpenAICompatibleProvider
            return OpenAICompatibleProvider(
                base_url=self.openai_compatible_url,
                api_key=self.llm_api_key or "none",
                model=self.llm_model,
            )
        if self.llm_provider == "openai":
            from quin_scanner.llm.openai_provider import OpenAIProvider
            return OpenAIProvider(api_key=self.llm_api_key, model=self.llm_model)
        if self.llm_provider == "anthropic":
            from quin_scanner.llm.anthropic_provider import AnthropicProvider
            return AnthropicProvider(api_key=self.llm_api_key, model=self.llm_model or "claude-haiku-4-5-20251001")
        if self.llm_provider == "google":
            from quin_scanner.llm.google_provider import GoogleProvider
            return GoogleProvider(api_key=self.llm_api_key, model=self.llm_model or "gemini-2.0-flash")
        if self.llm_provider == "ollama":
            from quin_scanner.llm.ollama_provider import OllamaProvider
            return OllamaProvider(model=self.llm_model or "llama3.2")
        raise ValueError(f"Unknown LLM provider: {self.llm_provider!r}")


def _resolve_api_key(provider: str) -> str | None:
    env_vars = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
        "gemini": "GOOGLE_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
        "ollama": None,
    }
    env_var = env_vars.get(provider)
    return os.environ.get(env_var) if env_var else None
