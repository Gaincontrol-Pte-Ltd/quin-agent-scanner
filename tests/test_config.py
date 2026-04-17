"""Tests for ScannerConfig loading and merging."""
from __future__ import annotations

import textwrap

import pytest

from quin_scanner.config import ScannerConfig, _resolve_api_key


class TestResolveApiKey:
    def test_openai_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
        assert _resolve_api_key("openai") == "sk-test-123"

    def test_anthropic_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        assert _resolve_api_key("anthropic") == "sk-ant-test"

    def test_google_key(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "goog-test")
        assert _resolve_api_key("google") == "goog-test"

    def test_gemini_maps_to_google(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "goog-test")
        assert _resolve_api_key("gemini") == "goog-test"

    def test_ollama_returns_none(self):
        assert _resolve_api_key("ollama") is None

    def test_unknown_provider_returns_none(self):
        assert _resolve_api_key("unknown-provider") is None

    def test_missing_env_var_returns_none(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert _resolve_api_key("openai") is None


class TestLoadFromArgs:
    def test_defaults(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        cfg = ScannerConfig.load_from_args()
        assert cfg.llm_provider == "openai"
        assert cfg.llm_model == "gpt-4o-mini"
        assert cfg.no_llm is False
        assert cfg.vuln_check_enabled is True

    def test_overrides(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        cfg = ScannerConfig.load_from_args(
            llm_provider="anthropic",
            llm_model="claude-haiku-4-5-20251001",
            no_llm=True,
        )
        assert cfg.llm_provider == "anthropic"
        assert cfg.llm_model == "claude-haiku-4-5-20251001"
        assert cfg.no_llm is True

    def test_no_llm_bool_coercion_from_string(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        cfg = ScannerConfig.load_from_args(no_llm="true")
        assert cfg.no_llm is True

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
        cfg = ScannerConfig.load_from_args(llm_provider="openai")
        assert cfg.llm_api_key == "sk-from-env"

    def test_explicit_api_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
        cfg = ScannerConfig.load_from_args(llm_provider="openai", llm_api_key="sk-explicit")
        assert cfg.llm_api_key == "sk-explicit"

    def test_vuln_search_provider_from_env(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("VULN_SEARCH_PROVIDER", "perplexity")
        cfg = ScannerConfig.load_from_args()
        assert cfg.vuln_search_provider == "perplexity"

    def test_vuln_search_provider_none_ignored(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("VULN_SEARCH_PROVIDER", "none")
        cfg = ScannerConfig.load_from_args()
        assert cfg.vuln_search_provider is None


class TestLoadFromFile:
    def test_minimal_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            llm:
              provider: anthropic
              model: claude-haiku-4-5-20251001
            output:
              format: json
        """))
        cfg = ScannerConfig.load_from_file(str(config_file))
        assert cfg.llm_provider == "anthropic"
        assert cfg.llm_model == "claude-haiku-4-5-20251001"
        assert cfg.output_format == "json"
        assert cfg.llm_api_key == "sk-ant-test"

    def test_api_key_from_env_var_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_CUSTOM_KEY", "sk-custom")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            llm:
              provider: openai
              api_key_env: MY_CUSTOM_KEY
        """))
        cfg = ScannerConfig.load_from_file(str(config_file))
        assert cfg.llm_api_key == "sk-custom"

    def test_scanners_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            llm:
              provider: openai
            scanners:
              enabled:
                - dependency
                - framework
        """))
        cfg = ScannerConfig.load_from_file(str(config_file))
        assert cfg.enabled_scanners == ["dependency", "framework"]

    def test_vuln_check_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("VULN_SEARCH_PROVIDER", raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(textwrap.dedent("""\
            llm:
              provider: openai
            vuln_check:
              enabled: true
              search_provider: anthropic
              osv_timeout_seconds: 20
              web_timeout_seconds: 30
        """))
        cfg = ScannerConfig.load_from_file(str(config_file))
        assert cfg.vuln_check_enabled is True
        assert cfg.vuln_search_provider == "anthropic"
        assert cfg.vuln_osv_timeout == 20.0
        assert cfg.vuln_web_timeout == 30.0


class TestProviderFactory:
    def test_openai_provider(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        cfg = ScannerConfig(llm_provider="openai", llm_api_key="sk-test")
        provider = cfg.provider_factory()
        from quin_scanner.llm.openai_provider import OpenAIProvider
        assert isinstance(provider, OpenAIProvider)

    def test_anthropic_provider(self):
        cfg = ScannerConfig(llm_provider="anthropic", llm_api_key="sk-ant-test")
        provider = cfg.provider_factory()
        from quin_scanner.llm.anthropic_provider import AnthropicProvider
        assert isinstance(provider, AnthropicProvider)

    def test_unknown_provider_raises(self):
        cfg = ScannerConfig(llm_provider="nonexistent", llm_api_key="key")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            cfg.provider_factory()

    def test_openai_compatible_provider(self):
        cfg = ScannerConfig(
            llm_provider="openai",
            llm_api_key="sk-test",
            openai_compatible_url="http://localhost:11434/v1",
        )
        provider = cfg.provider_factory()
        from quin_scanner.llm.openai_compatible import OpenAICompatibleProvider
        assert isinstance(provider, OpenAICompatibleProvider)
