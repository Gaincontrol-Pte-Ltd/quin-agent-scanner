"""Tests for model identifier, placeholder filtering, and provider classification."""
from __future__ import annotations

import pytest

from quin_scanner.model_identifier import (
    ModelIdentifier,
    classify_provider,
    _is_plausible_model_name,
    _split_colon_prefix,
)
from quin_scanner.orchestrator import (
    _is_placeholder_model,
    _is_test_path,
    _sanitise_model_usages,
)
from quin_scanner.models import ModelUsage


class TestClassifyProvider:
    @pytest.mark.parametrize("model,expected", [
        ("gpt-4o", "openai"),
        ("gpt-4o-mini", "openai"),
        ("gpt-3.5-turbo", "openai"),
        ("text-embedding-ada-002", "openai"),
        ("dall-e-3", "openai"),
        ("claude-sonnet-4-20250514", "anthropic"),
        ("claude-haiku-4-5-20251001", "anthropic"),
        ("claude-opus", "anthropic"),
        ("opus", "anthropic"),
        ("sonnet", "anthropic"),
        ("haiku", "anthropic"),
        ("gemini-2.0-flash", "google"),
        ("gemini-1.5-pro", "google"),
        ("llama3.2", "meta"),
        ("mistral-large", "mistral"),
        ("mixtral-8x7b", "mistral"),
        ("command-r-plus", "cohere"),
        ("dbrx-instruct", "databricks"),
    ])
    def test_known_models(self, model, expected):
        assert classify_provider(model) == expected

    def test_colon_prefix(self):
        assert classify_provider("openai:gpt-4o-mini") == "openai"
        assert classify_provider("anthropic:claude-haiku") == "anthropic"

    def test_unknown_model(self):
        assert classify_provider("totally-unknown-model-xyz") == "unknown"

    def test_empty_string(self):
        assert classify_provider("") == "unknown"


class TestSplitColonPrefix:
    def test_valid_prefix(self):
        assert _split_colon_prefix("openai:gpt-4o") == ("openai", "gpt-4o")

    def test_no_prefix(self):
        assert _split_colon_prefix("gpt-4o") == ("", "gpt-4o")

    def test_unknown_prefix_ignored(self):
        assert _split_colon_prefix("foobar:model") == ("", "foobar:model")

    def test_empty_after_colon(self):
        assert _split_colon_prefix("openai:") == ("", "openai:")


class TestIsPlausibleModelName:
    def test_valid_names(self):
        assert _is_plausible_model_name("gpt-4o") is True
        assert _is_plausible_model_name("claude-haiku-4-5-20251001") is True
        assert _is_plausible_model_name("llama3.2") is True

    def test_rejects_short(self):
        assert _is_plausible_model_name("ab") is False

    def test_rejects_variables(self):
        assert _is_plausible_model_name("${MODEL}") is False
        assert _is_plausible_model_name("$MODEL") is False

    def test_rejects_paths(self):
        assert _is_plausible_model_name("/path/to/model") is False

    def test_rejects_special_values(self):
        assert _is_plausible_model_name("none") is False
        assert _is_plausible_model_name("null") is False
        assert _is_plausible_model_name("true") is False


class TestIsPlaceholderModel:
    def test_placeholder_prefixes(self):
        assert _is_placeholder_model("your_model") is True
        assert _is_placeholder_model("test-model") is True
        assert _is_placeholder_model("mock-gpt") is True
        assert _is_placeholder_model("fake-llm") is True
        assert _is_placeholder_model("dummy-model") is True

    def test_placeholder_exact(self):
        assert _is_placeholder_model("model_id") is True
        assert _is_placeholder_model("model_name") is True
        assert _is_placeholder_model("<model>") is True
        assert _is_placeholder_model("placeholder") is True

    def test_real_models_pass(self):
        assert _is_placeholder_model("gpt-4o") is False
        assert _is_placeholder_model("claude-haiku-4-5-20251001") is False
        assert _is_placeholder_model("llama3.2") is False

    def test_names_with_spaces(self):
        assert _is_placeholder_model("some model name") is True

    def test_short_names(self):
        assert _is_placeholder_model("ab") is True


class TestIsTestPath:
    def test_test_directories(self):
        assert _is_test_path("tests/test_main.py") is True
        assert _is_test_path("test/test_main.py") is True
        assert _is_test_path("__tests__/main.test.js") is True
        assert _is_test_path("fixtures/data.json") is True

    def test_test_file_patterns(self):
        assert _is_test_path("src/test_config.py") is True
        assert _is_test_path("conftest.py") is True
        # These patterns only match at path boundaries, not mid-filename
        assert _is_test_path("src/main.spec.ts") is False
        assert _is_test_path("src/utils_test.go") is False

    def test_non_test_paths(self):
        assert _is_test_path("src/main.py") is False
        assert _is_test_path("src/config.py") is False
        assert _is_test_path("lib/utils.js") is False


class TestSanitiseModelUsages:
    def _make_usage(self, model_name, provider="openai", file_path="src/main.py"):
        return ModelUsage(
            provider=provider,
            model_name=model_name,
            source="code",
            file_path=file_path,
            line_number=1,
        )

    def test_filters_placeholders(self):
        usages = [self._make_usage("gpt-4o"), self._make_usage("your_model")]
        clean, test_count = _sanitise_model_usages(usages)
        assert len(clean) == 1
        assert clean[0].model_name == "gpt-4o"
        assert test_count == 0

    def test_filters_test_files(self):
        usages = [
            self._make_usage("gpt-4o", file_path="src/main.py"),
            self._make_usage("gpt-4o", file_path="tests/test_main.py"),
        ]
        clean, test_count = _sanitise_model_usages(usages)
        assert len(clean) == 1
        assert test_count == 1

    def test_deduplicates_by_model_name(self):
        usages = [
            self._make_usage("gpt-4o", provider="unknown"),
            self._make_usage("gpt-4o", provider="openai"),
        ]
        clean, _ = _sanitise_model_usages(usages)
        assert len(clean) == 1
        assert clean[0].provider == "openai"  # prefers known provider

    def test_empty_input(self):
        clean, test_count = _sanitise_model_usages([])
        assert clean == []
        assert test_count == 0


class TestModelIdentifierScanContent:
    def test_python_model_assignment(self):
        content = 'client = OpenAI()\nresponse = client.chat.completions.create(model="gpt-4o")\n'
        identifier = ModelIdentifier()
        usages = identifier._scan_content(content, "app.py")
        assert len(usages) == 1
        assert usages[0].model_name == "gpt-4o"
        assert usages[0].provider == "openai"

    def test_yaml_config(self):
        content = "llm:\n  model: claude-haiku-4-5-20251001\n"
        identifier = ModelIdentifier()
        usages = identifier._scan_content(content, "config.yaml")
        assert len(usages) == 1
        assert usages[0].model_name == "claude-haiku-4-5-20251001"

    def test_env_file(self):
        content = "OPENAI_MODEL=gpt-4o-mini\n"
        identifier = ModelIdentifier()
        usages = identifier._scan_content(content, ".env")
        assert len(usages) == 1
        assert usages[0].model_name == "gpt-4o-mini"
        assert usages[0].source == "env_var"

    def test_json_config(self):
        content = '{"model": "gemini-2.0-flash"}\n'
        identifier = ModelIdentifier()
        usages = identifier._scan_content(content, "config.json")
        assert len(usages) == 1
        assert usages[0].model_name == "gemini-2.0-flash"
