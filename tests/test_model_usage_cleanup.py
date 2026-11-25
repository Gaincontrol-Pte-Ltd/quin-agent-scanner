"""model_usages: one entry per model, and no class names, stubs or tutorial placeholders (#86)."""
from __future__ import annotations

import pytest

from quin_scanner.models import ModelUsage
from quin_scanner.orchestrator import _is_placeholder_model, _sanitise_model_usages


def _usage(name: str, provider: str = "unknown", path: str = "app.py", source: str = "code") -> ModelUsage:
    return ModelUsage(provider=provider, model_name=name, source=source, file_path=path, line_number=1)


def test_a_provider_prefix_is_moved_into_provider():
    cleaned, _ = _sanitise_model_usages([_usage("openai:gpt-5.4", provider="openai", source="config")])
    assert [(u.provider, u.model_name) for u in cleaned] == [("openai", "gpt-5.4")]


def test_prefixed_and_plain_names_are_one_model():
    cleaned, _ = _sanitise_model_usages([
        _usage("gpt-5.4", provider="openai", path="multi_agents/task.json", source="config"),
        _usage("openai:gpt-5.4", provider="openai", path="benchmark_results/run.json", source="config"),
    ])
    assert [(u.provider, u.model_name) for u in cleaned] == [("openai", "gpt-5.4")]


def test_the_prefix_is_kept_when_it_is_not_a_known_provider():
    cleaned, _ = _sanitise_model_usages([_usage("llama3:8b")])
    assert [u.model_name for u in cleaned] == ["llama3:8b"]


@pytest.mark.parametrize("name", [
    "Embeddings", "OpenAIEmbeddings", "ChatOpenAI",   # class names
    "my-llm", "my_model",                              # tutorial placeholders
    "stub-model", "conformance-stub", "mock_llm", "fake-chat-model", "dummy",  # stubs
])
def test_non_model_identifiers_are_rejected(name):
    assert _is_placeholder_model(name)


@pytest.mark.parametrize("name", [
    "gpt-4o", "claude-sonnet-4-20250514", "gemini-embedding-2", "text-embedding-3-large",
    "llama3", "mistral", "Qwen2.5-72B-Instruct", "Meta-Llama-3-8B", "o3-mini", "phi3",
])
def test_real_model_names_are_kept(name):
    assert not _is_placeholder_model(name)


@pytest.mark.parametrize("name, provider", [
    ("text-embedding-004", "google"), ("text-embedding-005", "google"),
    ("text-embedding-3-large", "openai"), ("text-embedding-ada-002", "openai"),
])
def test_google_embedding_models_are_not_openai(name, provider):
    from quin_scanner.model_identifier import classify_provider
    assert classify_provider(name) == provider


@pytest.mark.parametrize("line, role", [
    ('self.embedding_model = "text-embedding-3-large"', "embedding"),
    ('embed_model: "nomic-embed-text"', "embedding"),
    ('llm = ChatOpenAI(model="gpt-4o")', "unknown"),
])
def test_code_usages_take_the_embedding_role_from_the_assigned_name(line, role):
    from quin_scanner.model_identifier import ModelIdentifier
    usages = ModelIdentifier()._scan_code(line + "\n", "app.py")
    assert [u.role for u in usages] == [role]
