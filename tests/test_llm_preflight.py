"""A missing API key or an unknown LLM provider fails before scanning, not after it (issue #83)."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

import quin_scanner.orchestrator as orchestrator
from quin_scanner.cli import cli
from quin_scanner.config import ScannerConfig

_KEY_VARS = ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for var in _KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)  # no .env to pick up
    project = tmp_path / "app"
    project.mkdir()
    (project / "main.py").write_text("print('hello')\n", encoding="utf-8")
    return project


@pytest.fixture
def scanning_must_not_start(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("the scan started before the LLM provider was opened")

    monkeypatch.setattr(orchestrator, "FileIndex", _boom)


def _scan(project, *args):
    return CliRunner().invoke(cli, ["scan", str(project), "--no-vuln-check", "-o", "json", *args])


def test_missing_key_fails_before_the_scan_and_says_how_to_continue(repo, scanning_must_not_start):
    result = _scan(repo, "--llm-provider", "openai")

    assert result.exit_code == 1
    assert "Cannot start LLM analysis with provider 'openai'" in result.output
    assert "--no-llm" in result.output
    assert "--llm-api-key" in result.output


def test_unknown_provider_fails_before_the_scan(repo, scanning_must_not_start):
    result = _scan(repo, "--llm-provider", "nonsense")

    assert result.exit_code == 1
    assert "Unknown LLM provider" in result.output


def test_no_llm_still_scans_without_a_key(repo):
    result = _scan(repo, "--no-llm")

    assert result.exit_code == 0, result.output


class _FailingProvider:
    """Stands in for a provider whose calls fail; the scan must still finish (analysis fails soft)."""

    def analyze_prompt(self, *args, **kwargs):
        raise RuntimeError("no network in tests")

    def generate(self, *args, **kwargs):
        raise RuntimeError("no network in tests")


def test_the_provider_is_opened_once_and_a_failing_llm_still_fails_soft(repo, monkeypatch):
    opened = []

    def _factory(self):
        opened.append(self.llm_provider)
        return _FailingProvider()

    monkeypatch.setattr(ScannerConfig, "provider_factory", _factory)

    result = _scan(repo, "--llm-provider", "openai", "--llm-api-key", "sk-test-not-a-real-key-123456")

    assert result.exit_code == 0, result.output
    assert opened == ["openai"]
