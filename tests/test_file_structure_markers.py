"""Directory markers must not make ordinary repositories look like AI applications (UAT finding U2)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli


def _scan(tmp_path, files: dict[str, str]) -> dict:
    repo = tmp_path / "repo"
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("ci_dir", [".github/workflows", ".gitea/workflows", ".forgejo/workflows", ".gitlab/workflows", ".circleci/workflows"])
def test_ci_workflow_directories_are_not_ai_markers(tmp_path, ci_dir):
    report = _scan(tmp_path, {f"{ci_dir}/ci.yml": "name: CI\non: push\n", "main.go": "package main\nfunc main() {}\n"})
    assert report["is_ai_application"] is False
    assert not [a for a in report["artifacts"] if a["scanner_name"] == "FileStructureScanner"]


def test_a_real_workflows_directory_is_still_a_marker(tmp_path):
    report = _scan(tmp_path, {"workflows/triage.yaml": "steps: []\n"})
    assert any(a["scanner_name"] == "FileStructureScanner" and a["match_text"] == "workflows/" for a in report["artifacts"])


def test_agent_directories_inside_github_are_still_markers(tmp_path):
    # .github/agents holds GitHub Copilot agent profiles: a real AI signal that must not be lost with the CI fix.
    report = _scan(tmp_path, {".github/agents/reviewer.md": "# Reviewer\n", ".github/workflows/ci.yml": "name: CI\n"})
    markers = {a["match_text"] for a in report["artifacts"] if a["scanner_name"] == "FileStructureScanner"}
    assert "agents/" in markers and "workflows/" not in markers


def test_a_ci_workflows_directory_beside_a_real_one(tmp_path):
    report = _scan(tmp_path, {".github/workflows/ci.yml": "name: CI\n", "workflows/triage.yaml": "steps: []\n"})
    assert any(a["match_text"] == "workflows/" for a in report["artifacts"] if a["scanner_name"] == "FileStructureScanner")
