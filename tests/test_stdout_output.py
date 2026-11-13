"""`-f -` writes the report to stdout instead of a file named "-" (#103)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
import yaml
from click.testing import CliRunner

from quin_scanner.cli import cli

FAST = ["--no-llm", "--no-vuln-check"]


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    (path / "main.py").write_text(
        'from crewai import Agent\nAgent(name="Größe – 検索", role="r", goal="g", backstory="b")\n', encoding="utf-8"
    )
    (path / "requirements.txt").write_text("crewai\n", encoding="utf-8")
    return path


@pytest.fixture
def skills(tmp_path):
    path = tmp_path / "skills" / "demo"
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill.\n---\n\nFormat text.\n", encoding="utf-8")
    return tmp_path / "skills"


@pytest.mark.parametrize("fmt, parse", [("json", json.loads), ("yaml", yaml.safe_load), ("sarif", json.loads)])
def test_scan_dash_writes_the_report_to_stdout(tmp_path, repo, monkeypatch, fmt, parse):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["scan", str(repo), *FAST, "-o", fmt, "-f", "-"])
    assert result.exit_code == 0, result.stderr
    data = parse(result.stdout)
    if fmt != "sarif":
        assert data["is_ai_application"] is True
        assert "Größe – 検索" in [a["name"] for a in data["agents"]]
    assert not (tmp_path / "-").exists()
    assert not (tmp_path / "report").exists()
    assert "Report written" not in result.stderr


def test_scan_dash_keeps_progress_and_messages_off_stdout(tmp_path, repo, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["scan", str(repo), *FAST, "-o", "json", "-f", "-"])
    assert result.stdout.lstrip().startswith("{")
    json.loads(result.stdout)


def test_scan_dash_failure_keeps_exit_code_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path / "missing"), *FAST, "-o", "json", "-f", "-"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert not (tmp_path / "-").exists()


def test_skills_scan_dash_writes_to_stdout(tmp_path, skills, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["skills", "scan", str(skills), "--no-vuln-check", "-o", "json", "-f", "-"])
    assert result.exit_code == 0, result.stderr
    json.loads(result.stdout)
    assert not (tmp_path / "-").exists()


def test_scan_dash_is_utf8_when_stdout_is_not(tmp_path, repo):
    """A pipe on Windows defaults to cp1252, which cannot encode most names: the report is UTF-8 regardless."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    proc = subprocess.run(
        [sys.executable, "-c", "from quin_scanner.cli import cli; cli()", "scan", str(repo), *FAST, "-o", "json", "-f", "-"],
        capture_output=True, cwd=tmp_path, env=env, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert b"\r\n" not in proc.stdout
    data = json.loads(proc.stdout.decode("utf-8"))
    assert "Größe – 検索" in [a["name"] for a in data["agents"]]
