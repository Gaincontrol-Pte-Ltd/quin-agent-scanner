"""`--format` is a long alias for `-o`/`--output` wherever `-o` sets the report format (#104)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli

FAST = ["--no-llm", "--no-vuln-check"]


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    (path / "main.py").write_text('from crewai import Agent\nAgent(name="a", role="r", goal="g", backstory="b")\n')
    (path / "requirements.txt").write_text("crewai\n")
    return path


def test_scan_format_is_the_same_option_as_dash_o(repo):
    by_alias = CliRunner().invoke(cli, ["scan", str(repo), *FAST, "--format", "json", "-f", "-"])
    by_short = CliRunner().invoke(cli, ["scan", str(repo), *FAST, "-o", "json", "-f", "-"])
    assert by_alias.exit_code == by_short.exit_code == 0, by_alias.stderr
    assert json.loads(by_alias.stdout)["agents"] == json.loads(by_short.stdout)["agents"]


def test_skills_scan_accepts_format(tmp_path):
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill.\n---\n\nFormat text.\n")
    result = CliRunner().invoke(cli, ["skills", "scan", str(tmp_path / "skills"), "--no-vuln-check", "--format", "json"])
    assert result.exit_code == 0, result.stderr
    assert "skills" in json.loads(result.stdout)


@pytest.mark.parametrize("command", ["scan", "scan-batch", "scan-org", ("skills", "scan")])
def test_help_lists_the_alias(command):
    args = list(command) if isinstance(command, tuple) else [command]
    result = CliRunner().invoke(cli, [*args, "--help"])
    assert "--format" in result.output


def test_format_gets_the_same_file_name_hint(tmp_path):
    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-llm", "--format", "report.html"])
    assert result.exit_code == 2
    assert "-o html -f report.html" in result.stderr


def test_skills_baseline_dash_o_is_still_the_file():
    result = CliRunner().invoke(cli, ["skills", "baseline", "--help"])
    assert "--format" not in result.output
