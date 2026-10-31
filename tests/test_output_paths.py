"""Output files: parent folders are created, and a bad destination fails before any scanning (UAT finding U6)."""
from __future__ import annotations

import os
import sys

import pytest
from click.testing import CliRunner

from quin_scanner import orchestrator
from quin_scanner.cli import cli


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    (path / "main.py").write_text("from openai import OpenAI\nOpenAI()\n", encoding="utf-8")
    return path


@pytest.fixture
def skills(tmp_path):
    path = tmp_path / "skills" / "demo"
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill.\n---\n\nFormat text.\n", encoding="utf-8")
    return tmp_path / "skills"


def test_scan_creates_the_parent_folders_of_the_output_file(tmp_path, repo):
    out = tmp_path / "new" / "nested" / "report.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_skills_scan_creates_the_parent_folders_of_the_output_file(tmp_path, skills):
    out = tmp_path / "new" / "nested" / "skills.json"
    result = CliRunner().invoke(cli, ["skills", "scan", str(skills), "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_skills_baseline_creates_the_parent_folders_of_the_output_file(tmp_path, skills):
    out = tmp_path / "new" / "nested" / "baseline.yaml"
    result = CliRunner().invoke(cli, ["skills", "baseline", str(skills), "-o", str(out), "--no-vuln-check"])
    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_scan_with_an_impossible_output_path_fails_before_scanning(tmp_path, repo, monkeypatch):
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")

    def must_not_run(*args, **kwargs):
        raise AssertionError("the scan ran although the output path cannot be written")

    monkeypatch.setattr(orchestrator.ScanOrchestrator, "run", must_not_run)
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "-o", "json", "-f", str(blocker / "report.json")])
    assert result.exit_code == 1
    assert "cannot write" in result.stderr and "Traceback" not in result.stderr
    assert "Errno" not in result.stderr


def test_skills_scan_with_an_impossible_output_path_fails_before_scanning(tmp_path, skills, monkeypatch):
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")

    def must_not_run(*args, **kwargs):
        raise AssertionError("the scan ran although the output path cannot be written")

    monkeypatch.setattr("quin_scanner.scanners.skills.runner.run_skill_scan", must_not_run)
    result = CliRunner().invoke(cli, ["skills", "scan", str(skills), "-o", "json", "-f", str(blocker / "x.json")])
    assert result.exit_code == 2
    assert "cannot write" in result.stderr and "Traceback" not in result.stderr


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX permissions and a non-root user")
def test_an_unwritable_folder_fails_before_scanning(tmp_path, repo, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    monkeypatch.setattr(orchestrator.ScanOrchestrator, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scan ran")))
    try:
        result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "-o", "json", "-f", str(locked / "r.json")])
    finally:
        locked.chmod(0o700)
    assert result.exit_code == 1 and "cannot write" in result.stderr
