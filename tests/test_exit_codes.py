"""Exit codes are part of the CLI contract. The rows mirror the table in docs/stability.md."""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.repo_accessor import RepoAccessorFactory

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "skills_repo"
ROOT = Path(__file__).resolve().parent.parent
FAST = ["--no-llm", "--no-vuln-check"]
# Not a path, URL or owner/repo: RepoAccessorFactory.create raises ValueError. (A non-existent absolute
# path is NOT rejected today: LocalRepoAccessor accepts it and the scan exits 0.)
INVALID_TARGET = "not-a-valid-target"


@pytest.fixture
def good_repo(tmp_path):
    repo = tmp_path / "good"
    repo.mkdir()
    (repo / "agent.py").write_text('system_prompt = "You are a helpful research assistant that summarises papers."\n')
    return repo


def _run(args):
    return CliRunner().invoke(cli, args)


# --- scan -----------------------------------------------------------------------------------

def test_scan_success_exits_0_even_with_findings(tmp_path):
    result = _run(["scan", str(FIXTURE), "-o", "json", "-f", str(tmp_path / "r.json"), *FAST])
    assert result.exit_code == 0, result.output  # the fixture contains a HIGH_RISK skill


def test_scan_invalid_target_exits_1(tmp_path):
    result = _run(["scan", INVALID_TARGET, "-o", "json", *FAST])
    assert result.exit_code == 1


def test_scan_bad_skills_baseline_exits_2(tmp_path):
    bad = tmp_path / "baseline.yaml"
    bad.write_text("version: 99\nentries: []\n")
    result = _run(["scan", str(FIXTURE), "-o", "json", "-f", str(tmp_path / "r.json"), "--skills-baseline", str(bad), *FAST])
    assert result.exit_code == 2


def test_scan_usage_error_exits_2():
    assert _run(["scan"]).exit_code == 2
    assert _run(["scan", ".", "--no-such-option"]).exit_code == 2


# --- scan-batch -----------------------------------------------------------------------------

def test_scan_batch_all_targets_ok_exits_0(tmp_path, good_repo):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{good_repo}\n# a comment\n{FIXTURE}\n")
    result = _run(["scan-batch", str(targets), "-o", "json", "-d", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 0, result.output
    assert len(list((tmp_path / "out").glob("*.json"))) == 2


def test_scan_batch_a_failed_target_exits_1_but_other_reports_are_written(tmp_path, good_repo):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{good_repo}\n{INVALID_TARGET}\n")
    result = _run(["scan-batch", str(targets), "-o", "json", "-d", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 1
    assert len(list((tmp_path / "out").glob("*.json"))) == 1
    assert "1 of 2 targets failed" in result.output


def test_scan_batch_all_targets_failed_exits_1(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{INVALID_TARGET}\n{INVALID_TARGET}-2\n")
    result = _run(["scan-batch", str(targets), "-o", "json", "-d", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 1
    assert "2 of 2 targets failed" in result.output


def test_scan_batch_empty_file_exits_0(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# nothing\n")
    assert _run(["scan-batch", str(targets), "-d", str(tmp_path / "out"), *FAST]).exit_code == 0


def test_scan_batch_missing_targets_file_is_a_usage_error(tmp_path):
    assert _run(["scan-batch", str(tmp_path / "nope.txt")]).exit_code == 2


# --- scan-org -------------------------------------------------------------------------------

class _FakeClient:
    repos: list = []
    error: Exception | None = None

    def __init__(self, token=None):
        pass

    def list_repos_for(self, org, **kwargs):
        if _FakeClient.error:
            raise _FakeClient.error
        return _FakeClient.repos


def _repo(name):
    return types.SimpleNamespace(full_name=f"acme/{name}", clone_url=name, default_branch="main")


@pytest.fixture
def fake_org(monkeypatch, good_repo):
    monkeypatch.setattr("quin_scanner.github_client.GitHubClient", _FakeClient)
    _FakeClient.error = None
    _FakeClient.repos = []
    original = RepoAccessorFactory.create

    def create(target, **kwargs):
        # "good" maps to the local repo, anything else fails like an unreachable clone
        if target == "good":
            return original(str(good_repo))
        raise ValueError(f"cannot clone {target}")

    monkeypatch.setattr(RepoAccessorFactory, "create", staticmethod(create))
    return _FakeClient


def test_scan_org_all_repos_ok_exits_0_and_prints_a_json_summary(tmp_path, fake_org):
    fake_org.repos = [_repo("good")]
    result = _run(["scan-org", "acme", "-o", "json", "--output-dir", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    assert summary == [{"repo": "acme/good", "is_ai_application": summary[0]["is_ai_application"],
                        "confidence": summary[0]["confidence"]}]


def test_scan_org_a_failed_repo_exits_1_but_summary_still_printed(tmp_path, fake_org):
    fake_org.repos = [_repo("good"), _repo("broken")]
    result = _run(["scan-org", "acme", "-o", "json", "--output-dir", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 1
    assert [item["repo"] for item in json.loads(result.stdout)] == ["acme/good"]
    assert "1 of 2 repositories failed" in result.stderr


def test_scan_org_listing_failure_exits_1(tmp_path, fake_org):
    fake_org.error = RuntimeError("403 from GitHub")
    result = _run(["scan-org", "acme", "--output-dir", str(tmp_path / "out"), *FAST])
    assert result.exit_code == 1
    assert "Error listing repos" in result.stderr


# --- the documented table stays in sync -----------------------------------------------------

def test_stability_doc_no_longer_marks_batch_exit_codes_as_planned():
    text = (ROOT / "docs" / "stability.md").read_text(encoding="utf-8")
    assert "planned: 1 if any target failed" not in text
    assert "at least one target failed" in text
    assert "at least one repository failed" in text
