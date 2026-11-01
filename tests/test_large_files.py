"""A single huge data file must not dominate a scan (found by the rc2 UAT: one 162 MB JSON took 25 of a scan's 45 seconds)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner import orchestrator
from quin_scanner.cli import cli
from quin_scanner.orchestrator import FileTooLarge, _ReadTrackingAccessor
from quin_scanner.repo_accessor import LocalRepoAccessor


def test_reading_a_file_over_the_limit_raises_an_ordinary_exception_and_is_counted_apart(tmp_path):
    (tmp_path / "big.json").write_text("x" * 2048, encoding="utf-8")
    (tmp_path / "small.json").write_text("{}", encoding="utf-8")
    tracked = _ReadTrackingAccessor(LocalRepoAccessor(tmp_path), max_scanned_file_bytes=1024)
    with pytest.raises(FileTooLarge):
        tracked.read_file("big.json")
    assert issubclass(FileTooLarge, Exception)  # scanners skip unreadable files with `except Exception: continue`
    assert tracked.read_file("small.json") == "{}"
    coverage = tracked.coverage()
    assert coverage["files_skipped_too_large"] == 1
    assert coverage["files_failed_to_read"] == 0 and coverage["files_read"] == 1


def test_coverage_has_no_extra_key_when_nothing_was_skipped(tmp_path):
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    tracked = _ReadTrackingAccessor(LocalRepoAccessor(tmp_path))
    tracked.read_file("a.json")
    assert "files_skipped_too_large" not in tracked.coverage()


def test_the_default_limit_is_generous_for_source_and_config():
    assert orchestrator._MAX_SCANNED_FILE_BYTES >= 5 * 1024 * 1024


def test_a_scan_skips_a_huge_data_file_and_still_reports_everything_else(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "_MAX_SCANNED_FILE_BYTES", 64 * 1024)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8")
    (repo / ".env").write_text("OPENAI_API_KEY=abc123abc123\n", encoding="utf-8")
    (repo / "data.json").write_text(json.dumps({"rows": [{"id": i, "text": "lorem ipsum" * 5} for i in range(5000)]}), encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["is_ai_application"] is True
    assert any(a["file_path"] == ".env" for a in report["artifacts"])
    assert report["coverage"]["files_skipped_too_large"] == 1


class _Spy(LocalRepoAccessor):
    def __init__(self, root):
        super().__init__(root)
        self.reads: list[str] = []

    def read_file(self, path):
        self.reads.append(path)
        return super().read_file(path)


def test_an_oversized_local_file_is_never_read_at_all(tmp_path):
    (tmp_path / "big.json").write_text("x" * 4096, encoding="utf-8")
    spy = _Spy(tmp_path)
    tracked = _ReadTrackingAccessor(spy, max_scanned_file_bytes=1024)
    for _ in range(3):  # three scanners ask for the same file
        with pytest.raises(FileTooLarge):
            tracked.read_file("big.json")
    assert spy.reads == [], "the file was read although its size is known to be over the limit"
    assert tracked.coverage()["files_skipped_too_large"] == 1


def test_accessors_without_a_size_still_enforce_the_limit_after_reading(tmp_path):
    class NoSize:
        def read_file(self, path):
            return "x" * 4096

    tracked = _ReadTrackingAccessor(NoSize(), max_scanned_file_bytes=1024)
    with pytest.raises(FileTooLarge):
        tracked.read_file("remote.json")
