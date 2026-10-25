"""Content fingerprints used to match a running agent to the repository it came from."""
from __future__ import annotations

import hashlib

from quin_scanner.config import ScannerConfig
from quin_scanner.file_fingerprint import MAX_FILES, MIN_CHARS, compute_file_fingerprint, compute_file_hashes, normalized_digest
from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor

BODY = "def handler(event):\n    value = event.get('value')\n    return {'ok': True, 'value': value, 'note': 'x' * 60}\n"

# The same fixture is asserted in aegis_core/tests (SDK): if either side changes how it hashes, both fail.
SHARED_FIXTURE_TEXT = "def run():\n    return 'a project file long enough to be fingerprinted by both the scanner and the SDK, line two'\n"
SHARED_FIXTURE_SHA256 = hashlib.sha256(SHARED_FIXTURE_TEXT.encode("utf-8")).hexdigest()


def _hashes(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, newline="")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return compute_file_hashes(accessor, index)


def test_shared_fixture_is_stable():
    assert len(SHARED_FIXTURE_TEXT.strip()) >= MIN_CHARS
    assert normalized_digest(SHARED_FIXTURE_TEXT) == SHARED_FIXTURE_SHA256
    assert SHARED_FIXTURE_SHA256 == "07646d3a456702cab03b1e008ce909940e3e377e92d10be5cecb6a92dbafd044"


def test_line_endings_do_not_change_the_hash():
    assert normalized_digest(BODY) == normalized_digest(BODY.replace("\n", "\r\n")) == normalized_digest(BODY.replace("\n", "\r"))


def test_a_different_file_has_a_different_hash():
    assert normalized_digest(BODY) != normalized_digest(BODY + "# changed\n")


def test_small_files_are_not_fingerprinted():
    assert normalized_digest("") is None
    assert normalized_digest("x = 1\n") is None
    assert normalized_digest(" " * 500 + "\n") is None
    assert normalized_digest("y" * (MIN_CHARS - 1)) is None and normalized_digest("y" * MIN_CHARS) is not None


def test_source_files_only_and_tests_and_vendored_code_are_left_out(tmp_path):
    out = _hashes(tmp_path, {
        "src/agent.py": BODY, "src/util.ts": BODY, "README.md": BODY * 3, "data.json": BODY,
        "tests/test_agent.py": BODY, "pkg/test_x.py": BODY, "pkg/x_test.py": BODY, "a.spec.ts": BODY,
        "node_modules/lib/index.js": BODY, "src/__init__.py": "",
    })
    assert sorted(h["path"] for h in out) == ["src/agent.py", "src/util.ts"]


def test_hash_matches_between_crlf_and_lf_checkouts(tmp_path):
    a = _hashes(tmp_path / "a", {"m.py": BODY})
    b = _hashes(tmp_path / "b", {"m.py": BODY.replace("\n", "\r\n")})
    assert a == b and len(a) == 1


def test_cap(tmp_path, monkeypatch):
    monkeypatch.setattr("quin_scanner.file_fingerprint.MAX_FILES", 3)
    out = _hashes(tmp_path, {f"m{i}.py": BODY + f"# {i}\n" for i in range(6)})
    assert len(out) == 3


def test_unreadable_file_is_skipped(tmp_path):
    (tmp_path / "ok.py").write_text(BODY)
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe" + BODY.encode())
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    assert {h["path"] for h in compute_file_hashes(accessor, index)} == {"ok.py", "bad.py"}  # bad bytes are replaced, not fatal


def test_report_carries_hashes_in_json_but_not_in_html(tmp_path):
    from quin_scanner.models import ScanReport
    from quin_scanner.report import ReportGenerator
    r = ScanReport(repo_path="x", scan_timestamp="t", is_ai_application=False, confidence=0.0, file_hashes=[{"path": "a.py", "sha256": "ab" * 32}])
    assert r.to_dict()["file_hashes"] == [{"path": "a.py", "sha256": "ab" * 32}]
    assert "ab" * 32 not in ReportGenerator.to_html(r)


def _fingerprint(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, newline="")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return compute_file_fingerprint(accessor, index)


def test_the_cap_is_large_enough_for_a_big_monorepo():
    # a real monorepo had about 3200 qualifying files and was silently cut at 3000 (gap 19.11, found 2026-10-05)
    assert MAX_FILES >= 10_000


def test_stats_say_what_was_considered_and_what_was_hashed(tmp_path):
    hashes, stats = _fingerprint(tmp_path, {
        "a.py": BODY, "b.py": BODY + "# b\n", "tiny.py": "x = 1\n",      # tiny: considered, not hashed
        "tests/test_a.py": BODY, "README.md": BODY,                      # test file and non-source: not even considered
    })
    assert len(hashes) == 2 and stats == {"candidates": 3, "hashed": 2, "truncated": False}


def test_a_cut_list_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr("quin_scanner.file_fingerprint.MAX_FILES", 3)
    hashes, stats = _fingerprint(tmp_path, {f"m{i}.py": BODY + f"# {i}\n" for i in range(6)})
    assert len(hashes) == 3 and stats == {"candidates": 6, "hashed": 3, "truncated": True}


def test_exactly_at_the_cap_with_nothing_after_it_is_not_a_cut(tmp_path, monkeypatch):
    monkeypatch.setattr("quin_scanner.file_fingerprint.MAX_FILES", 3)
    hashes, stats = _fingerprint(tmp_path, {f"m{i}.py": BODY + f"# {i}\n" for i in range(3)})
    assert len(hashes) == 3 and stats["truncated"] is False


def test_the_files_that_were_kept_are_the_first_in_path_order(tmp_path, monkeypatch):
    monkeypatch.setattr("quin_scanner.file_fingerprint.MAX_FILES", 2)
    hashes, _ = _fingerprint(tmp_path, {"b/z.py": BODY + "# 1\n", "a/y.py": BODY + "# 2\n", "c/x.py": BODY + "# 3\n"})
    assert [h["path"] for h in hashes] == ["a/y.py", "b/z.py"]


def test_the_stats_reach_the_report(tmp_path):
    import json

    from click.testing import CliRunner

    from quin_scanner.cli import cli

    (tmp_path / "agent.py").write_text(BODY)
    out = tmp_path / "report.json"
    res = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert res.exit_code == 0, res.output
    report = json.loads(out.read_text())
    assert report["metadata"]["file_hash_stats"] == {"candidates": 1, "hashed": 1, "truncated": False}
    assert [h["path"] for h in report["file_hashes"]] == ["agent.py"]
