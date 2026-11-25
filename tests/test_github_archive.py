"""The owner/repo shorthand downloads the repository as one archive and extracts it safely (issue #87).

No network: quin_scanner._http.urlopen is replaced by a fake that serves an in-memory tarball, a tree and raw files.
"""
from __future__ import annotations

import io
import json
import os
import tarfile
import urllib.error
from pathlib import Path

import pytest

from quin_scanner import _github_archive, _http
from quin_scanner import repo_accessor as ra
from quin_scanner._github_archive import ArchiveError, extract
from quin_scanner.repo_accessor import GitHubMCPAccessor

SHA = "49943b5a94413a530761350f04e896f76e8d620e"
TOP = "pallets-flask-49943b5"


def make_tarball(entries, *, sha: str | None = SHA) -> bytes:
    """entries: (name, kind, payload) with kind 'file' (payload bytes), 'dir', 'sym' / 'hard' (payload = target), 'chr'."""
    buf = io.BytesIO()
    pax = {"comment": sha} if sha else {}
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers=pax) as tar:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
                continue
            info.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE, "chr": tarfile.CHRTYPE}[kind]
            if kind in ("sym", "hard"):
                info.linkname = payload
            tar.addfile(info)
    return buf.getvalue()


FILES = {
    "README.md": b"# flask\n",
    "src/flask/app.py": b"import os\r\nprint('crlf kept')\r\n",
    "src/flask/bad.py": b"x = '\xff\xfe'\n",  # invalid UTF-8, replaced the same way as the raw request did
}


def repo_tarball(extra=()) -> bytes:
    entries = [(TOP, "dir", None), (f"{TOP}/src", "dir", None), (f"{TOP}/src/flask", "dir", None)]
    entries += [(f"{TOP}/{path}", "file", data) for path, data in FILES.items()]
    return make_tarball(entries + list(extra))


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeGitHub:
    """Routes requests by URL; records every request."""

    def __init__(self, tarball: bytes | Exception, tree_paths=None, raw=None):
        self.tarball = tarball
        self.tree_paths = list(FILES) if tree_paths is None else tree_paths
        self.raw = {**FILES, **(raw or {})}
        self.requests = []

    def __call__(self, request, timeout=30):
        url = request.full_url
        self.requests.append(request)
        if "/tarball/" in url:
            if isinstance(self.tarball, Exception):
                raise self.tarball
            return _Response(self.tarball)
        if "/git/trees/" in url:
            return _Response(json.dumps({"tree": [{"path": p, "type": "blob"} for p in self.tree_paths]}).encode())
        if url.startswith("https://raw.githubusercontent.com/"):
            path = url.split("/", 6)[6]
            if path not in self.raw:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return _Response(self.raw[path])
        raise AssertionError(f"unexpected request {url}")

    def urls(self, part):
        return [r.full_url for r in self.requests if part in r.full_url]


@pytest.fixture
def github(monkeypatch):
    monkeypatch.setattr(ra.time, "sleep", lambda s: None)  # retries do not wait

    def install(fake: FakeGitHub) -> FakeGitHub:
        monkeypatch.setattr(_http, "urlopen", fake)
        return fake

    return install


def scan_all(accessor) -> dict[str, str]:
    return {path: accessor.read_file(path) for path in accessor.list_files()}


def expected_contents() -> dict[str, str]:
    return {path: data.decode("utf-8", errors="replace") for path, data in FILES.items()}


# ── accessor ────────────────────────────────────────────────────────────────


def test_one_archive_request_serves_every_file(github, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    fake = github(FakeGitHub(repo_tarball()))
    accessor = GitHubMCPAccessor("pallets", "flask")
    try:
        assert scan_all(accessor) == expected_contents()
        assert fake.urls("raw.githubusercontent.com") == []
        assert fake.urls("/tarball/") == ["https://api.github.com/repos/pallets/flask/tarball/main"]
        # The tree is listed at the commit the archive was made from, so both describe the same snapshot.
        assert fake.urls("/git/trees/") == [f"https://api.github.com/repos/pallets/flask/git/trees/{SHA}?recursive=1"]
        err = capsys.readouterr().err
        assert "Downloading pallets/flask (main) as one archive" in err
        assert "Extracted 3 files" in err
        assert capsys.readouterr().out == ""
    finally:
        accessor.cleanup()


def test_results_match_the_per_file_path(github):
    via_archive = GitHubMCPAccessor("pallets", "flask", github_token="t")
    github(FakeGitHub(repo_tarball()))
    archive_result = scan_all(via_archive)
    via_archive.cleanup()

    per_file = GitHubMCPAccessor("pallets", "flask", github_token="t")
    github(FakeGitHub(urllib.error.HTTPError("u", 500, "boom", {}, None)))
    assert scan_all(per_file) == archive_result


def test_the_top_level_directory_is_stripped(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(repo_tarball())
    result = extract(archive, tmp_path / "out")
    assert sorted(result.files) == sorted(FILES)
    assert result.commit_sha == SHA
    assert (tmp_path / "out" / "src" / "flask" / "app.py").read_bytes() == FILES["src/flask/app.py"]
    assert not (tmp_path / "out" / TOP).exists()


def test_a_symlink_is_written_as_its_target_text_never_as_a_link(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(make_tarball([
        (TOP, "dir", None),
        (f"{TOP}/inside", "sym", "README.md"),
        (f"{TOP}/outside", "sym", "../../../../etc/passwd"),
        (f"{TOP}/README.md", "file", b"hi"),
    ]))
    result = extract(archive, tmp_path / "out")
    for name, target in (("inside", b"README.md"), ("outside", b"../../../../etc/passwd")):
        on_disk = result.files[name]
        assert not os.path.islink(on_disk)
        assert on_disk.read_bytes() == target  # what the API returns for a symlink blob


@pytest.mark.parametrize(
    "entries, message",
    [
        ([(TOP, "dir", None), (f"{TOP}/../evil.py", "file", b"x")], "traversal"),
        ([(TOP, "dir", None), ("/etc/evil.py", "file", b"x")], "absolute"),
        ([(TOP, "dir", None), ("C:/evil.py", "file", b"x")], "absolute"),
        ([(TOP, "dir", None), ("other-top/evil.py", "file", b"x")], "top-level"),
        ([(TOP, "dir", None), (f"{TOP}/link", "hard", "/etc/passwd")], "link or special"),
        ([(TOP, "dir", None), (f"{TOP}/dev", "chr", None)], "link or special"),
        ([("evil.py", "file", b"x")], "top level"),
    ],
)
def test_unsafe_archives_are_rejected_and_nothing_escapes(tmp_path, entries, message):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(make_tarball(entries))
    with pytest.raises(ArchiveError, match=message):
        extract(archive, tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


def test_size_and_member_caps(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(repo_tarball())
    with pytest.raises(ArchiveError, match="expands to more than"):
        extract(archive, tmp_path / "out1", max_bytes=10)
    with pytest.raises(ArchiveError, match="more than 3 entries"):
        extract(archive, tmp_path / "out2", max_members=3)


def test_an_oversized_download_is_cut_off(tmp_path, monkeypatch):
    monkeypatch.setattr(_http, "urlopen", lambda request, timeout=30: _Response(b"x" * 5000))
    with pytest.raises(ArchiveError, match="larger than"):
        _github_archive.download("https://api.github.com/x", {}, tmp_path / "a", max_bytes=4000)


def test_a_corrupt_archive_is_an_archive_error(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(b"not a tarball")
    with pytest.raises(ArchiveError, match="cannot read archive"):
        extract(archive, tmp_path / "out")


@pytest.mark.parametrize(
    "failure",
    [urllib.error.HTTPError("u", 403, "rate limited", {}, None), urllib.error.HTTPError("u", 502, "bad gateway", {}, None)],
)
def test_archive_failure_falls_back_to_one_request_per_file(github, capsys, failure):
    fake = github(FakeGitHub(failure))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    assert scan_all(accessor) == expected_contents()
    assert len(fake.urls("raw.githubusercontent.com")) == len(FILES)
    assert fake.urls("/git/trees/") == ["https://api.github.com/repos/pallets/flask/git/trees/main?recursive=1"]
    err = capsys.readouterr().err
    assert f"could not download pallets/flask as one archive (HTTP {failure.code})" in err
    assert "one request at a time" in err
    accessor.cleanup()


def test_an_unsafe_archive_falls_back_too(github, capsys):
    fake = github(FakeGitHub(make_tarball([(TOP, "dir", None), (f"{TOP}/../x", "file", b"x")])))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    assert scan_all(accessor) == expected_contents()
    assert "path traversal" in capsys.readouterr().err
    assert len(fake.urls("raw.githubusercontent.com")) == len(FILES)


def test_a_missing_repository_reports_the_tree_error_without_a_note(github, capsys):
    github(FakeGitHub(urllib.error.HTTPError("u", 404, "Not Found", {}, None), tree_paths=[]))
    accessor = GitHubMCPAccessor("pallets", "nope", github_token="t")
    accessor._get_json = lambda url: (_ for _ in ()).throw(urllib.error.HTTPError(url, 404, "Not Found", {}, None))
    with pytest.raises(RuntimeError, match="HTTP 404"):
        accessor.list_files()
    assert "Note:" not in capsys.readouterr().err


def test_a_file_missing_from_the_archive_is_read_with_its_own_request(github):
    # export-ignore in .gitattributes leaves files out of the archive; the tree still lists them.
    fake = github(FakeGitHub(repo_tarball(), tree_paths=[*FILES, "ignored.txt"], raw={"ignored.txt": b"kept"}))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    assert scan_all(accessor)["ignored.txt"] == "kept"
    assert fake.urls("raw.githubusercontent.com") == [f"https://raw.githubusercontent.com/pallets/flask/{SHA}/ignored.txt"]
    accessor.cleanup()


def test_the_token_goes_to_the_api_and_is_not_forwarded_on_redirect(github):
    fake = github(FakeGitHub(repo_tarball()))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="ghp_secret")
    accessor.list_files()
    (request,) = [r for r in fake.requests if "/tarball/" in r.full_url]
    assert request.get_header("Authorization") == "Bearer ghp_secret"
    assert "Authorization" in request.unredirected_hdrs and "Authorization" not in request.headers
    accessor.cleanup()


def test_no_authorization_header_without_a_token(github, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    fake = github(FakeGitHub(repo_tarball()))
    accessor = GitHubMCPAccessor("pallets", "flask")
    accessor.list_files()
    assert all(r.get_header("Authorization") is None for r in fake.requests)
    accessor.cleanup()


def _temp_dirs(accessor) -> Path:
    assert accessor._temp_dir is not None
    return accessor._temp_dir


def test_cleanup_removes_the_extracted_tree(github):
    github(FakeGitHub(repo_tarball()))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    accessor.list_files()
    temp = _temp_dirs(accessor)
    assert (temp / "tree" / "README.md").is_file()
    assert not (temp / "repo.tar.gz").exists()  # the download is removed once extracted
    accessor.cleanup()
    assert not temp.exists()
    accessor.cleanup()  # idempotent


def test_the_temp_dir_is_removed_when_extraction_fails(github, monkeypatch):
    made: list[Path] = []
    real_mkdtemp = ra.tempfile.mkdtemp

    def recording_mkdtemp(*args, **kwargs):
        made.append(Path(real_mkdtemp(*args, **kwargs)))
        return str(made[-1])

    monkeypatch.setattr(ra.tempfile, "mkdtemp", recording_mkdtemp)
    github(FakeGitHub(b"garbage"))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    accessor.list_files()
    assert made and not made[0].exists()


def test_the_temp_dir_is_removed_on_interrupt(github, monkeypatch):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    github(FakeGitHub(repo_tarball()))
    monkeypatch.setattr(_github_archive, "extract", interrupted)
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    with pytest.raises(KeyboardInterrupt):
        accessor.list_files()
    assert accessor._temp_dir is None


def test_reads_after_cleanup_go_to_github(github):
    fake = github(FakeGitHub(repo_tarball()))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    accessor.list_files()
    accessor.cleanup()
    assert accessor.read_file("README.md") == "# flask\n"
    assert len(fake.urls("raw.githubusercontent.com")) == 1


def test_the_150_file_note_is_gone(github, capsys):
    many = {f"src/f{i}.py": b"x = 1\n" for i in range(200)}
    entries = [(TOP, "dir", None)] + [(f"{TOP}/{p}", "file", d) for p, d in many.items()]
    github(FakeGitHub(make_tarball(entries), tree_paths=list(many), raw=many))
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="t")
    assert len(accessor.list_files()) == 200
    assert "Note:" not in capsys.readouterr().err
    accessor.cleanup()


def test_the_checks_do_not_depend_on_tarfile_data_filter(tmp_path, monkeypatch):
    # Python 3.11.0-3.11.3 have no tarfile.data_filter; the manual checks must stand on their own.
    monkeypatch.delattr(tarfile, "data_filter", raising=False)
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(make_tarball([(TOP, "dir", None), (f"{TOP}/../evil.py", "file", b"x")]))
    with pytest.raises(ArchiveError, match="traversal"):
        extract(archive, tmp_path / "out")
    archive.write_bytes(repo_tarball())
    assert sorted(extract(archive, tmp_path / "ok").files) == sorted(FILES)


@pytest.mark.parametrize("path, ok", [
    ("src/app.py", True),
    ("src/CON", False), ("docs/nul.txt", False), ("lpt1.md", False), ("a/com9", False), ("a/CONOUT$", False),
    ("a/console.py", True), ("a/COM10", True),
    ("trail.", False), ("trail /x.py", False),
    ("a:b", False), ("a\\b", False),
])
def test_windows_names_that_map_elsewhere_are_read_with_their_own_request(path, ok):
    from quin_scanner._github_archive import _representable

    assert _representable(path, windows=True) is ok
    assert _representable("a/CON", windows=False) is True
