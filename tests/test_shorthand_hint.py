"""The owner/repo shorthand points to the URL form once the repository is big enough to be slow (issue #87)."""
from __future__ import annotations

from quin_scanner.repo_accessor import _SLOW_SHORTHAND_FILES, GitHubMCPAccessor


def _accessor_with_files(monkeypatch, count: int) -> GitHubMCPAccessor:
    accessor = GitHubMCPAccessor("pallets", "flask", github_token="x")
    tree = {"tree": [{"path": f"src/f{i}.py", "type": "blob"} for i in range(count)]}
    monkeypatch.setattr(accessor, "_get_json", lambda url: tree)
    return accessor


def test_a_large_repository_gets_one_note_pointing_to_the_url_form(monkeypatch, capsys):
    accessor = _accessor_with_files(monkeypatch, _SLOW_SHORTHAND_FILES)

    files = accessor.list_files()
    accessor.list_files()  # the tree is cached: no second note

    err = capsys.readouterr().err
    assert len(files) == _SLOW_SHORTHAND_FILES
    assert err.count("Note:") == 1
    assert "https://github.com/pallets/flask" in err
    assert f"{_SLOW_SHORTHAND_FILES} files" in err


def test_a_small_repository_gets_no_note(monkeypatch, capsys):
    accessor = _accessor_with_files(monkeypatch, _SLOW_SHORTHAND_FILES - 1)

    accessor.list_files()

    assert capsys.readouterr().err == ""
