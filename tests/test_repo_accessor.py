"""Tests for RepoAccessorFactory target routing and LocalRepoAccessor."""
from __future__ import annotations


import pytest

from quin_scanner.repo_accessor import (
    GitHubAPIAccessor,
    GitHubMCPAccessor,
    LocalRepoAccessor,
    RepoAccessorFactory,
)


class TestRepoAccessorFactory:
    def test_local_absolute_path(self, tmp_path):
        accessor = RepoAccessorFactory.create(str(tmp_path))
        assert isinstance(accessor, LocalRepoAccessor)

    def test_local_relative_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "myrepo").mkdir()
        accessor = RepoAccessorFactory.create("./myrepo")
        assert isinstance(accessor, LocalRepoAccessor)

    def test_github_https_url(self):
        accessor = RepoAccessorFactory.create("https://github.com/owner/repo")
        assert isinstance(accessor, GitHubAPIAccessor)

    def test_github_git_url(self):
        accessor = RepoAccessorFactory.create("git@github.com:owner/repo")
        assert isinstance(accessor, GitHubAPIAccessor)

    def test_owner_repo_shorthand(self):
        accessor = RepoAccessorFactory.create("owner/repo")
        assert isinstance(accessor, GitHubMCPAccessor)

    def test_owner_repo_passes_token(self):
        accessor = RepoAccessorFactory.create("owner/repo", github_token="ghp_test123")
        assert isinstance(accessor, GitHubMCPAccessor)
        assert accessor._token == "ghp_test123"

    def test_github_url_with_tree_branch(self):
        accessor = RepoAccessorFactory.create(
            "https://github.com/owner/repo/tree/feature-branch"
        )
        assert isinstance(accessor, GitHubAPIAccessor)
        assert accessor.branch == "feature-branch"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError, match="Cannot determine accessor type"):
            RepoAccessorFactory.create("not a valid target at all")

    def test_github_api_accessor_passes_token(self):
        accessor = RepoAccessorFactory.create(
            "https://github.com/owner/repo",
            github_token="ghp_test",
        )
        assert isinstance(accessor, GitHubAPIAccessor)
        assert accessor.github_token == "ghp_test"


class TestLocalRepoAccessor:
    def test_list_files(self, tmp_path):
        (tmp_path / "a.py").write_text("print('hello')")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.py").write_text("print('world')")
        accessor = LocalRepoAccessor(tmp_path)
        files = accessor.list_files("**/*.py")
        assert len(files) == 2
        assert any("a.py" in f for f in files)
        assert any("b.py" in f for f in files)

    def test_read_file(self, tmp_path):
        (tmp_path / "test.txt").write_text("content here")
        accessor = LocalRepoAccessor(tmp_path)
        assert accessor.read_file("test.txt") == "content here"

    def test_file_exists(self, tmp_path):
        (tmp_path / "exists.txt").write_text("yes")
        accessor = LocalRepoAccessor(tmp_path)
        assert accessor.file_exists("exists.txt") is True
        assert accessor.file_exists("missing.txt") is False

    def test_repo_identifier(self, tmp_path):
        accessor = LocalRepoAccessor(tmp_path)
        assert accessor.repo_identifier() == str(tmp_path.resolve())


class TestGitHubMCPAccessorInit:
    def test_token_from_param(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        accessor = GitHubMCPAccessor("owner", "repo", github_token="ghp_param")
        assert accessor._token == "ghp_param"

    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
        accessor = GitHubMCPAccessor("owner", "repo")
        assert accessor._token == "ghp_env"

    def test_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env")
        accessor = GitHubMCPAccessor("owner", "repo", github_token="ghp_param")
        assert accessor._token == "ghp_param"

    def test_no_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        accessor = GitHubMCPAccessor("owner", "repo")
        assert accessor._token is None

    def test_repo_identifier(self):
        accessor = GitHubMCPAccessor("myorg", "myrepo")
        assert accessor.repo_identifier() == "myorg/myrepo"
