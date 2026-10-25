"""Tests for RepoAccessorFactory target routing and LocalRepoAccessor."""
from __future__ import annotations

import os

import pytest

from quin_scanner.repo_accessor import (
    GitCloneAccessor,
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
        assert isinstance(accessor, GitCloneAccessor)

    def test_github_git_url(self):
        accessor = RepoAccessorFactory.create("git@github.com:owner/repo")
        assert isinstance(accessor, GitCloneAccessor)

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
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.branch == "feature-branch"

    def test_github_url_with_tree_branch_and_folder(self):
        accessor = RepoAccessorFactory.create("https://github.com/owner/repo/tree/main/example/crewai/")
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.branch == "main"
        assert accessor.subpath == "example/crewai"
        assert accessor.repo_url == "https://github.com/owner/repo"
        assert accessor.repo_identifier() == "https://github.com/owner/repo"

    def test_github_url_without_folder_has_empty_subpath(self):
        assert RepoAccessorFactory.create("https://github.com/owner/repo/tree/dev").subpath == ""
        assert RepoAccessorFactory.create("https://github.com/owner/repo").subpath == ""

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError, match="Cannot determine accessor type"):
            RepoAccessorFactory.create("not a valid target at all")

    def test_github_api_accessor_passes_token(self):
        accessor = RepoAccessorFactory.create(
            "https://github.com/owner/repo",
            github_token="ghp_test",
        )
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.github_token == "ghp_test"

    def test_azure_devops_https_url(self):
        accessor = RepoAccessorFactory.create(
            "https://dev.azure.com/myorg/myproject/_git/myrepo"
        )
        assert isinstance(accessor, GitCloneAccessor)

    def test_azure_devops_visualstudio_url(self):
        accessor = RepoAccessorFactory.create(
            "https://myorg.visualstudio.com/myproject/_git/myrepo"
        )
        assert isinstance(accessor, GitCloneAccessor)

    def test_azure_devops_passes_token_and_askpass_username(self):
        accessor = RepoAccessorFactory.create(
            "https://dev.azure.com/myorg/myproject/_git/myrepo",
            azure_token="azpat_test123",
        )
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.github_token == "azpat_test123"
        assert accessor.askpass_username == "azpat_test123"

    def test_azure_devops_no_token_has_no_askpass_username_override(self):
        accessor = RepoAccessorFactory.create(
            "https://dev.azure.com/myorg/myproject/_git/myrepo"
        )
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.github_token is None

    def test_github_url_not_matched_as_azure_devops(self):
        accessor = RepoAccessorFactory.create("https://github.com/owner/repo")
        assert isinstance(accessor, GitCloneAccessor)
        assert accessor.askpass_username == "x-access-token"


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


class TestGitCloneAccessorFolder:
    @staticmethod
    def _repo(tmp_path):
        import subprocess
        repo = tmp_path / "origin"
        (repo / "example").mkdir(parents=True)
        (repo / "example" / "agent.py").write_text("x = 1\n")
        (repo / "other.py").write_text("y = 2\n")
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t", "PATH": os.environ["PATH"], "HOME": str(tmp_path)}
        for cmd in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "m"]):
            subprocess.run(["git", *cmd], cwd=repo, env=env, check=True)
        return repo

    def test_only_the_folder_is_scanned(self, tmp_path):
        acc = GitCloneAccessor(str(self._repo(tmp_path)), subpath="example", verbose=False)
        try:
            assert acc.list_files() == ["agent.py"]
            assert acc.root.name == "example"
        finally:
            acc.cleanup()

    def test_whole_repo_without_folder(self, tmp_path):
        acc = GitCloneAccessor(str(self._repo(tmp_path)), verbose=False)
        try:
            assert sorted(f for f in acc.list_files() if not f.startswith(".git")) == ["example/agent.py", "other.py"]
        finally:
            acc.cleanup()

    @pytest.mark.parametrize("sub", ["missing", "..", "../escape", "other.py"])
    def test_bad_folder_is_an_error(self, tmp_path, sub):
        acc = GitCloneAccessor(str(self._repo(tmp_path)), subpath=sub, verbose=False)
        try:
            with pytest.raises(ValueError, match="not found"):
                acc.list_files()
        finally:
            acc.cleanup()
