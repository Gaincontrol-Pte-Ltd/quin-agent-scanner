from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path


class RepoAccessor(ABC):
    """Unified interface for accessing repo contents."""

    @abstractmethod
    def list_files(self, glob_pattern: str = "**/*") -> list[str]:
        """Return relative file paths matching the glob pattern."""
        ...

    @abstractmethod
    def read_file(self, path: str) -> str:
        """Return the contents of the file at path (relative to repo root)."""
        ...

    @abstractmethod
    def file_exists(self, path: str) -> bool:
        """Return True if the file exists in the repo."""
        ...

    @abstractmethod
    def repo_identifier(self) -> str:
        """Return a string identifying this repo (e.g. absolute path or owner/repo)."""
        ...


class LocalRepoAccessor(RepoAccessor):
    """Reads files directly from the local filesystem."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path.resolve()

    def list_files(self, glob_pattern: str = "**/*") -> list[str]:
        return [
            str(p.relative_to(self.repo_path))
            for p in self.repo_path.glob(glob_pattern)
            if p.is_file()
        ]

    def read_file(self, path: str) -> str:
        return (self.repo_path / path).read_text(encoding="utf-8", errors="replace")

    def file_exists(self, path: str) -> bool:
        return (self.repo_path / path).is_file()

    def repo_identifier(self) -> str:
        return str(self.repo_path)

    @property
    def root(self) -> Path:
        return self.repo_path


class GitHubMCPAccessor(RepoAccessor):
    """Reads files from a public or private GitHub repository via the GitHub REST API.

    Authentication: set GITHUB_TOKEN environment variable to avoid rate limits and
    access private repositories. Without a token, unauthenticated requests are limited
    to 60/hour per IP.
    """

    _API_BASE = "https://api.github.com"
    _RAW_BASE = "https://raw.githubusercontent.com"

    def __init__(self, owner: str, repo: str, branch: str = "main") -> None:
        self.owner = owner
        self.repo = repo
        self.branch = branch
        self._token: str | None = os.environ.get("GITHUB_TOKEN")
        # Lazily populated on first list_files() call
        self._file_list: list[str] | None = None

    # ------------------------------------------------------------------
    # RepoAccessor interface
    # ------------------------------------------------------------------

    def list_files(self, glob_pattern: str = "**/*") -> list[str]:
        if self._file_list is None:
            self._file_list = self._fetch_tree()
        return list(self._file_list)

    def read_file(self, path: str) -> str:
        url = f"{self._RAW_BASE}/{self.owner}/{self.repo}/{self.branch}/{path}"
        try:
            return self._get_text(url)
        except urllib.error.HTTPError as exc:
            raise FileNotFoundError(
                f"GitHub: {self.owner}/{self.repo}/{path} → HTTP {exc.code}"
            ) from exc

    def file_exists(self, path: str) -> bool:
        if self._file_list is not None:
            return path in self._file_list
        # Avoid fetching the full tree just for a single exists() check
        url = f"{self._RAW_BASE}/{self.owner}/{self.repo}/{self.branch}/{path}"
        try:
            self._get_text(url)
            return True
        except (urllib.error.HTTPError, urllib.error.URLError):
            return False

    def repo_identifier(self) -> str:
        return f"{self.owner}/{self.repo}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_tree(self) -> list[str]:
        """Return all blob paths in the repo using the Git Trees API (recursive)."""
        url = (
            f"{self._API_BASE}/repos/{self.owner}/{self.repo}"
            f"/git/trees/{self.branch}?recursive=1"
        )
        try:
            data = self._get_json(url)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"GitHub API error fetching tree for {self.owner}/{self.repo}@{self.branch}: "
                f"HTTP {exc.code}. "
                "Set GITHUB_TOKEN env var to avoid rate limits or access private repos."
            ) from exc
        if data.get("truncated"):
            # Very large repos (>100k files) may be truncated — warn but continue
            import warnings
            warnings.warn(
                f"{self.owner}/{self.repo}: git tree was truncated by GitHub API; "
                "some files may be missed.",
                RuntimeWarning,
                stacklevel=3,
            )
        return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _get_json(self, url: str) -> dict:
        req = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _get_text(self, url: str) -> str:
        req = urllib.request.Request(url, headers=self._headers())
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")


class GitHubAPIAccessor(RepoAccessor):
    """Accessor for GitHub repos via REST API (clone to temp dir)."""

    def __init__(self, repo_url: str, github_token: str | None = None, branch: str = "main"):
        self.repo_url = repo_url
        self.github_token = github_token
        self.branch = branch
        self._temp_dir: Path | None = None
        self._local_accessor: LocalRepoAccessor | None = None

    def setup(self) -> None:
        """Clone repo to temp directory."""
        import tempfile
        import subprocess
        self._temp_dir = Path(tempfile.mkdtemp(prefix="quin_scanner_"))
        if self.github_token:
            # Embed token in URL for auth
            url = self.repo_url.replace("https://", f"https://{self.github_token}@")
        else:
            url = self.repo_url
        # Skip LFS file downloads — avoids failures when git-lfs is not installed
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        lfs_bypass = ["-c", "filter.lfs.smudge=cat", "-c", "filter.lfs.required=false"]

        def _has_files(d: Path) -> bool:
            return any(True for _ in d.iterdir()) if d.exists() else False

        # Try with explicit branch first; fall back to default branch if it fails
        result = subprocess.run(
            ["git", *lfs_bypass, "clone", "--depth", "1", "--branch", self.branch, url, str(self._temp_dir)],
            capture_output=True, env=env
        )
        if result.returncode != 0 and not _has_files(self._temp_dir):
            # Branch may not exist (e.g. repo uses master instead of main); clone default branch
            import shutil
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = Path(tempfile.mkdtemp(prefix="quin_scanner_"))
            result = subprocess.run(
                ["git", *lfs_bypass, "clone", "--depth", "1", url, str(self._temp_dir)],
                capture_output=True, env=env
            )
            if result.returncode != 0 and not _has_files(self._temp_dir):
                raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        self._local_accessor = LocalRepoAccessor(self._temp_dir)

    def cleanup(self) -> None:
        """Remove temp directory."""
        import shutil
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir)
            self._temp_dir = None

    def list_files(self, glob_pattern: str = "**/*") -> list[str]:
        if not self._local_accessor:
            self.setup()
        return self._local_accessor.list_files(glob_pattern)

    def read_file(self, path: str) -> str:
        if not self._local_accessor:
            self.setup()
        return self._local_accessor.read_file(path)

    def file_exists(self, path: str) -> bool:
        if not self._local_accessor:
            self.setup()
        return self._local_accessor.file_exists(path)

    def repo_identifier(self) -> str:
        return self.repo_url

    @property
    def root(self) -> Path:
        if not self._local_accessor:
            self.setup()
        return self._local_accessor.root


class RepoAccessorFactory:
    """Creates the appropriate RepoAccessor for a given target string."""

    @staticmethod
    def create(target: str, github_token: str | None = None, branch: str = "main") -> RepoAccessor:
        """
        Parse target and return the right accessor.

        - /absolute/path or ./relative/path → LocalRepoAccessor
        - https://github.com/owner/repo     → GitHubAPIAccessor
        - git@github.com:owner/repo         → GitHubAPIAccessor
        - owner/repo                        → GitHubMCPAccessor
        """
        # GitHub clone URL patterns
        if target.startswith("https://github.com/") or target.startswith("git@github.com:"):
            # Strip browser-style /tree/<branch> suffix (e.g. copied from GitHub UI)
            # and extract branch if embedded in URL
            import re
            tree_match = re.search(r"/tree/([^/]+)$", target)
            if tree_match:
                branch = tree_match.group(1)
                target = target[: tree_match.start()]
            return GitHubAPIAccessor(target, github_token=github_token, branch=branch)

        # Local path: starts with / or . or is an existing directory
        target_path = Path(target)
        if target.startswith("/") or target.startswith(".") or target_path.exists():
            return LocalRepoAccessor(target_path)

        # owner/repo shorthand (exactly one slash, no spaces)
        parts = target.split("/")
        if len(parts) == 2 and all(p and " " not in p for p in parts):
            return GitHubMCPAccessor(parts[0], parts[1], branch)

        raise ValueError(f"Cannot determine accessor type for target: {target!r}")
