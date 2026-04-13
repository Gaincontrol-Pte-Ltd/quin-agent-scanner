from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

# ── Network resilience & progress utilities ──────────────────────────────────

_MAX_RETRIES = 5
_BASE_DELAY = 2  # seconds — exponential backoff: 2, 4, 8, 16, 32

# HTTP status codes that should NOT be retried (permanent errors)
_PERMANENT_HTTP_CODES = frozenset({401, 403, 404, 422})


def _is_permanent_error(exc: Exception) -> bool:
    """Return True if the error is permanent and should not be retried."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _PERMANENT_HTTP_CODES
    return False


def _retry_with_backoff(
    fn: Callable,
    *,
    max_retries: int = _MAX_RETRIES,
    base_delay: float = _BASE_DELAY,
    on_retry: Callable[[int, int, float, str], None] | None = None,
) -> object:
    """Call *fn()* with exponential backoff on transient failures.

    Parameters
    ----------
    fn:
        Zero-argument callable to execute.
    max_retries:
        Total number of attempts (including the first).
    base_delay:
        Initial delay in seconds; doubled on each retry.
    on_retry:
        Optional callback ``(attempt, max_retries, delay, error_msg)``
        invoked before each wait.

    Returns the result of *fn()* on success, or raises the last exception.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            if _is_permanent_error(exc):
                raise
            last_exc = exc
            if attempt == max_retries:
                break
            delay = base_delay * (2 ** (attempt - 1))
            if on_retry:
                on_retry(attempt, max_retries, delay, str(exc))
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]


# ── Git clone progress parsing ───────────────────────────────────────────────

# Matches lines like:  Receiving objects:  45% (123/274)
_GIT_PROGRESS_RE = re.compile(
    r"(Counting objects|Compressing objects|Receiving objects|Resolving deltas)"
    r":\s+(\d+)%\s+\((\d+)/(\d+)\)"
)


def _parse_git_progress(line: str) -> tuple[str, int] | None:
    """Parse a git progress stderr line into (phase, percentage) or None."""
    m = _GIT_PROGRESS_RE.search(line)
    if m:
        return m.group(1), int(m.group(2))
    return None


def _render_clone_progress(label: str, phase: str, pct: int) -> None:
    """Render an in-place progress bar for git clone on stderr."""
    width = 25
    filled = int(pct / 100 * width)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    line = f"\r  {label}  [{bar}] {pct:3d}%  {phase}"
    sys.stderr.write(line)
    sys.stderr.flush()


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
        def _do() -> dict:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        return _retry_with_backoff(_do)

    def _get_text(self, url: str) -> str:
        def _do() -> str:
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        return _retry_with_backoff(_do)


class GitHubAPIAccessor(RepoAccessor):
    """Accessor for GitHub repos via REST API (clone to temp dir)."""

    def __init__(self, repo_url: str, github_token: str | None = None, branch: str = "main",
                 verbose: bool = True):
        self.repo_url = repo_url
        self.github_token = github_token
        self.branch = branch
        self.verbose = verbose
        self._temp_dir: Path | None = None
        self._local_accessor: LocalRepoAccessor | None = None

    def setup(self, verbose: bool = True) -> None:
        """Clone repo to temp directory with progress and retry."""
        import shutil
        import subprocess
        import tempfile

        if self.github_token:
            url = self.repo_url.replace("https://", f"https://{self.github_token}@")
        else:
            url = self.repo_url

        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        lfs_bypass = ["-c", "filter.lfs.smudge=cat", "-c", "filter.lfs.required=false"]

        def _has_files(d: Path) -> bool:
            return any(True for _ in d.iterdir()) if d.exists() else False

        def _clone_with_progress(branch_args: list[str]) -> Path:
            """Run git clone with --progress, stream stderr, return temp dir."""
            tmp = Path(tempfile.mkdtemp(prefix="quin_scanner_"))
            cmd = ["git", *lfs_bypass, "clone", "--depth", "1", "--progress",
                   *branch_args, url, str(tmp)]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
            # Read stderr byte-by-byte to handle \r-delimited progress lines
            buf = b""
            while True:
                ch = proc.stderr.read(1)  # type: ignore[union-attr]
                if not ch:
                    break
                if ch in (b"\r", b"\n"):
                    line = buf.decode("utf-8", errors="replace")
                    buf = b""
                    if verbose and line.strip():
                        parsed = _parse_git_progress(line)
                        if parsed:
                            phase, pct = parsed
                            _render_clone_progress("Cloning    ", phase, pct)
                else:
                    buf += ch
            proc.wait()
            if proc.returncode != 0 and not _has_files(tmp):
                shutil.rmtree(tmp, ignore_errors=True)
                raise subprocess.CalledProcessError(
                    proc.returncode, cmd, proc.stdout.read() if proc.stdout else b"",  # type: ignore[union-attr]
                    b"",
                )
            return tmp

        def _retry_msg(attempt: int, max_retries: int, delay: float, msg: str) -> None:
            if verbose:
                sys.stderr.write(
                    f"\n  Connection failed. Retrying ({attempt}/{max_retries})... "
                    f"waiting {int(delay)}s\n"
                )
                sys.stderr.flush()

        def _do_clone() -> Path:
            # Try explicit branch first; fall back to default branch
            try:
                return _clone_with_progress(["--branch", self.branch])
            except subprocess.CalledProcessError:
                return _clone_with_progress([])

        self._temp_dir = _retry_with_backoff(_do_clone, on_retry=_retry_msg)

        if verbose:
            # Finish the progress line
            _render_clone_progress("Cloning    ", "done", 100)
            sys.stderr.write("\n")
            sys.stderr.flush()

        self._local_accessor = LocalRepoAccessor(self._temp_dir)

    def cleanup(self) -> None:
        """Remove temp directory."""
        import shutil
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir)
            self._temp_dir = None

    def list_files(self, glob_pattern: str = "**/*") -> list[str]:
        if not self._local_accessor:
            self.setup(verbose=self.verbose)
        return self._local_accessor.list_files(glob_pattern)

    def read_file(self, path: str) -> str:
        if not self._local_accessor:
            self.setup(verbose=self.verbose)
        return self._local_accessor.read_file(path)

    def file_exists(self, path: str) -> bool:
        if not self._local_accessor:
            self.setup(verbose=self.verbose)
        return self._local_accessor.file_exists(path)

    def repo_identifier(self) -> str:
        return self.repo_url

    @property
    def root(self) -> Path:
        if not self._local_accessor:
            self.setup(verbose=self.verbose)
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
