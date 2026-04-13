from __future__ import annotations

import fnmatch
from pathlib import Path

from quin_scanner.repo_accessor import RepoAccessor


_EXCLUDED_DIRS = frozenset({
    ".venv", "venv", "node_modules", "__pycache__", ".git",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".eggs", "*.egg-info",
})


def _is_vendor_path(path: str) -> bool:
    """Return True if path passes through a vendor/generated directory."""
    for part in path.replace("\\", "/").split("/"):
        if part in _EXCLUDED_DIRS or part.endswith(".egg-info"):
            return True
    return False


class FileIndex:
    """Index of all files in a repo, queryable by extension, directory, or glob."""

    def __init__(self, accessor: RepoAccessor) -> None:
        self._accessor = accessor
        self._files: list[str] = []

    def build(self) -> None:
        """Populate the index by listing all files via the accessor."""
        self._files = [
            f for f in self._accessor.list_files("**/*")
            if not _is_vendor_path(f)
        ]

    def all_files(self) -> list[str]:
        """Return every file path in the index."""
        return list(self._files)

    def files_by_extension(self, ext: str) -> list[str]:
        """Return files whose name ends with ext (e.g. '.py', '.yaml')."""
        if not ext.startswith("."):
            ext = f".{ext}"
        return [f for f in self._files if Path(f).suffix == ext]

    def files_in_dir(self, directory: str) -> list[str]:
        """Return files that are inside directory (prefix match on path segments)."""
        prefix = directory.rstrip("/") + "/"
        return [f for f in self._files if f.startswith(prefix) or f == directory]

    def files_matching(self, glob_pattern: str) -> list[str]:
        """Return files matching glob_pattern (e.g. '**/*.yaml').

        Supports ** as a zero-or-more directory wildcard.
        """
        return [f for f in self._files if self._glob_match(f, glob_pattern)]

    @staticmethod
    def _glob_match(path: str, pattern: str) -> bool:
        """Match path against a glob pattern with full ** support (anywhere in pattern)."""
        path_parts = path.replace("\\", "/").split("/")
        pat_parts = pattern.replace("\\", "/").split("/")
        return FileIndex._parts_match(path_parts, pat_parts)

    @staticmethod
    def _parts_match(path_parts: list[str], pat_parts: list[str]) -> bool:
        """Recursive segment-by-segment glob match supporting ** wildcards."""
        if not pat_parts:
            return not path_parts
        if not path_parts:
            # Only valid if all remaining pattern parts are **
            return all(p == "**" for p in pat_parts)
        if pat_parts[0] == "**":
            # ** matches zero or more path segments
            # Try consuming zero segments (skip the **)
            if FileIndex._parts_match(path_parts, pat_parts[1:]):
                return True
            # Try consuming one segment and keep ** for the rest
            return FileIndex._parts_match(path_parts[1:], pat_parts)
        if fnmatch.fnmatch(path_parts[0], pat_parts[0]):
            return FileIndex._parts_match(path_parts[1:], pat_parts[1:])
        return False
