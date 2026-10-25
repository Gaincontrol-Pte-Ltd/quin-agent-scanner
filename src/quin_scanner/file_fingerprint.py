"""Content fingerprints of a repository's source files.

The Aegis SDK hashes the project modules a running agent has loaded, and the control plane compares them with
these hashes to find which repository an agent runs from (several shared files, one repository). No name or
setting has to be configured by the team, so the hash must be computed identically on both sides:

    sha256 of the file's text, decoded as UTF-8 (undecodable bytes replaced), with CRLF and CR turned into LF

and a file is only hashed when its stripped text is at least MIN_CHARS long, so empty ``__init__.py`` files and
other boilerplate that every project has do not make unrelated repositories look alike.

Keep ``normalized_digest`` in step with ``aegis_core/code_fingerprint.py`` in the SDK: both repositories test it
against the same known value.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import RepoAccessor

MIN_CHARS = 100
# 20000 files is about 3 MB of report and a few seconds; a large monorepo (about 3200 qualifying files) was cut by the earlier 3000
# and silently lost everything after the cut. If even this is exceeded the report says so (file_hash_stats.truncated).
MAX_FILES = 20000
# The SDK is Python today; the other extensions are hashed so a JavaScript or TypeScript SDK can match later.
FINGERPRINT_EXTENSIONS = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")

_TEST_PATH = re.compile(
    r"(^|[\\/])(test_|tests[\\/]|test[\\/]|__tests__[\\/]|fixtures[\\/]|conftest\.py$)|\.spec\.|_test\.|\.test\.",
    re.IGNORECASE,
)


def normalized_digest(text: str) -> str | None:
    """Hex SHA-256 of the normalized text, or None when the file is too small to tell projects apart."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(normalized.strip()) < MIN_CHARS:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def compute_file_fingerprint(accessor: RepoAccessor, file_index: FileIndex) -> tuple[list[dict[str, str]], dict[str, int | bool]]:
    """``(hashes, stats)``: ``hashes`` is ``[{"path", "sha256"}]`` for the repository's source files, test files excluded (an agent does
    not load them). ``stats`` says what was and was not covered: ``candidates`` source files considered, ``hashed`` of them, and
    ``truncated`` when MAX_FILES stopped the list before the end (files after the cut, in path order, are then missing, so an agent
    whose files live there cannot match). Files too small to hash are in ``candidates`` but not ``hashed``."""
    candidates = [
        path for path in sorted(file_index.all_files())
        if Path(path).suffix in FINGERPRINT_EXTENSIONS and not _TEST_PATH.search(path)
    ]
    out: list[dict[str, str]] = []
    truncated = False
    for position, path in enumerate(candidates):
        if len(out) >= MAX_FILES:
            truncated = True
            break
        try:
            digest = normalized_digest(accessor.read_file(path))
        except Exception:
            continue
        if digest:
            out.append({"path": path, "sha256": digest})
    return out, {"candidates": len(candidates), "hashed": len(out), "truncated": truncated}


def compute_file_hashes(accessor: RepoAccessor, file_index: FileIndex) -> list[dict[str, str]]:
    """Just the hashes of :func:`compute_file_fingerprint`."""
    return compute_file_fingerprint(accessor, file_index)[0]
