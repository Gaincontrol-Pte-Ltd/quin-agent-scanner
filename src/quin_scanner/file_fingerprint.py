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
MAX_FILES = 3000
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


def compute_file_hashes(accessor: RepoAccessor, file_index: FileIndex) -> list[dict[str, str]]:
    """``[{"path", "sha256"}]`` for the repository's source files, test files excluded (an agent does not load them)."""
    out: list[dict[str, str]] = []
    for path in sorted(file_index.all_files()):
        if Path(path).suffix not in FINGERPRINT_EXTENSIONS or _TEST_PATH.search(path):
            continue
        try:
            digest = normalized_digest(accessor.read_file(path))
        except Exception:
            continue
        if digest:
            out.append({"path": path, "sha256": digest})
        if len(out) >= MAX_FILES:
            break
    return out
