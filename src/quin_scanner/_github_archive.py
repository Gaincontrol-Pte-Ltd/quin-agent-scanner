"""Download a GitHub repository as one tarball and extract it safely (issue #87).

The ``owner/repo`` shorthand used to read every file with its own request to raw.githubusercontent.com, so a scan took
time in proportion to the file count. ``GET /repos/{owner}/{repo}/tarball/{ref}`` returns the whole tree in one
response (it redirects to codeload.github.com), with the same access rules as the API: a token that can read the
repository through the API can download its archive.

The archive is untrusted input. Nothing in it is executed, and nothing is extracted through ``tarfile.extractall``:
each member is validated and its bytes are copied into a fresh directory by this module.

- Only regular files, directories and symlinks are accepted. Hard links, device files, FIFOs and anything else make
  the whole archive rejected (``git archive``, which GitHub uses, never writes them).
- A symlink is never created on disk. Its target text is written as an ordinary file, which is exactly what the API
  and raw.githubusercontent.com return for a symlink blob, so the scan sees the same content either way.
- A member name that is absolute, has a drive letter, contains ``..`` or NUL, or sits outside the single top-level
  ``owner-repo-sha/`` directory rejects the archive. Where available (Python 3.11.4+), ``tarfile.data_filter`` is
  applied as a second check.
- At most ``MAX_MEMBERS`` members and ``MAX_BYTES`` bytes (the download and the extracted total, each) are accepted.
- A file that cannot be written on this filesystem (a name Windows does not allow, or two paths that differ only in
  case on a case-insensitive disk) is left out of the extracted set; the caller reads it with its own request instead.
"""
from __future__ import annotations

import errno
import os
import re
import tarfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from quin_scanner import _http

MAX_MEMBERS = 200_000
MAX_BYTES = 1024 * 1024 * 1024  # 1 GiB, for the compressed download and for the extracted total
_CHUNK = 1024 * 1024
_TIMEOUT = 60
_SHA = re.compile(r"^[0-9a-f]{40}$")


class ArchiveError(ValueError):
    """The archive could not be used: unsafe, too large, or unreadable."""


@dataclass
class ExtractedArchive:
    commit_sha: str | None  # from the pax global header that git archive writes; None if absent
    files: dict[str, Path] = field(default_factory=dict)  # repo path (forward slashes) -> file on disk
    total_bytes: int = 0


def tarball_url(api_base: str, owner: str, repo: str, ref: str) -> str:
    return f"{api_base}/repos/{owner}/{repo}/tarball/{quote(ref, safe='/')}"


def download(url: str, headers: dict[str, str], dest: Path, *, max_bytes: int = MAX_BYTES) -> None:
    """Stream *url* into *dest*. ``Authorization`` is sent to the API only, not to the host it redirects to."""
    request = urllib.request.Request(url)
    for name, value in headers.items():
        if name.lower() == "authorization":
            # Not forwarded on redirect: codeload's redirect URL carries its own short-lived token for private repos.
            request.add_unredirected_header(name, value)
        else:
            request.add_header(name, value)
    written = 0
    with _http.urlopen(request, timeout=_TIMEOUT) as response, open(dest, "wb") as out:
        while chunk := response.read(_CHUNK):
            written += len(chunk)
            if written > max_bytes:
                raise ArchiveError(f"archive is larger than {max_bytes // (1024 * 1024)} MB")
            out.write(chunk)


def _relative_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name:
        raise ArchiveError(f"invalid member name: {name!r}")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ArchiveError(f"absolute path in archive: {name!r}")
    parts = tuple(p for p in PurePosixPath(name).parts if p != ".")
    if ".." in parts:
        raise ArchiveError(f"path traversal in archive: {name!r}")
    return parts


def extract(archive: Path, dest: Path, *, max_members: int = MAX_MEMBERS, max_bytes: int = MAX_BYTES) -> ExtractedArchive:
    """Extract the gzipped tarball *archive* into the empty directory *dest*, without its top-level directory."""
    root = dest.resolve()
    result = ExtractedArchive(commit_sha=None)
    top: str | None = None
    members = 0
    data_filter = getattr(tarfile, "data_filter", None)
    try:
        with tarfile.open(archive, mode="r|gz") as tar:
            for member in tar:
                if top is None:  # the global pax header is read with the first member
                    comment = tar.pax_headers.get("comment", "")
                    result.commit_sha = comment if _SHA.match(comment) else None
                members += 1
                if members > max_members:
                    raise ArchiveError(f"archive has more than {max_members} entries")
                parts = _relative_parts(member.name)
                if not parts:
                    continue
                if top is None:
                    top = parts[0]
                elif parts[0] != top:
                    raise ArchiveError(f"archive has more than one top-level directory: {member.name!r}")
                rel = parts[1:]
                if member.isdir():
                    continue
                if not (member.isreg() or member.issym()):
                    raise ArchiveError(f"unsupported entry in archive (link or special file): {member.name!r}")
                if not rel:
                    raise ArchiveError(f"file at the top level of the archive: {member.name!r}")
                if member.isreg() and data_filter is not None:
                    try:
                        data_filter(member, str(root))
                    except tarfile.FilterError as exc:
                        raise ArchiveError(f"unsafe entry in archive: {exc}") from exc
                if member.issym():
                    content = member.linkname.encode("utf-8", "surrogateescape")
                    size = len(content)
                else:
                    content = None
                    size = member.size
                if result.total_bytes + size > max_bytes:
                    raise ArchiveError(f"archive expands to more than {max_bytes // (1024 * 1024)} MB")
                repo_path = "/".join(rel)
                target = root.joinpath(*rel)
                if not _representable(repo_path) or not target.resolve().is_relative_to(root):
                    continue  # not representable on this filesystem: the caller reads it with its own request
                written = _write(tar, member, target, content, max_bytes - result.total_bytes)
                if written is not None:
                    result.total_bytes += written
                    result.files[repo_path] = target
    except ArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:  # zlib.error is not raised: gzip wraps it as OSError
        raise ArchiveError(f"cannot read archive: {type(exc).__name__}: {exc}") from exc
    if top is None:
        raise ArchiveError("archive is empty")
    return result


_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"{d}{i}" for d in ("COM", "LPT") for i in range(1, 10)}
)


def _representable(repo_path: str, *, windows: bool | None = None) -> bool:
    """False for names this OS would map onto a different path or a device.

    Everywhere: a backslash. On Windows also ':' (streams) and the other forbidden characters, a part ending in a dot or
    space (Windows drops them, so ``a.`` would become ``a``), and device names such as ``CON`` or ``nul.txt``, which
    open the device instead of a file.
    """
    if "\\" in repo_path:
        return False
    if not (os.name == "nt" if windows is None else windows):
        return True
    if any(c in repo_path for c in ':*?"<>|'):
        return False
    for part in repo_path.split("/"):
        if part.endswith((".", " ")) or part.split(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICES:
            return False
    return True


def _write(tar: tarfile.TarFile, member: tarfile.TarInfo, target: Path, content: bytes | None, budget: int) -> int | None:
    """Write one member; return the bytes written, or None if this filesystem cannot hold it under that name."""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        out = open(target, "xb")  # never overwrite: a second path that maps to the same file is skipped
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise
        return None
    written = 0
    with out:
        if content is not None:
            out.write(content)
            return len(content)
        source = tar.extractfile(member)
        if source is None:
            return 0
        while chunk := source.read(_CHUNK):
            written += len(chunk)
            if written > budget:
                raise ArchiveError("archive expands to more than its declared size allows")
            out.write(chunk)
    return written
