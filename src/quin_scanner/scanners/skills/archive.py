"""Safe extraction of skill .zip archives for a pre-install scan. Nothing is ever executed."""
from __future__ import annotations

import stat
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 5000
MAX_TOTAL_BYTES = 200 * 1024 * 1024
_CHUNK = 64 * 1024


class ArchiveError(ValueError):
    """The archive is unreadable or unsafe to extract."""


def _member_path(info: zipfile.ZipInfo) -> PurePosixPath:
    """Validate a member name and return it as a relative path; raise ArchiveError if unsafe."""
    name = info.filename.replace("\\", "/")
    if not name or "\x00" in name:
        raise ArchiveError(f"invalid member name: {info.filename!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or (len(name) > 1 and name[1] == ":"):
        raise ArchiveError(f"absolute path in archive: {info.filename!r}")
    if ".." in path.parts:
        raise ArchiveError(f"path traversal in archive: {info.filename!r}")
    mode = (info.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK:
        raise ArchiveError(f"symlink in archive: {info.filename!r}")
    if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ArchiveError(f"special file in archive: {info.filename!r}")
    return path


def extract_zip(zip_path: str | Path, dest: Path) -> None:
    """Extract *zip_path* into *dest* after validating every member.

    All members are checked (count, total size, absolute paths, ``..``, symlinks) before
    anything is written; sizes are enforced again while streaming.
    """
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ArchiveError(f"too many members in archive: {len(infos)} > {MAX_MEMBERS}")
            if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
                raise ArchiveError(f"archive uncompressed size exceeds {MAX_TOTAL_BYTES} bytes")
            planned = [(info, _member_path(info)) for info in infos]

            root = dest.resolve()
            written = 0
            for info, rel in planned:
                target = root.joinpath(*rel.parts)
                if root != target and root not in target.parents:
                    raise ArchiveError(f"path escapes extraction directory: {info.filename!r}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "xb") as out:
                    while chunk := src.read(_CHUNK):
                        written += len(chunk)
                        if written > MAX_TOTAL_BYTES:
                            raise ArchiveError(f"archive uncompressed size exceeds {MAX_TOTAL_BYTES} bytes")
                        out.write(chunk)
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError, EOFError) as exc:
        raise ArchiveError(f"cannot read archive {Path(zip_path).name}: {type(exc).__name__}: {exc}") from exc


@contextmanager
def extracted_zip(zip_path: str | Path) -> Iterator[Path]:
    """Extract *zip_path* into a fresh temp directory, yield it, and always remove it afterwards."""
    if not Path(zip_path).is_file():
        raise ArchiveError(f"zip file not found: {zip_path}")
    with tempfile.TemporaryDirectory(prefix="quin-skill-") as tmp:
        root = Path(tmp)
        extract_zip(zip_path, root)
        yield root
