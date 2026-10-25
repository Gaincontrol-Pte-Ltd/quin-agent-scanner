from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from quin_scanner.endpoint_identifier import redact
from quin_scanner.models import SkillRecord
from quin_scanner.repo_accessor import RepoAccessor

MAX_FILE_CHARS = 1_000_000
MAX_FILES_PER_SKILL = 500
MAX_EVIDENCE_CHARS = 500

_KIND_BY_SUFFIX = {
    ".md": "markdown", ".markdown": "markdown",
    ".py": "code", ".js": "code", ".mjs": "code", ".cjs": "code", ".ts": "code",
    ".rb": "code", ".ps1": "code",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".json": "config", ".yaml": "config", ".yml": "config", ".toml": "config",
    ".cfg": "config", ".ini": "config",
    ".txt": "text",
}
_KIND_BY_NAME = {"makefile": "shell", "dockerfile": "shell"}

_SECRET_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b(\s*[=:]\s*)['\"]?[A-Za-z0-9_\-./+]{12,}['\"]?"
)
_KEY_PREFIX = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)


def file_kind(path: str) -> str | None:
    """Return 'markdown' | 'code' | 'shell' | 'config' | 'text', or None for non-text files."""
    p = PurePosixPath(path.replace("\\", "/"))
    by_name = _KIND_BY_NAME.get(p.name.lower())
    if by_name:
        return by_name
    return _KIND_BY_SUFFIX.get(p.suffix.lower())


def evidence(text: str) -> str:
    """Collapse whitespace, redact credentials, and cap length."""
    out = " ".join(text.split())
    out = redact(out)
    out = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}REDACTED", out)
    out = _KEY_PREFIX.sub("REDACTED", out)
    if len(out) > MAX_EVIDENCE_CHARS:
        out = out[:MAX_EVIDENCE_CHARS] + "…"
    return out


@dataclass
class SkillFile:
    path: str
    text: str


@dataclass
class SkillBundle:
    """A skill's record plus the text of its analyzable files. Read-only."""
    record: SkillRecord
    files: list[SkillFile]
    skipped: list[str] = field(default_factory=list)

    def of_kind(self, *kinds: str) -> list[SkillFile]:
        return [f for f in self.files if file_kind(f.path) in kinds]

    def get(self, name: str) -> SkillFile | None:
        for f in self.files:
            if PurePosixPath(f.path).name.lower() == name.lower():
                return f
        return None

    @classmethod
    def from_texts(
        cls,
        texts: dict[str, str],
        *,
        name: str = "demo",
        description: str = "",
        allowed_tools: list[str] | None = None,
        ecosystem: str = "generic",
    ) -> "SkillBundle":
        """Build an in-memory bundle (used by tests and analyzers' unit tests)."""
        skill_md = next((p for p in texts if PurePosixPath(p).name.lower() == "skill.md"), "")
        record = SkillRecord(
            id="test-skill",
            name=name,
            description=description,
            root_path=".",
            skill_md_path=skill_md,
            ecosystem=ecosystem,
            allowed_tools=list(allowed_tools or []),
            files=list(texts),
        )
        return cls(record=record, files=[SkillFile(p, t) for p, t in texts.items()])


def load_bundle(record: SkillRecord, accessor: RepoAccessor) -> SkillBundle:
    """Read a skill's text files, enforcing size and count caps. Never executes anything."""
    files: list[SkillFile] = []
    skipped: list[str] = []
    candidates = record.files[:MAX_FILES_PER_SKILL]
    if len(record.files) > MAX_FILES_PER_SKILL:
        skipped.append(f"{len(record.files) - MAX_FILES_PER_SKILL} files beyond cap")
    for path in candidates:
        if file_kind(path) is None:
            continue
        try:
            text = accessor.read_file(path)
        except Exception:
            skipped.append(f"{path}: unreadable")
            continue
        if len(text) > MAX_FILE_CHARS:
            skipped.append(f"{path}: too large")
            continue
        if "\x00" in text:
            skipped.append(f"{path}: binary")
            continue
        files.append(SkillFile(path, text))
    return SkillBundle(record=record, files=files, skipped=skipped)
