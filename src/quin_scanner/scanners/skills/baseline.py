"""Skills baseline: accept current findings so later scans report only new ones.

A baseline file is YAML::

    version: 1
    generated: "2026-10-25T09:00:00+00:00"
    entries:
      - fingerprint: <sha256 hex>
        rule_id: SK-PI-001
        skill: evil-formatter
        file_path: .claude/skills/evil-formatter/SKILL.md
        note: ""            # free text for reviewers; ignored by the scanner

Only ``fingerprint`` is used for matching. The fingerprint is line-number independent and
never stores raw evidence, so the file is safe to commit and review.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from quin_scanner.models import SkillAssessment, SkillFinding
from quin_scanner.scanners.skills.scoring import rescore

BASELINE_VERSION = 1


class BaselineError(ValueError):
    """A baseline file is missing or malformed."""


@dataclass
class Baseline:
    fingerprints: set[str] = field(default_factory=set)
    entries: list[dict[str, Any]] = field(default_factory=list)
    path: str = ""


@dataclass
class BaselineResult:
    suppressed_count: int = 0
    stale_count: int = 0


def fingerprint(finding: SkillFinding, skill_name: str) -> str:
    """sha256 of ``rule_id | skill name | file_path | evidence`` (whitespace collapsed, case kept)."""
    evidence = " ".join(finding.evidence.split())
    raw = "|".join((finding.rule_id, skill_name, finding.file_path, evidence))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_baseline(path: str | Path, assessments: list[SkillAssessment]) -> int:
    """Write every current finding as a baseline entry; returns the number of entries written.

    Findings sharing a fingerprint (same rule, skill, file and evidence) produce one entry.
    """
    entries: dict[str, dict[str, Any]] = {}
    for a in assessments:
        for f in a.findings:
            fp = fingerprint(f, a.record.name)
            entries.setdefault(fp, {
                "fingerprint": fp,
                "rule_id": f.rule_id,
                "skill": a.record.name,
                "file_path": f.file_path,
                "note": "",
            })
    ordered = sorted(entries.values(), key=lambda e: (e["skill"], e["file_path"], e["rule_id"], e["fingerprint"]))
    doc = {
        "version": BASELINE_VERSION,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": ordered,
    }
    Path(path).write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return len(ordered)


def load_baseline(path: str | Path) -> Baseline:
    """Read and validate a baseline file. Raises BaselineError with a readable message."""
    p = Path(path)
    if not p.is_file():
        raise BaselineError(f"baseline file not found: {path}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineError(f"cannot read baseline file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise BaselineError(f"baseline file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"baseline file {path} must be a YAML mapping with 'version' and 'entries'")
    if data.get("version") != BASELINE_VERSION:
        raise BaselineError(
            f"baseline file {path}: unsupported version {data.get('version')!r} (expected {BASELINE_VERSION})"
        )
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise BaselineError(f"baseline file {path}: 'entries' must be a list")
    fingerprints: set[str] = set()
    for i, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline file {path}: entry {i} must be a mapping")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or not fp.strip():
            raise BaselineError(f"baseline file {path}: entry {i} needs a string 'fingerprint'")
        fingerprints.add(fp.strip())
    return Baseline(fingerprints=fingerprints, entries=entries, path=str(path))


def apply_baseline(assessments: list[SkillAssessment], baseline: Baseline) -> BaselineResult:
    """Remove baselined findings in place and rescore each assessment.

    ``stale_count`` is the number of distinct baseline fingerprints that matched nothing.
    """
    matched: set[str] = set()
    suppressed = 0
    for a in assessments:
        kept: list[SkillFinding] = []
        for f in a.findings:
            fp = fingerprint(f, a.record.name)
            if fp in baseline.fingerprints:
                matched.add(fp)
                suppressed += 1
            else:
                kept.append(f)
        if len(kept) != len(a.findings):
            a.findings = kept
            rescore(a)
    return BaselineResult(suppressed_count=suppressed, stale_count=len(baseline.fingerprints - matched))


def baseline_metadata(path: str | Path, result: BaselineResult) -> dict[str, Any]:
    """The ``metadata['skills_baseline']`` record (file basename only, never the full path)."""
    return {
        "file": Path(path).name,
        "suppressed_count": result.suppressed_count,
        "stale_count": result.stale_count,
    }


def baseline_summary(meta: dict[str, Any]) -> str:
    """One-line human summary of a ``skills_baseline`` metadata record."""
    s, m = meta.get("suppressed_count", 0), meta.get("stale_count", 0)
    return f"Baseline: {s} finding(s) suppressed, {m} stale {'entry' if m == 1 else 'entries'}"
