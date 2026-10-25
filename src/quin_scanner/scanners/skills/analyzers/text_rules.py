from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import line_of, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle, file_kind

_RULES_PATH = Path(__file__).parents[3] / "rules" / "skill_rules.yaml"
_MAX_PER_RULE_PER_FILE = 5
_NEGATION = re.compile(
    r"(?i)\b(never|do not|don.?t|must not|should not|shouldn.?t|avoid|warn(?:s|ing)?"
    r"|prevent|detect|block|refuse)\b"
)


@dataclass(frozen=True)
class TextRule:
    id: str
    title: str
    severity: str
    category: str
    threat_id: str
    confidence: float
    pattern: re.Pattern[str]
    applies_to: frozenset[str]
    skip_in_fence: bool
    negatable: bool


@lru_cache(maxsize=1)
def load_rules() -> tuple[TextRule, ...]:
    data = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
    return tuple(
        TextRule(
            id=r["id"],
            title=r["title"],
            severity=r["severity"],
            category=r["category"],
            threat_id=r["threat_id"],
            confidence=float(r["confidence"]),
            pattern=re.compile(r["pattern"]),
            applies_to=frozenset(r["applies_to"]),
            skip_in_fence=bool(r.get("skip_in_fence", False)),
            negatable=bool(r.get("negatable", False)),
        )
        for r in data["rules"]
    )


def fenced_lines(text: str) -> set[int]:
    """1-based line numbers inside (and including) ``` / ~~~ fences."""
    inside = False
    out: set[int] = set()
    for n, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith(("```", "~~~")):
            out.add(n)
            inside = not inside
            continue
        if inside:
            out.add(n)
    return out


def is_negated(text: str, start: int) -> bool:
    """True when the same line, before *start*, contains a negation word."""
    line_start = text.rfind("\n", 0, start) + 1
    return bool(_NEGATION.search(text[line_start:start][-60:]))


def rule_matches(
    rule: TextRule, text: str, kind: str, fenced: set[int]
) -> Iterator[re.Match[str]]:
    if "any" not in rule.applies_to and kind not in rule.applies_to:
        return
    for m in rule.pattern.finditer(text):
        if rule.skip_in_fence and kind == "markdown" and line_of(text, m.start()) in fenced:
            continue
        if rule.negatable and is_negated(text, m.start()):
            continue
        yield m


def analyze_text(bundle: SkillBundle) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.files:
        kind = file_kind(f.path)
        if kind is None:
            continue
        fenced = fenced_lines(f.text) if kind == "markdown" else set()
        for rule in load_rules():
            count = 0
            seen_lines: set[int] = set()
            for m in rule_matches(rule, f.text, kind, fenced):
                line_no = line_of(f.text, m.start())
                if line_no in seen_lines:   # one finding per rule per line
                    continue
                seen_lines.add(line_no)
                findings.append(
                    make_finding(
                        bundle,
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        title=rule.title,
                        file_path=f.path,
                        line_number=line_no,
                        evidence_text=m.group(0),
                        threat_id=rule.threat_id,
                        confidence=rule.confidence,
                    )
                )
                count += 1
                if count >= _MAX_PER_RULE_PER_FILE:
                    break
    return findings
