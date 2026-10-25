from __future__ import annotations

import ast

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.bundle import SkillBundle, evidence


def line_of(text: str, pos: int) -> int:
    """1-based line number of character offset *pos*."""
    return text.count("\n", 0, pos) + 1


def dotted(node: ast.AST) -> str | None:
    """Return 'a.b.c' for a Name/Attribute chain, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def call_last_name(call: ast.Call) -> str:
    """Last identifier of a call target, even when the base is itself a call."""
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def make_finding(
    bundle: SkillBundle,
    *,
    rule_id: str,
    severity: str,
    category: str,
    title: str,
    file_path: str,
    line_number: int | None,
    evidence_text: str,
    threat_id: str,
    confidence: float = 0.8,
) -> SkillFinding:
    return SkillFinding(
        rule_id=rule_id,
        skill_id=bundle.record.id,
        severity=severity,
        category=category,
        title=title,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence(evidence_text),
        threat_id=threat_id,
        confidence=confidence,
    )
