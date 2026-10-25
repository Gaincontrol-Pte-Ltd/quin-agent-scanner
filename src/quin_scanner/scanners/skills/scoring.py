from __future__ import annotations

from collections import Counter, defaultdict

from quin_scanner.models import SkillAssessment, SkillFinding, SkillRecord

SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_CAUTION_AT = 20
_HIGH_RISK_ABOVE = 50


def is_protected(f: SkillFinding) -> bool:
    """Critical, AST (SK-CODE-*) and taint (SK-TAINT-*) findings can't be downgraded by the LLM."""
    return f.severity == "critical" or f.rule_id.startswith(("SK-CODE-", "SK-TAINT-"))


def _weight(f: SkillFinding) -> float:
    w = SEVERITY_WEIGHT.get(f.severity, 0) * f.confidence
    if f.llm_verdict == "disputed" and not is_protected(f):
        w *= 0.5
    return w


def _rule_contributions(findings: list[SkillFinding]) -> dict[str, float]:
    """Per-rule contribution: heaviest finding full weight, each repeat halves again."""
    by_rule: dict[str, list[SkillFinding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)
    return {
        rule: sum(w * (0.5 ** i) for i, w in enumerate(sorted((_weight(f) for f in fs), reverse=True)))
        for rule, fs in by_rule.items()
    }


def score_findings(findings: list[SkillFinding]) -> tuple[int, str]:
    total = min(100, round(sum(_rule_contributions(findings).values())))
    if total > _HIGH_RISK_ABOVE:
        verdict = "HIGH_RISK"
    elif total >= _CAUTION_AT:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"
    if verdict == "SAFE" and any(f.severity == "critical" for f in findings):
        verdict = "CAUTION"
    return total, verdict


def build_assessment(record: SkillRecord, findings: list[SkillFinding]) -> SkillAssessment:
    assessment = SkillAssessment(record=record, findings=list(findings))
    rescore(assessment)
    return assessment


def rescore(assessment: SkillAssessment) -> None:
    """Recompute score, verdict, counts and top rules (call again after LLM review)."""
    score, verdict = score_findings(assessment.findings)
    assessment.risk_score = score
    assessment.verdict = verdict
    counts = Counter(f.severity for f in assessment.findings)
    assessment.finding_counts = {s: counts[s] for s in _SEVERITY_ORDER if counts[s]}
    contributions = _rule_contributions(assessment.findings)
    assessment.top_rule_ids = [
        r for r, _ in sorted(contributions.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    ]
