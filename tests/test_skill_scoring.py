# tests/test_skill_scoring.py
from quin_scanner.models import SkillFinding, SkillRecord
from quin_scanner.scanners.skills.scoring import build_assessment, rescore, score_findings


def _f(rule="SK-X-001", sev="high", conf=1.0, verdict="none") -> SkillFinding:
    return SkillFinding(
        rule_id=rule, skill_id="s", severity=sev, category="c", title="t",
        file_path="SKILL.md", line_number=1, evidence="e", threat_id="T001",
        confidence=conf, llm_verdict=verdict,
    )


def _record():
    return SkillRecord(id="s", name="demo", description="", root_path=".", skill_md_path="SKILL.md")


def test_no_findings_is_safe_zero():
    assert score_findings([]) == (0, "SAFE")


def test_single_high_is_caution():
    assert score_findings([_f(sev="high")]) == (20, "CAUTION")


def test_low_findings_stay_safe():
    assert score_findings([_f(sev="low", conf=0.6)])[1] == "SAFE"


def test_single_critical_forces_at_least_caution_even_when_low_confidence():
    score, verdict = score_findings([_f(sev="critical", conf=0.2)])
    assert score < 20 and verdict == "CAUTION"


def test_repeated_rule_has_diminishing_returns():
    one = score_findings([_f(sev="medium")])[0]
    three = score_findings([_f(sev="medium")] * 3)[0]
    assert one == 8
    assert one < three < 3 * one   # 8 + 4 + 2 = 14


def test_distinct_rules_add_up_and_cap_at_100():
    findings = [_f(rule=f"SK-X-{i:03d}", sev="critical") for i in range(5)]
    assert score_findings(findings) == (100, "HIGH_RISK")


def test_high_risk_threshold_is_above_50():
    findings = [_f(rule="A", sev="high"), _f(rule="B", sev="high"), _f(rule="C", sev="high")]
    assert score_findings(findings) == (60, "HIGH_RISK")
    assert score_findings(findings[:2]) == (40, "CAUTION")


def test_disputed_counts_half_and_confirmed_full():
    assert score_findings([_f(sev="high", verdict="disputed")])[0] == 10
    assert score_findings([_f(sev="high", verdict="confirmed")])[0] == 20


def test_disputed_critical_is_not_demoted():
    assert score_findings([_f(sev="critical", conf=0.1, verdict="disputed")])[1] == "CAUTION"
    assert score_findings([_f(sev="critical", conf=1.0, verdict="disputed")])[0] == 40


def test_disputed_ast_and_taint_findings_keep_full_weight():
    for rule in ("SK-CODE-001", "SK-TAINT-002"):
        assert score_findings([_f(rule=rule, sev="high", verdict="disputed")])[0] == 20
    assert score_findings([_f(rule="SK-PI-001", sev="high", verdict="disputed")])[0] == 10


def test_score_is_monotonic_when_adding_findings():
    base = [_f(rule="A", sev="medium")]
    assert score_findings(base + [_f(rule="B", sev="low")])[0] >= score_findings(base)[0]


def test_build_assessment_counts_and_top_rules():
    findings = [_f("A", "high"), _f("A", "high"), _f("B", "medium"), _f("C", "low")]
    a = build_assessment(_record(), findings)
    assert a.finding_counts == {"high": 2, "medium": 1, "low": 1}
    assert a.top_rule_ids[0] == "A"
    assert a.risk_score == score_findings(findings)[0]
    assert a.verdict == score_findings(findings)[1]


def test_rescore_updates_after_llm_verdicts():
    a = build_assessment(_record(), [_f("A", "high"), _f("B", "high"), _f("C", "high")])
    assert a.verdict == "HIGH_RISK"
    for f in a.findings:
        f.llm_verdict = "disputed"
    rescore(a)
    assert a.risk_score == 30 and a.verdict == "CAUTION"
