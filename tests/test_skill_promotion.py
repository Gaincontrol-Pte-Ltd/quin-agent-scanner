import json

from quin_scanner.models import ScanReport, SkillFinding, SkillRecord
from quin_scanner.report import ReportGenerator
from quin_scanner.scanners.skills.promotion import promote_skill_findings
from quin_scanner.scanners.skills.scoring import build_assessment


def _assessment(*findings):
    rec = SkillRecord(id="s", name="evil", description="", root_path="skills/evil",
                      skill_md_path="skills/evil/SKILL.md")
    return build_assessment(rec, list(findings))


def _f(rule="SK-PI-001", sev="high", cat="prompt_injection", verdict="none", line=7):
    return SkillFinding(rule_id=rule, skill_id="s", severity=sev, category=cat,
                        title="Instruction-override phrasing", file_path="skills/evil/SKILL.md",
                        line_number=line, evidence="e", threat_id="T001", confidence=0.8,
                        llm_verdict=verdict)


def test_only_high_and_critical_are_promoted():
    signals = promote_skill_findings(
        [_assessment(_f(sev="critical"), _f(rule="B", sev="high"), _f(rule="C", sev="medium"),
                     _f(rule="D", sev="low"))]
    )
    assert [s.severity for s in signals] == ["critical", "high"]


def test_disputed_findings_are_not_promoted():
    assert promote_skill_findings([_assessment(_f(verdict="disputed"))]) == []


def test_signal_shape():
    [s] = promote_skill_findings([_assessment(_f())])
    assert s.threat_id == "T001"
    assert "[skill: evil]" in s.signal and "SK-PI-001" in s.signal
    assert s.recommended_controls == ["C001: Input Validation & Filtering"]
    [ref] = s.evidence_refs
    assert (ref.file_path, ref.line_number, ref.scanner) == ("skills/evil/SKILL.md", 7, "SkillScanner")


def test_control_mapping_by_category_with_default():
    cats = {
        "supply_chain": "C004", "exfiltration": "C005", "dangerous_code": "C002",
        "permissions": "C003", "safety_bypass": "C006", "unknown_cat": "C008",
    }
    for cat, control in cats.items():
        [s] = promote_skill_findings([_assessment(_f(cat=cat))])
        assert s.recommended_controls[0].startswith(control)


def test_promoted_signals_flow_into_sarif_with_location():
    signals = promote_skill_findings([_assessment(_f())])
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True,
                        confidence=0.9, risk_signals=signals)
    sarif = json.loads(ReportGenerator.to_sarif(report))
    results = sarif["runs"][0]["results"]
    [r] = [r for r in results if r["ruleId"] == "T001"]
    assert r["level"] == "error"
    assert "SK-PI-001" in r["message"]["text"]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "skills/evil/SKILL.md"
    assert loc["region"]["startLine"] == 7
