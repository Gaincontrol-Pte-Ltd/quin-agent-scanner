from quin_scanner.cli import skill_summary_lines
from quin_scanner.models import ScanReport, SkillRecord
from quin_scanner.scanners.skills.scoring import build_assessment


def _a(name, findings=()):
    rec = SkillRecord(id=name, name=name, description="", root_path=".", skill_md_path="SKILL.md")
    return build_assessment(rec, list(findings))


def test_no_skills_no_lines():
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=False, confidence=0.0)
    assert skill_summary_lines(report) == []


def test_lines_sorted_by_score_with_header():
    from quin_scanner.models import SkillFinding

    bad = SkillFinding(rule_id="A", skill_id="x", severity="critical", category="c", title="t",
                       file_path="f", line_number=1, evidence="e", threat_id="T005", confidence=1.0)
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True, confidence=0.9,
                        skills=[_a("good"), _a("bad", [bad])])
    lines = skill_summary_lines(report)
    assert lines[0] == "Skills: 2 found"
    assert lines[1].strip().startswith("bad") and "CAUTION" in lines[1] and "40" in lines[1]
    assert lines[2].strip().startswith("good") and "SAFE" in lines[2]


def _mcp(findings=()):
    rec = SkillRecord(id="mcp", name="MCP tool definitions", description="", root_path=".",
                      skill_md_path="", ecosystem="mcp")
    return build_assessment(rec, list(findings))


def test_mcp_pseudo_skill_is_not_counted_as_a_skill():
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True, confidence=0.9,
                        skills=[_a("good"), _mcp()])
    lines = skill_summary_lines(report)
    assert lines[0] == "Skills: 1 found"
    assert not any(l.strip().startswith("MCP tool definitions") and "found" in l for l in lines)
    assert lines[-1] == "MCP tool definitions: SAFE 0"
    assert sum("good" in l for l in lines) == 1


def test_only_mcp_record_prints_just_the_mcp_line():
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True, confidence=0.9,
                        skills=[_mcp()])
    assert skill_summary_lines(report) == ["MCP tool definitions: SAFE 0"]
