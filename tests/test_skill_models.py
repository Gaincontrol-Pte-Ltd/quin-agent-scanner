from quin_scanner.models import ScanReport, SkillAssessment, SkillFinding, SkillRecord


def _record() -> SkillRecord:
    return SkillRecord(
        id="abc123",
        name="demo",
        description="Demo skill",
        root_path="skills/demo",
        skill_md_path="skills/demo/SKILL.md",
        ecosystem="claude",
        allowed_tools=["Bash(git status:*)"],
        files=["skills/demo/SKILL.md"],
    )


def _finding() -> SkillFinding:
    return SkillFinding(
        rule_id="SK-PI-001",
        skill_id="abc123",
        severity="high",
        category="prompt_injection",
        title="Instruction-override phrasing",
        file_path="skills/demo/SKILL.md",
        line_number=7,
        evidence="ignore all previous instructions",
        threat_id="T001",
        confidence=0.75,
    )


def test_record_to_dict():
    d = _record().to_dict()
    assert d["id"] == "abc123"
    assert d["ecosystem"] == "claude"
    assert d["allowed_tools"] == ["Bash(git status:*)"]
    assert d["frontmatter_valid"] is True


def test_finding_defaults_and_to_dict():
    f = _finding()
    assert f.llm_verdict == "none"
    assert f.explanation == ""
    d = f.to_dict()
    assert d["rule_id"] == "SK-PI-001"
    assert d["threat_id"] == "T001"
    assert d["line_number"] == 7


def test_assessment_nests_record_and_findings():
    a = SkillAssessment(
        record=_record(),
        findings=[_finding()],
        risk_score=15,
        verdict="SAFE",
        finding_counts={"high": 1},
        top_rule_ids=["SK-PI-001"],
    )
    d = a.to_dict()
    assert d["record"]["name"] == "demo"
    assert d["findings"][0]["rule_id"] == "SK-PI-001"
    assert d["risk_score"] == 15
    assert d["verdict"] == "SAFE"
    assert d["finding_counts"] == {"high": 1}


def test_scan_report_serializes_skills_key():
    report = ScanReport(
        repo_path="r", scan_timestamp="t", is_ai_application=False, confidence=0.0
    )
    assert report.to_dict()["skills"] == []
    report.skills.append(
        SkillAssessment(record=_record(), findings=[], risk_score=0, verdict="SAFE")
    )
    assert report.to_dict()["skills"][0]["record"]["id"] == "abc123"
