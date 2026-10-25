from quin_scanner.models import ScanReport, SkillFinding, SkillRecord
from quin_scanner.report import ReportGenerator
from quin_scanner.scanners.skills.scoring import build_assessment


def _report():
    rec = SkillRecord(id="s", name="evil</script><b>x", description="d",
                      root_path="skills/evil", skill_md_path="skills/evil/SKILL.md",
                      ecosystem="claude", allowed_tools=["Bash"])
    f = SkillFinding(rule_id="SK-PI-001", skill_id="s", severity="high",
                     category="prompt_injection", title="Instruction-override phrasing",
                     file_path="skills/evil/SKILL.md", line_number=7,
                     evidence="ignore all previous instructions", threat_id="T001",
                     confidence=0.8, llm_verdict="confirmed", explanation="real")
    return ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True,
                      confidence=0.9, skills=[build_assessment(rec, [f])])


def test_html_embeds_skills_data_and_escapes_script_close():
    html = ReportGenerator.to_html(_report())
    assert '"skills"' in html
    assert "SK-PI-001" in html
    # a raw "</script>" coming from skill data must never reach the page unescaped
    assert "evil</script>" not in html


def test_html_template_has_skill_card_renderer_and_styles():
    html = ReportGenerator.to_html(_report())
    assert "skill-card" in html
    assert "Skill Risk" in html
    assert "verdictClass" in html


def test_skills_payload_is_valid_json_inside_the_page():
    html = ReportGenerator.to_html(_report())
    # "<\/" is the escaped form of "</" used when embedding JSON in a <script> tag
    assert "evil<\\/script>" in html
