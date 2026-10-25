# tests/test_skill_orchestrator.py
import json
from pathlib import Path

from quin_scanner.config import ScannerConfig, _ALL_SCANNERS
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.report import ReportGenerator
from quin_scanner.repo_accessor import LocalRepoAccessor

FIXTURES = Path(__file__).parent / "fixtures" / "skills_repo"


class StubProvider:
    """LLM stub: disputes everything it is asked about, answers other prompts with '{}'."""

    def __init__(self):
        self.skill_prompts = 0

    def generate(self, prompt):
        if "security reviewer for AI agent skills" in prompt:
            self.skill_prompts += 1
            n = prompt.count("rule=")
            return json.dumps([
                {"index": i, "verdict": "disputed", "explanation": "stub"} for i in range(n)
            ])
        return "{}"

    def analyze_prompt(self, system_prompt):  # pragma: no cover
        raise NotImplementedError


def _config(**kw):
    return ScannerConfig(enabled_scanners=["skills"], no_llm=True, vuln_check_enabled=False, **kw)


def test_skills_scanner_enabled_by_default():
    assert "skills" in _ALL_SCANNERS


def test_report_contains_skills_promoted_signals_and_coverage():
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), _config(), verbose=False)
    names = {a.record.name: a for a in report.skills}
    assert names["evil-formatter"].verdict == "HIGH_RISK"
    assert names["commit-helper"].verdict == "SAFE"
    assert report.coverage["skills_found"] == 3
    signals = [s.signal for s in report.risk_signals]
    assert any("[skill: evil-formatter]" in s for s in signals)
    assert not any("[skill: commit-helper]" in s for s in signals)
    # skills alone must not make the repo an "AI application"
    assert report.is_ai_application is False
    assert {a["scanner_name"] for a in report.inventory} == {"SkillScanner"}


def test_report_serialises_in_all_formats():
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), _config(), verbose=False)
    data = json.loads(ReportGenerator.to_json(report))
    assert {s["record"]["name"] for s in data["skills"]} == {
        "commit-helper", "evil-formatter", "injection-awareness",
    }
    assert "evil-formatter" in ReportGenerator.to_yaml(report)
    sarif = json.loads(ReportGenerator.to_sarif(report))
    assert any("evil-formatter" in r["message"]["text"] for r in sarif["runs"][0]["results"])


def test_artifact_types_label_skills():
    from quin_scanner.artifact_types import artifact_type

    assert artifact_type("skill", "agent-skills", "x") == "Skill"
    assert artifact_type("skill_risk", "skill-risk:SK-PI-001", "x") == "Skill"


def test_non_skill_repo_has_empty_skills_and_no_skill_coverage(tmp_path):
    (tmp_path / "app.py").write_text("print(1)")
    report = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), _config(), verbose=False)
    assert report.skills == []


def test_llm_review_runs_when_enabled_disputes_never_demote_protected_findings(monkeypatch):
    stub = StubProvider()
    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: stub)
    config = ScannerConfig(enabled_scanners=["skills"], no_llm=False, vuln_check_enabled=False)
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), config, verbose=False)
    assert stub.skill_prompts >= 1
    evil = next(a for a in report.skills if a.record.name == "evil-formatter")
    assert evil.findings and all(
        f.llm_verdict == "disputed" for f in evil.findings if f.severity in {"critical", "high", "medium"}
    )
    signals = [s.signal for s in report.risk_signals if "[skill: evil-formatter]" in s.signal]
    protected = [
        f for f in evil.findings
        if f.severity in {"critical", "high"}
        and (f.severity == "critical" or f.rule_id.startswith(("SK-CODE-", "SK-TAINT-")))
    ]
    assert len(signals) == len(protected)   # only protected findings survive a dispute


def test_no_llm_makes_no_provider_call(monkeypatch):
    def boom(self):
        raise AssertionError("provider must not be created with --no-llm")

    monkeypatch.setattr(ScannerConfig, "provider_factory", boom)
    ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), _config(), verbose=False)


def test_discovered_skills_appear_as_skill_tool_usages():
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), _config(), verbose=False)
    skills = {t.tool_name: t for t in report.tool_usages if t.tool_type == "skill"}
    assert {"commit-helper", "evil-formatter", "injection-awareness"} <= set(skills)
    for a in report.skills:
        if a.record.ecosystem != "mcp":
            t = skills[a.record.name]
            assert t.source_file == a.record.skill_md_path and t.line_number is None


def test_classify_leaves_skill_entries_alone():
    from quin_scanner.models import ToolUsage
    from quin_scanner.orchestrator import _classify_tool_usages

    class Srv:
        name = "commit-helper"

    t = ToolUsage(tool_name="commit-helper", tool_type="skill", source_file="x/foo.py")
    _classify_tool_usages([t], [Srv()])
    assert t.tool_type == "skill"


def test_skill_usage_does_not_invent_agent_links():
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURES), _config(), verbose=False)
    assert all(
        not {"commit-helper", "evil-formatter", "injection-awareness"} & set(a.skills)
        for a in report.agents
    )
