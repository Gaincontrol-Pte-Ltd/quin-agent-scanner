"""The regulatory crosswalk in the JSON/YAML report, SARIF and HTML."""
from __future__ import annotations

import json

from quin_scanner.models import AgentProfile, RiskIndicator, ScanReport, Vulnerability
from quin_scanner.report import ReportGenerator


def _report(**fields) -> ScanReport:
    base = dict(repo_path="/x/demo", scan_timestamp="2026-11-03T00:00:00+00:00", is_ai_application=True, confidence=0.9)
    base.update(fields)
    return ScanReport(**base)


def _signal(threat="T006", controls=("C003: Access Control & Least Privilege",), signal="Agent can run shell"):
    return RiskIndicator(signal=signal, threat_id=threat, recommended_controls=list(controls), severity="high")


def _agent(*signals):
    return AgentProfile(name="a", agent_type="worker", goal="", id="agent:a", risk_signals=list(signals))


class TestJson:
    def test_controls_catalog_from_repo_and_agent_signals(self):
        report = _report(risk_signals=[_signal()],
                         agents=[_agent(_signal("T012", ["C007: Monitoring, Logging & Observability"]))])
        controls = json.loads(ReportGenerator.to_json(report))["controls"]
        assert list(controls) == ["C003", "C007"]
        assert controls["C007"]["name"] == "Monitoring, Logging & Observability"
        assert {"framework": "eu-ai-act", "id": "Art. 12", "title": "Record-keeping",
                "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"} in controls["C007"]["regulatory_refs"]

    def test_no_signals_gives_empty_catalog(self):
        assert json.loads(ReportGenerator.to_json(_report()))["controls"] == {}

    def test_string_agent_signals_are_ignored(self):
        report = _report(agents=[_agent("legacy free-text signal")])
        assert json.loads(ReportGenerator.to_json(report))["controls"] == {}

    def test_yaml_has_controls(self):
        assert "controls:" in ReportGenerator.to_yaml(_report(risk_signals=[_signal()]))
