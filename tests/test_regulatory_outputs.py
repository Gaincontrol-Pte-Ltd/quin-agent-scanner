"""The regulatory crosswalk in the JSON/YAML report, SARIF and HTML."""
from __future__ import annotations

import json

import yaml

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
        data = yaml.safe_load(ReportGenerator.to_yaml(_report(risk_signals=[_signal()])))
        assert list(data["controls"]) == ["C003"]


def _sarif(report):
    return json.loads(ReportGenerator.to_sarif(report))["runs"][0]["tool"]["driver"]["rules"]


class TestSarif:
    def test_threat_rule_uses_the_threats_controls(self):
        from quin_scanner.regulatory import refs_for_control, sarif_tag
        from quin_scanner.risk_taxonomy import load_taxonomy

        rule = next(r for r in _sarif(_report(risk_signals=[_signal("T006")])) if r["id"] == "T006")
        threat = next(t for t in load_taxonomy().threats if t.id == "T006")
        expected = sorted({sarif_tag(ref) for cid in threat.recommended_controls for ref in refs_for_control(cid)})
        assert rule["properties"]["tags"] == expected
        assert rule["help"]["text"].startswith("Relevant to (informative): EU AI Act ")
        assert "ISO/IEC 42001 " in rule["help"]["text"] and "NIST AI RMF " in rule["help"]["text"]

    def test_signal_without_threat_uses_its_own_controls(self):
        signal = _signal(threat=None, controls=["C006: Human Oversight & Approval Gates"], signal="No approval gate")
        rule = _sarif(_report(risk_signals=[signal]))[0]
        assert rule["properties"]["tags"] == ["eu-ai-act/art-14", "eu-ai-act/art-26", "iso-42001/a.9.2",
                                              "nist-ai-rmf/manage-2.4", "nist-ai-rmf/map-3.5"]
        assert rule["help"]["text"] == (
            "Relevant to (informative): EU AI Act Art. 14, Art. 26; ISO/IEC 42001 A.9.2; NIST AI RMF MAP 3.5, MANAGE 2.4."
        )

    def test_vulnerability_rule_gets_supply_chain_tags(self):
        vuln = Vulnerability(cve_id="CVE-2024-1", severity="high", cvss_score=7.5, published=None,
                             summary="x", source="osv", source_url=None)
        rule = next(r for r in _sarif(_report(framework="CrewAI 0.80.0", vulnerabilities=[vuln])) if r["id"] == "CVE-2024-1")
        assert "iso-42001/a.10.3" in rule["properties"]["tags"]
        assert "nist-ai-rmf/govern-6.1" in rule["properties"]["tags"]

    def test_rule_without_mapped_controls_has_no_tags(self):
        signal = _signal(threat=None, controls=["Rotate the key"], signal="Free text")
        rule = _sarif(_report(risk_signals=[signal]))[0]
        assert "properties" not in rule and "help" not in rule

    def test_shared_rule_id_combines_controls_of_all_indicators(self):
        from quin_scanner.regulatory import refs_for_control, sarif_tag

        a = _signal(threat=None, controls=["C001: Input Validation"], signal="Hardcoded secret found in config file A")
        b = _signal(threat=None, controls=["C006: Human Oversight & Approval Gates"],
                    signal="Hardcoded secret found in config file B")
        rules = _sarif(_report(risk_signals=[a, b]))
        assert len(rules) == 1
        expected = {sarif_tag(r) for cid in ("C001", "C006") for r in refs_for_control(cid)}
        assert expected <= set(rules[0]["properties"]["tags"])
