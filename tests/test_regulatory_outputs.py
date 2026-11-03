"""The regulatory crosswalk in the JSON/YAML report, SARIF and HTML."""
from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest
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


FRAMEWORK_IDS = ["eu-ai-act", "iso-42001", "nist-ai-rmf"]


class TestSarif:
    def test_threat_rule_has_framework_tags_and_clause_help(self):
        rule = next(r for r in _sarif(_report(risk_signals=[_signal("T006")])) if r["id"] == "T006")
        assert rule["properties"]["tags"] == FRAMEWORK_IDS
        assert rule["help"]["text"].startswith("Relevant to (informative): EU AI Act ")
        assert "ISO/IEC 42001 " in rule["help"]["text"] and "NIST AI RMF " in rule["help"]["text"]

    def test_signal_without_threat_uses_its_own_controls(self):
        signal = _signal(threat=None, controls=["C006: Human Oversight & Approval Gates"], signal="No approval gate")
        rule = _sarif(_report(risk_signals=[signal]))[0]
        assert rule["properties"]["tags"] == FRAMEWORK_IDS
        assert rule["help"]["text"] == (
            "Relevant to (informative): EU AI Act Art. 14, Art. 26; ISO/IEC 42001 A.9.2; NIST AI RMF MAP 3.5, MANAGE 2.4."
        )

    def test_every_threat_and_vulnerability_rule_has_at_most_three_framework_tags(self):
        # GitHub code scanning rejects a rule with more than 20 tags and only uses 10.
        from quin_scanner.risk_taxonomy import load_taxonomy

        threats = load_taxonomy().threats
        signals = [_signal(t.id, list(t.recommended_controls), signal=f"signal {t.id}") for t in threats]
        vuln = Vulnerability(cve_id="CVE-2024-1", severity="high", cvss_score=7.5, published=None,
                             summary="x", source="osv", source_url=None)
        rules = _sarif(_report(framework="CrewAI 0.80.0", risk_signals=signals, vulnerabilities=[vuln]))
        by_id = {r["id"]: r for r in rules}
        assert {t.id for t in threats} <= set(by_id) and "CVE-2024-1" in by_id
        for rule in rules:
            tags = rule.get("properties", {}).get("tags", [])
            assert len(tags) <= 3 and set(tags) <= set(FRAMEWORK_IDS)
            assert tags == [f for f in FRAMEWORK_IDS if f in tags]

    def test_help_text_orders_clauses_by_catalogue_position(self):
        # T001's controls give first-seen order Art. 15, Art. 14, Art. 26, Art. 9.
        rule = next(r for r in _sarif(_report(risk_signals=[_signal("T001")])) if r["id"] == "T001")
        assert "EU AI Act Art. 9, Art. 14, Art. 15, Art. 26;" in rule["help"]["text"]

    def test_vulnerability_rule_gets_supply_chain_tags(self):
        vuln = Vulnerability(cve_id="CVE-2024-1", severity="high", cvss_score=7.5, published=None,
                             summary="x", source="osv", source_url=None)
        rule = next(r for r in _sarif(_report(framework="CrewAI 0.80.0", vulnerabilities=[vuln])) if r["id"] == "CVE-2024-1")
        assert rule["properties"]["tags"] == FRAMEWORK_IDS
        assert "ISO/IEC 42001 A.10.3" in rule["help"]["text"]

    def test_rule_without_mapped_controls_has_no_tags(self):
        signal = _signal(threat=None, controls=["Rotate the key"], signal="Free text")
        rule = _sarif(_report(risk_signals=[signal]))[0]
        assert "properties" not in rule and "help" not in rule

    def test_shared_rule_id_combines_controls_of_all_indicators(self):
        a = _signal(threat=None, controls=["C001: Input Validation"], signal="Hardcoded secret found in config file A")
        b = _signal(threat=None, controls=["C006: Human Oversight & Approval Gates"],
                    signal="Hardcoded secret found in config file B")
        rules = _sarif(_report(risk_signals=[a, b]))
        assert len(rules) == 1
        assert "Art. 14" in rules[0]["help"]["text"] and "Art. 15" in rules[0]["help"]["text"]


class TestHtml:
    def test_chips_code_and_data_are_present(self):
        html = ReportGenerator.to_html(_report(risk_signals=[_signal()]))
        assert "function regChips(" in html
        assert "controlLink(c)+chips" in html and "regChips(c)" in html
        assert "#regulatory-crosswalk" in html
        data = re.search(r"window\.__REPORT_DATA__ = (.*?);\n</script>", html, re.S).group(1)
        assert "C003" in json.loads(data)["controls"]

    def test_chip_styles_wrap_on_narrow_screens(self):
        html = ReportGenerator.to_html(_report())
        assert ".reg-chips{" in html and "flex-wrap:wrap" in html
        chip_css = re.search(r"\.reg-chip\{[^}]*\}", html).group(0)
        assert "white-space:normal" in chip_css and "overflow-wrap:anywhere" in chip_css and "max-width:100%" in chip_css
        assert "nowrap" not in chip_css

    def test_informative_note_is_rendered_once_per_signal_when_chips_exist(self):
        html = ReportGenerator.to_html(_report())
        note = "Regulatory references are informative, not a compliance assessment."
        assert html.count(note) == 1
        assert "if(anyChips)" in html

    def test_control_link_and_chips_accept_leading_whitespace_alike(self):
        html = ReportGenerator.to_html(_report())
        assert html.count(r"/^\s*(C\d{3})\b/i") == 2

    @pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
    def test_reg_chips_behaviour_in_node(self):
        html = ReportGenerator.to_html(_report())

        def grab(pattern):
            return re.search(pattern, html, re.S).group(0)

        src = "\n".join([
            grab(r'var DOCS_BASE = "[^"]*";'),
            grab(r"function esc\(s\)\{.*?\n  \}"),
            grab(r"var REG_SHORT=.*?;"),
            grab(r"function regChips\(label\)\{.*?\n  \}"),
        ])
        script = src + """
var D = {controls: {
  C003: {regulatory_refs: [
    {framework: "eu-ai-act", id: "Art. 14", title: "Human oversight"},
    {framework: "eu-ai-act", id: "Art. 26", title: "Deployer obligations"},
    {framework: "iso-42001", id: "A.9.2", title: "Responsible use"},
    {framework: "nist-ai-rmf", id: "MAP 3.5", title: "<img src=x onerror=1>"},
    {framework: "nist-ai-rmf", id: "MANAGE 2.4", title: "Mechanisms"}]}}};
process.stdout.write(JSON.stringify([regChips("C003: Access Control"), regChips("C999"), regChips("nope")]));
"""
        out = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout
        chips, unknown, nolabel = json.loads(out)
        assert "EU Art. 14, Art. 26" in chips
        assert "ISO A.9.2" in chips
        assert "NIST MAP 3.5, MANAGE 2.4" in chips
        assert 'title="Relevant to (informative) \u2014 Art. 14 \u2014 Human oversight\nArt. 26 \u2014 Deployer obligations"' in chips
        assert "<img" not in chips and "&lt;img src=x onerror=1&gt;" in chips
        assert unknown == "" and nolabel == ""


def test_controls_and_tags_do_not_depend_on_the_hash_seed():
    import os
    import sys
    from pathlib import Path

    import quin_scanner

    src = str(Path(quin_scanner.__file__).resolve().parent.parent)
    code = (
        "import json;"
        "from quin_scanner.models import RiskIndicator, ScanReport;"
        "from quin_scanner.report import ReportGenerator;"
        "r=ScanReport(repo_path='/x', scan_timestamp='2026-11-03T00:00:00+00:00', is_ai_application=True, confidence=1.0,"
        " risk_signals=[RiskIndicator(signal='s%d'%i, threat_id='T%03d'%i, recommended_controls=['C%03d'%i]) for i in range(1,15)]);"
        "print(json.dumps([json.loads(ReportGenerator.to_json(r))['controls'],"
        " json.loads(ReportGenerator.to_sarif(r))['runs'][0]['tool']['driver']['rules']]))"
    )
    outs = set()
    for seed in ("1", "2", "3"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": src}
        outs.add(subprocess.run([sys.executable, "-c", code], env=env, check=True, capture_output=True, text=True).stdout)
    assert len(outs) == 1
    assert '"C014"' in next(iter(outs))
