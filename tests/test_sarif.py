"""Tests for SARIF report generation."""
from __future__ import annotations

from quin_scanner.sarif import _severity_to_level, _slugify


class TestSeverityToLevel:
    def test_critical_maps_to_error(self):
        assert _severity_to_level("critical") == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_level("high") == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_level("medium") == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_level("low") == "note"

    def test_info_maps_to_note(self):
        assert _severity_to_level("info") == "note"


class TestSlugify:
    def test_slugifies_multiword_text(self):
        assert _slugify("Excessive Agent Permissions Detected Here Now") == "excessive-agent-permissions-detected-here-now"

    def test_truncates_to_six_words(self):
        assert _slugify("one two three four five six seven eight") == "one-two-three-four-five-six"

    def test_strips_punctuation(self):
        assert _slugify("Agent has, unrestricted (network) access!") == "agent-has-unrestricted-network-access"

    def test_empty_text_falls_back(self):
        assert _slugify("") == "risk-signal"

    def test_punctuation_only_falls_back(self):
        assert _slugify("!!!") == "risk-signal"


from quin_scanner.models import EvidenceRef, RiskIndicator
from quin_scanner.sarif import _location_from_evidence, _message_text, _rule_id


class TestRuleId:
    def test_uses_threat_id_when_present(self):
        indicator = RiskIndicator(signal="Some signal text", threat_id="T001")
        assert _rule_id(indicator) == "T001"

    def test_slugifies_signal_when_no_threat_id(self):
        indicator = RiskIndicator(signal="Excessive agent permissions detected")
        assert _rule_id(indicator) == "excessive-agent-permissions-detected"


class TestLocationFromEvidence:
    def test_returns_none_for_empty_file_path(self):
        ref = EvidenceRef(file_path="", line_number=None, scanner="", source_url="https://example.com/cve")
        assert _location_from_evidence(ref) is None

    def test_builds_location_with_line_number(self):
        ref = EvidenceRef(file_path="src/agent.py", line_number=42, scanner="AgentScanner")
        loc = _location_from_evidence(ref)
        assert loc == {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/agent.py"},
                "region": {"startLine": 42},
            }
        }

    def test_builds_location_without_line_number(self):
        ref = EvidenceRef(file_path="src/agent.py", line_number=None, scanner="AgentScanner")
        loc = _location_from_evidence(ref)
        assert loc == {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/agent.py"},
            }
        }


class TestMessageText:
    def test_plain_signal_no_agent_no_controls(self):
        indicator = RiskIndicator(signal="Plain signal")
        assert _message_text(indicator) == "Plain signal"

    def test_prefixes_agent_name(self):
        indicator = RiskIndicator(signal="Plain signal")
        assert _message_text(indicator, agent_name="Router") == "[agent: Router] Plain signal"

    def test_appends_recommended_controls(self):
        indicator = RiskIndicator(
            signal="Plain signal",
            recommended_controls=["C003: Access Control & Least Privilege"],
        )
        result = _message_text(indicator)
        assert result == "Plain signal\n\nRecommended: C003: Access Control & Least Privilege"

    def test_joins_multiple_controls_with_semicolon(self):
        indicator = RiskIndicator(
            signal="Plain signal",
            recommended_controls=["C001: Foo", "C002: Bar"],
        )
        result = _message_text(indicator)
        assert result == "Plain signal\n\nRecommended: C001: Foo; C002: Bar"


from quin_scanner.sarif import _result_from_indicator


class TestResultFromIndicator:
    def test_result_with_one_location(self):
        indicator = RiskIndicator(
            signal="Excessive tool access",
            severity="high",
            threat_id="T001",
            evidence_refs=[EvidenceRef(file_path="src/agent.py", line_number=10, scanner="AgentScanner")],
        )
        result = _result_from_indicator(indicator)
        assert result["ruleId"] == "T001"
        assert result["level"] == "error"
        assert result["message"]["text"] == "Excessive tool access"
        assert result["locations"] == [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/agent.py"},
                    "region": {"startLine": 10},
                }
            }
        ]

    def test_result_with_no_file_locations(self):
        indicator = RiskIndicator(
            signal="CVE-derived risk",
            severity="medium",
            evidence_refs=[EvidenceRef(file_path="", source_url="https://osv.dev/vuln/GHSA-xxxx")],
        )
        result = _result_from_indicator(indicator)
        assert result["locations"] == []

    def test_result_filters_mixed_locations(self):
        indicator = RiskIndicator(
            signal="Mixed evidence",
            severity="low",
            evidence_refs=[
                EvidenceRef(file_path="", source_url="https://example.com"),
                EvidenceRef(file_path="src/tool.py", line_number=5, scanner="ToolScanner"),
            ],
        )
        result = _result_from_indicator(indicator)
        assert len(result["locations"]) == 1
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/tool.py"

    def test_result_with_agent_name(self):
        indicator = RiskIndicator(signal="Agent-specific risk", severity="medium")
        result = _result_from_indicator(indicator, agent_name="Router")
        assert result["message"]["text"] == "[agent: Router] Agent-specific risk"


from quin_scanner.risk_taxonomy import ExternalRef, Threat
from quin_scanner.sarif import _rule_from_indicator


class TestRuleFromIndicator:
    def test_enriches_from_taxonomy_when_threat_found(self):
        indicator = RiskIndicator(signal="raw signal text", severity="critical", threat_id="T999")
        threat = Threat(
            id="T999",
            name="Excessive Agent Autonomy",
            category="autonomy",
            applies_to=["agentic_ai"],
            key_risk_indicators=[],
            recommended_controls=["C003"],
            description="Agents acting without oversight.",
            why_it_matters="Can cause unbounded damage.",
            external_refs=[ExternalRef(title="OWASP", url="https://owasp.org/t999")],
        )
        rule = _rule_from_indicator(indicator, {"T999": threat})
        assert rule["id"] == "T999"
        assert rule["shortDescription"]["text"] == "Excessive Agent Autonomy"
        assert rule["fullDescription"]["text"] == "Agents acting without oversight.\n\nCan cause unbounded damage."
        assert rule["helpUri"] == "https://owasp.org/t999"
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_omits_help_uri_when_no_external_refs(self):
        indicator = RiskIndicator(signal="raw signal text", severity="medium", threat_id="T998")
        threat = Threat(
            id="T998",
            name="Some Threat",
            category="x",
            applies_to=[],
            key_risk_indicators=[],
            recommended_controls=[],
            description="A description.",
        )
        rule = _rule_from_indicator(indicator, {"T998": threat})
        assert "helpUri" not in rule

    def test_falls_back_to_signal_text_when_no_threat_id(self):
        indicator = RiskIndicator(signal="raw signal text", severity="low")
        rule = _rule_from_indicator(indicator, {})
        assert rule["id"] == "raw-signal-text"
        assert rule["shortDescription"]["text"] == "raw signal text"
        assert rule["fullDescription"]["text"] == "raw signal text"
        assert "helpUri" not in rule

    def test_falls_back_when_threat_id_not_in_taxonomy(self):
        indicator = RiskIndicator(signal="raw signal text", severity="low", threat_id="T404")
        rule = _rule_from_indicator(indicator, {})
        assert rule["id"] == "T404"
        assert rule["shortDescription"]["text"] == "raw signal text"


import json

from quin_scanner.models import AgentProfile, ScanReport
from quin_scanner.sarif import to_sarif


def _minimal_report(**kwargs) -> ScanReport:
    defaults = dict(
        repo_path="/tmp/test-repo",
        scan_timestamp="2025-01-01T00:00:00Z",
        is_ai_application=True,
        confidence=0.95,
    )
    defaults.update(kwargs)
    return ScanReport(**defaults)


class TestToSarif:
    def test_valid_json_envelope(self):
        report = _minimal_report()
        doc = json.loads(to_sarif(report))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "quin-scanner"
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_includes_repo_level_signal_with_real_taxonomy_entry(self):
        report = _minimal_report(
            risk_signals=[
                RiskIndicator(
                    signal="Agent retrieves external content (RAG, web, email, documents)",
                    severity="high",
                    threat_id="T001",
                    evidence_refs=[EvidenceRef(file_path="src/agent.py", line_number=3, scanner="AgentScanner")],
                )
            ]
        )
        doc = json.loads(to_sarif(report))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "T001"
        assert results[0]["level"] == "error"
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "T001"
        # Real taxonomy entry — shortDescription should not just echo the raw signal
        assert rules[0]["shortDescription"]["text"] != ""

    def test_includes_agent_level_signal_with_prefix(self):
        report = _minimal_report(
            agents=[
                AgentProfile(
                    name="Router",
                    agent_type="supervisor",
                    goal="Route requests",
                    risk_signals=[RiskIndicator(signal="Unbounded delegation", severity="medium")],
                )
            ]
        )
        doc = json.loads(to_sarif(report))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["message"]["text"] == "[agent: Router] Unbounded delegation"

    def test_dedupes_rules_by_rule_id(self):
        report = _minimal_report(
            risk_signals=[
                RiskIndicator(signal="Dup signal one", severity="low", threat_id="T001"),
                RiskIndicator(signal="Dup signal two", severity="high", threat_id="T001"),
            ]
        )
        doc = json.loads(to_sarif(report))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert len(doc["runs"][0]["results"]) == 2
