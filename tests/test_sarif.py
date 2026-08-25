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
