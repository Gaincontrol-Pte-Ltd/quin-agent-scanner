"""Tests for LLM response parsing (synthesis, classification, base)."""
from __future__ import annotations

import json

import pytest

from quin_scanner.llm.base import parse_llm_json
from quin_scanner.llm.synthesis_agent import _parse_synthesis_response, _parse_risk_signals
from quin_scanner.llm.classification_agent import _parse_classification_response


class TestParseLlmJson:
    def test_valid_json(self):
        raw = json.dumps({
            "agent_name": "TestAgent",
            "goal": "Test things",
            "capabilities": ["web-search"],
            "risk_signals": ["has internet access"],
        })
        result = parse_llm_json(raw)
        assert result.agent_name == "TestAgent"
        assert result.goal == "Test things"
        assert result.capabilities == ["web-search"]
        assert result.risk_signals == ["has internet access"]

    def test_markdown_fenced_json(self):
        raw = '```json\n{"agent_name": "Fenced", "goal": "test", "capabilities": [], "risk_signals": []}\n```'
        result = parse_llm_json(raw)
        assert result.agent_name == "Fenced"

    def test_markdown_fenced_no_language(self):
        raw = '```\n{"agent_name": "NoLang", "goal": "test", "capabilities": [], "risk_signals": []}\n```'
        result = parse_llm_json(raw)
        assert result.agent_name == "NoLang"

    def test_missing_fields_use_defaults(self):
        raw = json.dumps({"goal": "only goal"})
        result = parse_llm_json(raw)
        assert result.agent_name == "UnknownAgent"
        assert result.capabilities == []

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            parse_llm_json("not json at all")


class TestParseSynthesisResponse:
    def test_valid_full_response(self):
        data = {
            "is_ai_application": True,
            "framework": "LangChain",
            "summary": "An AI app using LangChain.",
            "agents": [
                {
                    "name": "Researcher",
                    "agent_type": "worker",
                    "goal": "Research topics",
                    "capabilities": ["web-search"],
                    "risk_signals": [{"signal": "Has internet access", "recommended_controls": ["C001: Control"]}],
                    "skills": ["research-skill"],
                    "tools": ["google_search"],
                    "source_file": "agent.py",
                }
            ],
            "tool_usages": [
                {
                    "tool_name": "google_search",
                    "tool_type": "tool_definition",
                    "service_category": "web_search",
                    "source_file": "tools.py",
                    "line_number": 10,
                }
            ],
            "risk_signals": [
                {"signal": "No observability", "recommended_controls": ["C005: Monitoring"]}
            ],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert result.is_ai_application is True
        assert result.framework == "LangChain"
        assert len(result.agents) == 1
        assert result.agents[0].name == "Researcher"
        assert result.agents[0].tools == ["google_search"]
        assert result.agents[0].skills == ["research-skill"]
        assert len(result.tool_usages) == 1
        assert result.tool_usages[0].service_category == "web_search"
        assert len(result.risk_signals) == 1

    def test_markdown_fenced_response(self):
        data = {"is_ai_application": True, "framework": "CrewAI", "summary": "Test."}
        raw = f"```json\n{json.dumps(data)}\n```"
        result = _parse_synthesis_response(raw)
        assert result.framework == "CrewAI"

    def test_preamble_text_before_json(self):
        data = {"is_ai_application": False, "framework": "unknown", "summary": ""}
        raw = f"Here is the result:\n{json.dumps(data)}"
        result = _parse_synthesis_response(raw)
        assert result.is_ai_application is False

    def test_invalid_json_returns_fallback(self):
        result = _parse_synthesis_response("totally broken {{{ json")
        assert result.is_ai_application is False
        assert result.framework == "unknown"
        assert result.agents == []

    def test_empty_string_returns_fallback(self):
        result = _parse_synthesis_response("")
        assert result.is_ai_application is False

    def test_invalid_tool_type_defaults(self):
        data = {
            "is_ai_application": True,
            "framework": "unknown",
            "summary": "",
            "tool_usages": [
                {"tool_name": "mytool", "tool_type": "invalid_type", "service_category": "other"}
            ],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert result.tool_usages[0].tool_type == "tool_definition"

    def test_framework_null_becomes_unknown(self):
        data = {"is_ai_application": True, "framework": None, "summary": ""}
        result = _parse_synthesis_response(json.dumps(data))
        assert result.framework == "unknown"


class TestParseRiskSignals:
    def test_dict_format(self):
        raw = [{"signal": "Risk A", "recommended_controls": ["C001"]}]
        result = _parse_risk_signals(raw)
        assert len(result) == 1
        assert result[0].signal == "Risk A"
        assert result[0].recommended_controls == ["C001"]
        assert result[0].threat_id is None

    def test_dict_format_with_threat_id(self):
        raw = [{"signal": "Risk A", "recommended_controls": ["C001"], "threat_id": "T001"}]
        result = _parse_risk_signals(raw)
        assert len(result) == 1
        assert result[0].threat_id == "T001"

    def test_dict_format_empty_threat_id_becomes_none(self):
        raw = [{"signal": "Risk A", "recommended_controls": [], "threat_id": ""}]
        result = _parse_risk_signals(raw)
        assert result[0].threat_id is None

    def test_legacy_string_format(self):
        raw = ["Risk B", "Risk C"]
        result = _parse_risk_signals(raw)
        assert len(result) == 2
        assert result[0].signal == "Risk B"
        assert result[0].recommended_controls == []
        assert result[0].threat_id is None

    def test_empty_signal_skipped(self):
        raw = [{"signal": "", "recommended_controls": []}]
        result = _parse_risk_signals(raw)
        assert len(result) == 0

    def test_mixed_formats(self):
        raw = [
            {"signal": "Dict signal", "recommended_controls": ["C001"], "threat_id": "T002"},
            "String signal",
        ]
        result = _parse_risk_signals(raw)
        assert len(result) == 2
        assert result[0].threat_id == "T002"
        assert result[1].threat_id is None


class TestRiskIndicatorToDict:
    def test_to_dict_includes_threat_id_and_severity(self):
        from quin_scanner.models import RiskIndicator
        ri = RiskIndicator(signal="s", recommended_controls=["C001"], threat_id="T001")
        d = ri.to_dict()
        assert d == {
            "signal": "s",
            "recommended_controls": ["C001"],
            "threat_id": "T001",
            "severity": "medium",
        }

    def test_to_dict_threat_id_defaults_to_none(self):
        from quin_scanner.models import RiskIndicator
        ri = RiskIndicator(signal="s")
        assert ri.to_dict()["threat_id"] is None

    def test_severity_defaults_to_medium(self):
        from quin_scanner.models import RiskIndicator
        assert RiskIndicator(signal="s").severity == "medium"

    def test_severity_round_trips_through_to_dict(self):
        from quin_scanner.models import RiskIndicator
        ri = RiskIndicator(signal="s", severity="critical")
        assert ri.to_dict()["severity"] == "critical"


class TestThreatIdTaxonomyResolution:
    def test_hardcoded_vuln_threat_id_resolves(self):
        """The orchestrator's hardcoded CVE->RiskIndicator uses threat_id='T003'; verify T003 exists in taxonomy."""
        import re
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        threat_ids = {t.id for t in tax.threats}
        assert "T003" in threat_ids
        # Format guard: all taxonomy threats follow T0NN
        pattern = re.compile(r"^T\d{3}$")
        for tid in threat_ids:
            assert pattern.match(tid), f"Invalid threat ID format: {tid}"


class TestParseClassificationResponse:
    def test_valid_response(self):
        data = {
            "system_types": ["standard_ai", "agentic_ai"],
            "relevant_threats": ["T001", "T002"],
        }
        result = _parse_classification_response(json.dumps(data))
        assert result is not None
        assert "standard_ai" in result.system_types
        assert "agentic_ai" in result.system_types

    def test_invalid_system_type_filtered(self):
        data = {
            "system_types": ["standard_ai", "made_up_type"],
            "relevant_threats": [],
        }
        result = _parse_classification_response(json.dumps(data))
        assert result is not None
        assert result.system_types == ["standard_ai"]

    def test_no_valid_types_returns_none(self):
        data = {"system_types": ["invalid"], "relevant_threats": []}
        result = _parse_classification_response(json.dumps(data))
        assert result is None

    def test_invalid_json_returns_none(self):
        result = _parse_classification_response("not json")
        assert result is None

    def test_markdown_fenced(self):
        data = {"system_types": ["mcp_enabled"], "relevant_threats": []}
        raw = f"```json\n{json.dumps(data)}\n```"
        result = _parse_classification_response(raw)
        assert result is not None
        assert "mcp_enabled" in result.system_types

    def test_non_list_fields_returns_none(self):
        data = {"system_types": "standard_ai", "relevant_threats": "T001"}
        result = _parse_classification_response(json.dumps(data))
        assert result is None
