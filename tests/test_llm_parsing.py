"""Tests for LLM response parsing (synthesis, classification, base)."""
from __future__ import annotations

import json

import pytest

from quin_scanner.llm.base import parse_llm_json
from quin_scanner.llm.synthesis_agent import _build_evidence_block, _parse_synthesis_response, _parse_risk_signals
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
            "enrichment": {
                "agent:researcher": {
                    "agent_type": "worker",
                    "goal": "Research topics",
                    "capabilities": ["web-search"],
                    "risk_signals": [{"signal": "Has internet access", "recommended_controls": ["C001: Control"]}],
                }
            },
            "tool_enrichment": {"tool:google_search": {"service_category": "web_search"}},
            "suggested_agents": [{"name": "planner", "evidence": "built by make_planner()", "file": "agents.py"}],
            "suggested_tools": [{"name": "browse", "evidence": "registered at runtime", "file": "tools.py"}],
            "risk_signals": [{"signal": "No observability", "recommended_controls": ["C005: Monitoring"]}],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert result.is_ai_application is True
        assert result.framework == "LangChain"
        enrichment = result.enrichment["agent:researcher"]
        assert (enrichment.agent_type, enrichment.goal, enrichment.capabilities) == ("worker", "Research topics", ["web-search"])
        assert [s.signal for s in enrichment.risk_signals] == ["Has internet access"]
        assert result.tool_enrichment == {"tool:google_search": "web_search"}
        assert [(i.name, i.file) for i in result.suggested_agents] == [("planner", "agents.py")]
        assert [i.name for i in result.suggested_tools] == ["browse"]
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
        assert result.enrichment == {}

    def test_empty_string_returns_fallback(self):
        result = _parse_synthesis_response("")
        assert result.is_ai_application is False

    def test_malformed_enrichment_is_ignored(self):
        data = {
            "is_ai_application": True, "framework": "unknown", "summary": "",
            "enrichment": {"agent:a": "not an object", "agent:b": {"agent_type": "boss", "capabilities": ["x", 3]}},
            "tool_enrichment": ["not", "a", "dict"],
            "suggested_agents": [{"name": ""}, "x", {"name": "ok"}],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert list(result.enrichment) == ["agent:b"]
        assert result.enrichment["agent:b"].agent_type == "unknown"
        assert result.enrichment["agent:b"].capabilities == ["x"]
        assert result.tool_enrichment == {}
        assert [i.name for i in result.suggested_agents] == ["ok"]

    def test_old_style_agents_and_tool_usages_are_ignored(self):
        data = {"is_ai_application": True, "framework": "x", "summary": "",
                "agents": [{"name": "invented"}], "tool_usages": [{"tool_name": "gpt-4o"}]}
        result = _parse_synthesis_response(json.dumps(data))
        assert result.enrichment == {}
        assert result.suggested_agents == []

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
    def test_to_dict_includes_all_fields(self):
        from quin_scanner.models import RiskIndicator
        ri = RiskIndicator(signal="s", recommended_controls=["C001"], threat_id="T001")
        d = ri.to_dict()
        assert d == {
            "signal": "s",
            "recommended_controls": ["C001"],
            "threat_id": "T001",
            "severity": "medium",
            "evidence_refs": [],
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

    def test_evidence_refs_default_to_empty_list(self):
        from quin_scanner.models import RiskIndicator
        assert RiskIndicator(signal="s").evidence_refs == []

    def test_evidence_refs_round_trip(self):
        from quin_scanner.models import RiskIndicator, EvidenceRef
        ri = RiskIndicator(signal="s", evidence_refs=[
            EvidenceRef(file_path="src/main.py", line_number=42, scanner="ToolDefinitionScanner"),
            EvidenceRef(scanner="VulnChecker", source_url="https://example.com/advisory"),
        ])
        d = ri.to_dict()
        assert len(d["evidence_refs"]) == 2
        assert d["evidence_refs"][0]["file_path"] == "src/main.py"
        assert d["evidence_refs"][0]["line_number"] == 42
        assert d["evidence_refs"][1]["source_url"] == "https://example.com/advisory"


class TestParseEvidenceRefs:
    """LLM-output parser tolerates malformed evidence_refs."""

    def _parse(self, raw):
        from quin_scanner.llm.synthesis_agent import _parse_evidence_refs
        return _parse_evidence_refs(raw)

    def test_well_formed(self):
        refs = self._parse([
            {"file_path": "src/x.py", "line_number": 10, "scanner": "ToolDefinitionScanner"},
        ])
        assert len(refs) == 1
        assert refs[0].file_path == "src/x.py"
        assert refs[0].line_number == 10

    def test_drops_entries_with_no_path_or_url(self):
        refs = self._parse([
            {"line_number": 5, "scanner": "X"},  # no file_path / source_url
            {"file_path": "src/x.py"},
        ])
        assert len(refs) == 1
        assert refs[0].file_path == "src/x.py"

    def test_negative_line_number_becomes_none(self):
        refs = self._parse([{"file_path": "x", "line_number": -1}])
        assert refs[0].line_number is None

    def test_string_line_number_parsed(self):
        refs = self._parse([{"file_path": "x", "line_number": "42"}])
        assert refs[0].line_number == 42

    def test_invalid_line_number_becomes_none(self):
        refs = self._parse([{"file_path": "x", "line_number": "not-a-number"}])
        assert refs[0].line_number is None

    def test_non_list_returns_empty(self):
        assert self._parse(None) == []
        assert self._parse("not a list") == []
        assert self._parse({}) == []

    def test_non_dict_items_skipped(self):
        assert self._parse(["not a dict", 42, None]) == []


class TestThreatIdTaxonomyResolution:
    def test_hardcoded_vuln_threat_id_resolves(self):
        """The orchestrator's hardcoded CVE->RiskIndicator uses threat_id='T003'; verify T003 exists in taxonomy."""
        import re
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        threat_ids = {t.id for t in tax.threats}
        assert "T003" in threat_ids
        # CVE control label is C004 — must exist and be one of T003's recommended controls
        control_ids = {c.id for c in tax.controls}
        assert "C004" in control_ids
        t003 = next(t for t in tax.threats if t.id == "T003")
        assert "C004" in t003.recommended_controls
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


def test_evidence_block_lists_the_inventory_by_id():
    block = _build_evidence_block(
        [], [], [],
        agent_inventory=[{"id": "agent:r", "name": "r", "scope": "production", "instances": 2,
                          "instructions": "literal", "tools": ["search"], "skills": [], "file": "a.py"}],
        tool_inventory=[{"id": "tool:search", "name": "search", "type": "tool_definition", "category": "",
                         "file": "t.py", "line": 3}],
    )
    assert ('id=agent:r name="r" scope=production instances=2 instructions=literal tools=[search] skills=[none] '
            'file=a.py') in block
    assert 'id=tool:search name="search" type=tool_definition at t.py:3' in block


def test_service_category_must_be_a_listed_category():
    from quin_scanner.llm.synthesis_agent import SERVICE_CATEGORIES, _SYSTEM_PROMPT
    data = {"is_ai_application": True, "framework": "x", "summary": "",
            "tool_enrichment": {"tool:a": {"service_category": "web_search"},
                                "tool:b": {"service_category": "ransomware"},
                                "tool:c": {"service_category": ["web_search"]}}}
    result = _parse_synthesis_response(json.dumps(data))
    assert result.tool_enrichment == {"tool:a": "web_search"}
    assert len(SERVICE_CATEGORIES) == 17
    for name, _ in SERVICE_CATEGORIES:
        assert f'* "{name}" —' in _SYSTEM_PROMPT


def test_goal_and_suggestions_are_strings_capped_and_redacted():
    secret = "sk-proj-" + "A" * 40
    data = {
        "is_ai_application": True, "framework": "x", "summary": "",
        "enrichment": {"agent:a": {"goal": ["not", "a", "string"]},
                       "agent:b": {"goal": "g" * 900},
                       "agent:c": {"goal": f"uses key {secret}"}},
        "suggested_agents": [
            {"name": 42, "evidence": "x", "file": "a.py"},
            {"name": "n" * 300, "evidence": 7, "file": ["a.py"]},
            {"name": "planner", "evidence": f"key {secret} " + "e" * 900, "file": "f" * 900},
        ],
    }
    result = _parse_synthesis_response(json.dumps(data))
    assert result.enrichment["agent:a"].goal == ""
    assert result.enrichment["agent:b"].goal == "g" * 500
    assert secret not in result.enrichment["agent:c"].goal and "REDACTED" in result.enrichment["agent:c"].goal
    long_name, planner = result.suggested_agents
    assert (long_name.name, long_name.evidence, long_name.file) == ("n" * 200, "", "")
    assert secret not in planner.evidence and "REDACTED" in planner.evidence
    assert len(planner.evidence) == 500 and len(planner.file) == 500

