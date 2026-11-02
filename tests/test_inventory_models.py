"""Report records added by the inventory (schema 1.1)."""
from __future__ import annotations

from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    AgentToolRelationship,
    InstanceTool,
    LLMInferredItem,
    ScanReport,
    ToolUsage,
)


def test_agent_profile_serialises_the_new_fields_with_defaults():
    d = AgentProfile(name="a", agent_type="unknown", goal="").to_dict()
    assert (d["id"], d["identity"], d["scope"]) == ("", "strong", "production")
    assert (d["flags"], d["provenance"], d["instances"]) == ([], {}, [])


def test_agent_instance_round_trip():
    instance = AgentInstance(
        id="agent:r/a.py#1", file="a.py", line=3, scope="production", multiplicity="many", model="env:MODEL",
        tools=[InstanceTool(name="search", tool_id="tool:search", resolved=True), InstanceTool(name="ghost")],
    )
    assert instance.to_dict() == {
        "id": "agent:r/a.py#1", "file": "a.py", "line": 3, "scope": "production", "multiplicity": "many",
        "model": "env:MODEL", "tools_known": True,
        "tools": [
            {"name": "search", "tool_id": "tool:search", "resolved": True},
            {"name": "ghost", "tool_id": None, "resolved": False},
        ],
    }


def test_existing_records_gain_ids():
    tool = ToolUsage(tool_name="t").to_dict()
    assert (tool["id"], tool["scope"]) == ("", "production")
    edge = AgentToolRelationship(agent_name="a", tool_name="t", source_file="a.py", line_number=1).to_dict()
    assert (edge["agent_id"], edge["instance_id"], edge["tool_id"]) == ("", "", None)


def test_report_carries_the_llm_inferred_lists():
    report = ScanReport(
        repo_path="r", scan_timestamp="t", is_ai_application=False, confidence=0.0,
        llm_inferred_agents=[LLMInferredItem(name="planner", evidence="factory", file="a.py")],
    )
    data = report.to_dict()
    assert data["llm_inferred_agents"] == [{"name": "planner", "evidence": "factory", "file": "a.py"}]
    assert data["llm_inferred_tools"] == []
