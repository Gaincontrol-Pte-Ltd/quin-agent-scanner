"""The inventory resolver: one test per rule in spec §6."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.resolver import fallback, resolve
from quin_scanner.models import ToolUsage

PROMPT = InstructionsRef.literal("Find facts.")
OTHER = InstructionsRef.literal("Write prose.")


def agent(name, path="src/app.py", line=1, *, role="both", kind="constructor",
          instructions=NO_INSTRUCTIONS, tools=(), model=None, in_loop=False):
    return AgentSite(role=role, kind=kind, name=name, file_path=path, line=line, instructions=instructions,
                     model_expr=model, tool_refs=tools, in_loop=in_loop)


def tool(name, path="src/tools.py", line=1, kind="@tool"):
    return ToolSite(name=name, kind=kind, file_path=path, line=line)


# --- tools ------------------------------------------------------------------------------------


def test_unique_tool_names_get_plain_ids():
    inv = resolve([], [tool("search"), tool("calc", "src/calc.py")])
    assert [(t.id, t.tool_name, t.source_file, t.scope) for t in inv.tools] == [
        ("tool:calc", "calc", "src/calc.py", "production"),
        ("tool:search", "search", "src/tools.py", "production"),
    ]


def test_same_name_in_two_files_is_a_collision():
    inv = resolve([], [tool("search", "src/a.py"), tool("search", "tests/test_b.py")])
    assert [(t.id, t.scope) for t in inv.tools] == [
        ("tool:search@src/a.py", "production"),
        ("tool:search@tests/test_b.py", "test"),
    ]


def test_same_name_twice_in_one_file_is_one_tool():
    inv = resolve([], [tool("search", line=9), tool("search", line=3)])
    assert [(t.id, t.line_number) for t in inv.tools] == [("tool:search", 3)]


def test_extra_tools_are_merged_by_name():
    extras = [
        ToolUsage(tool_name="search", tool_type="external_service", service_category="web_search",
                  source_file="requirements.txt"),
        ToolUsage(tool_name="pdf", tool_type="skill", source_file="skills/pdf/SKILL.md"),
        ToolUsage(tool_name="SEARCH", tool_type="skill", source_file="skills/s/SKILL.md"),
    ]
    inv = resolve([], [tool("search")], extras)
    assert [(t.id, t.tool_type, t.service_category) for t in inv.tools] == [
        ("tool:pdf", "skill", ""),
        ("tool:search", "external_service", "web_search"),
    ]
# --- agent grouping and IDs ---------------------------------------------------------------------


def test_same_name_and_instructions_are_one_agent_with_instances():
    inv = resolve([
        agent("researcher", "src/a.py", 3, instructions=PROMPT),
        agent("researcher", "src/b.py", 7, instructions=PROMPT),
        agent("researcher", "src/a.py", 9, instructions=PROMPT),
    ], [])
    (a,) = inv.agents
    assert (a.id, a.identity, a.flags, a.name) == ("agent:researcher", "strong", [], "researcher")
    assert [i.id for i in a.instances] == [
        "agent:researcher/src/a.py#1", "agent:researcher/src/a.py#2", "agent:researcher/src/b.py#1",
    ]


def test_same_name_different_instructions_is_a_collision():
    inv = resolve([
        agent("assistant", "src/a.py", instructions=PROMPT),
        agent("assistant", "examples/b.py", instructions=OTHER),
    ], [])
    assert [(a.id, a.flags) for a in inv.agents] == [
        ("agent:assistant@examples/b.py", ["name_collision"]),
        ("agent:assistant@src/a.py", ["name_collision"]),
    ]


def test_collision_ids_in_one_file_get_a_counter():
    inv = resolve([agent("a", "src/x.py", 1, instructions=PROMPT), agent("a", "src/x.py", 2, instructions=OTHER)], [])
    assert [a.id for a in inv.agents] == ["agent:a@src/x.py", "agent:a@src/x.py#2"]


def test_unknown_instructions_join_the_single_same_named_agent():
    inv = resolve([agent("r", "src/a.py", instructions=PROMPT), agent("r", "src/b.py")], [])
    (a,) = inv.agents
    assert len(a.instances) == 2


def test_unknown_instructions_with_two_candidates_are_ambiguous():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT),
        agent("r", "src/b.py", instructions=OTHER),
        agent("r", "src/c.py"),
    ], [])
    flags = {a.source_file: a.flags for a in inv.agents}
    assert flags == {
        "src/a.py": ["name_collision"],
        "src/b.py": ["name_collision"],
        "src/c.py": ["ambiguous_instance", "name_collision"],
    }


def test_sites_without_a_name_are_weak_agents_numbered_per_file():
    inv = resolve([agent(None, "src/a.py", 5), agent(None, "src/a.py", 2), agent(None, "src/b.py", 1)], [])
    assert [(a.id, a.identity, a.name) for a in inv.agents] == [
        ("agent:@src/a.py#1", "weak", ""),
        ("agent:@src/a.py#2", "weak", ""),
        ("agent:@src/b.py#1", "weak", ""),
    ]
    assert inv.agents[0].instances[0].line == 2


def test_config_key_links_a_code_instance_to_its_yaml_definition():
    definition = agent("Senior Researcher", "config/agents.yaml", None, role="definition", kind="config_entry",
                       instructions=InstructionsRef("config", "researcher"), tools=None)
    instance = agent("researcher", "src/crew.py", 12, instructions=InstructionsRef("config", "researcher"),
                     tools=("search",))
    (a,) = resolve([definition, instance], []).agents
    assert (a.id, a.source_file) == ("agent:Senior Researcher", "config/agents.yaml")
    assert [i.file for i in a.instances] == ["src/crew.py"]


def test_a_definition_without_instances_is_its_own_instance():
    (a,) = resolve([agent("Writer", "src/w.py", 1, role="definition", kind="subclass", tools=None)], []).agents
    assert [i.id for i in a.instances] == ["agent:Writer/src/w.py#1"]


@pytest.mark.parametrize(
    ("paths", "scope"),
    [
        (["tests/test_a.py", "src/b.py"], "production"),
        (["tests/test_a.py", "examples/b.py"], "test"),
        (["examples/b.py"], "example"),
    ],
)
def test_agent_scope_is_production_if_any_site_is(paths, scope):
    (a,) = resolve([agent("r", p, instructions=PROMPT) for p in paths], []).agents
    assert a.scope == scope


def test_ids_do_not_depend_on_line_numbers():
    before = resolve([agent("r", "src/a.py", 3, instructions=PROMPT), agent(None, "src/a.py", 10)], [])
    after = resolve([agent("r", "src/a.py", 40, instructions=PROMPT), agent(None, "src/a.py", 80)], [])
    assert [a.id for a in before.agents] == [a.id for a in after.agents]
    assert [i.id for a in before.agents for i in a.instances] == [i.id for a in after.agents for i in a.instances]


def test_output_is_sorted_and_independent_of_input_order():
    sites = [agent("b", "src/b.py", instructions=PROMPT), agent("a", "src/a.py", instructions=PROMPT), agent(None, "src/c.py")]
    forward = resolve(sites, [])
    backward = resolve(list(reversed(sites)), [])
    assert [a.to_dict() for a in forward.agents] == [a.to_dict() for a in backward.agents]
    assert [a.id for a in forward.agents] == ["agent:@src/c.py#1", "agent:a", "agent:b"]


# --- instance tools, relationships and divergence ---------------------------------------------


def test_instance_tools_link_to_a_same_file_definition_first():
    inv = resolve([agent("r", "src/a.py", 5, tools=("search", "ghost"))],
                  [tool("search", "src/a.py", 2), tool("search", "src/b.py", 1)])
    (instance,) = inv.agents[0].instances
    assert [t.to_dict() for t in instance.tools] == [
        {"name": "search", "tool_id": "tool:search@src/a.py", "resolved": True},
        {"name": "ghost", "tool_id": None, "resolved": False},
    ]


def test_instance_tools_link_to_a_repo_unique_name():
    inv = resolve([agent("r", "src/a.py", tools=("lookup",))], [tool("lookup", "src/tools.py", 2)])
    assert inv.agents[0].instances[0].tools[0].tool_id == "tool:lookup"


def test_a_colliding_tool_name_from_other_files_stays_unresolved():
    inv = resolve([agent("r", "src/a.py", tools=("search",))], [tool("search", "src/b.py"), tool("search", "src/c.py")])
    assert inv.agents[0].instances[0].tools[0].resolved is False


def test_relationships_are_built_from_instances():
    inv = resolve([agent("researcher", "agent.py", 5, tools=("lookup_customer",))],
                  [tool("lookup_customer", "agent.py", 2)])
    assert [r.to_dict() for r in inv.relationships] == [{
        "agent_name": "researcher", "tool_name": "lookup_customer", "source_file": "agent.py", "line_number": 5,
        "tool_source_file": "agent.py", "tool_line_number": 2, "evidence": "explicit_tools_argument",
        "agent_id": "agent:researcher", "instance_id": "agent:researcher/agent.py#1",
        "tool_id": "tool:lookup_customer",
    }]
    assert inv.agents[0].tools == ["lookup_customer"]


def test_production_tool_divergence_is_a_t006_risk_signal():
    inv = resolve([
        agent("r", "src/a.py", 1, instructions=PROMPT, tools=("search",)),
        agent("r", "src/admin.py", 1, instructions=PROMPT, tools=("search", "shell_exec")),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["tool_divergence"]
    (signal,) = a.risk_signals
    assert (signal.threat_id, signal.severity, signal.recommended_controls) == (
        "T006", "medium", ["C003: Access Control & Least Privilege"],
    )
    assert "shell_exec" in signal.signal
    assert [(r.file_path, r.line_number) for r in signal.evidence_refs] == [("src/a.py", 1), ("src/admin.py", 1)]


def test_divergence_only_in_test_code_is_a_flag_without_a_signal():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, tools=("search",)),
        agent("r", "tests/test_a.py", instructions=PROMPT, tools=("search", "fake")),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["tool_divergence"]
    assert a.risk_signals == []


def test_unknown_tool_lists_do_not_count_as_divergence():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, tools=("search",)),
        agent("r", "src/b.py", instructions=PROMPT, tools=None),
    ], [])
    assert inv.agents[0].flags == []


def test_model_divergence_is_informational_and_loops_are_marked():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, model="gpt-4o", in_loop=True),
        agent("r", "src/b.py", instructions=PROMPT, model="env:MODEL"),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["model_divergence"]
    assert a.risk_signals == []
    assert [i.multiplicity for i in a.instances] == ["many", "one"]


def test_provenance_and_digest_instructions():
    inv = resolve([agent("r", instructions=InstructionsRef("file", "prompts/r.md"))], [])
    assert inv.agents[0].provenance == {"name": "static", "tools": "static"}
    assert inv.instructions == {"agent:r": "file:prompts/r.md"}


def test_fallback_gives_one_weak_agent_per_site():
    inv = fallback([agent("r", "src/a.py", 3), agent(None, "src/a.py", 1)])
    assert [(a.id, a.name, a.identity) for a in inv.agents] == [
        ("agent:@src/a.py#1", "", "weak"),
        ("agent:@src/a.py#2", "r", "weak"),
    ]
    assert inv.tools == [] and inv.relationships == []
