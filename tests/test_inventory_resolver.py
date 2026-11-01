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
