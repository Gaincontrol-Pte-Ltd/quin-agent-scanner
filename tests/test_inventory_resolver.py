"""The inventory resolver: one test per rule in spec §6."""
from __future__ import annotations

import ast

import pytest

from quin_scanner.inventory import python_sites
from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.resolver import fallback, resolve
from quin_scanner.models import ToolUsage
from quin_scanner.scanners.agent_instance_scanner import AgentInstanceScanner

PROMPT = InstructionsRef.literal("Find facts.")
OTHER = InstructionsRef.literal("Write prose.")


def agent(name, path="src/app.py", line=1, *, role="both", kind="constructor",
          instructions=NO_INSTRUCTIONS, tools=(), model=None, in_loop=False):
    return AgentSite(role=role, kind=kind, name=name, file_path=path, line=line, instructions=instructions,
                     model_expr=model, tool_refs=tools, in_loop=in_loop)


def tool(name, path="src/tools.py", line=1, kind="@tool"):
    return ToolSite(name=name, kind=kind, file_path=path, line=line)


def config_entry(name, path, key, tools=None):
    return agent(name, path, None, role="definition", kind="config_entry",
                 instructions=InstructionsRef("config", key), tools=tools)


def python(source, path):
    """Real scanner evidence for one Python file."""
    return python_sites.agent_sites(ast.parse(source), path)


def agents_yaml(content, path):
    """Real scanner evidence for one agents.yaml file."""
    scanner = AgentInstanceScanner()
    scanner._sites = []
    scanner._scan_agent_yaml(content, path, set())
    return scanner.evidence()


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


def test_extra_tools_do_not_depend_on_input_order():
    extras = [
        ToolUsage(tool_name="web", tool_type="skill", source_file="skills/a/SKILL.md"),
        ToolUsage(tool_name="Web", tool_type="external_service", source_file=""),
    ]
    forward = resolve([], [], extras)
    backward = resolve([], [], list(reversed(extras)))
    assert [t.to_dict() for t in forward.tools] == [t.to_dict() for t in backward.tools]
    assert [(t.id, t.tool_type) for t in forward.tools] == [("tool:Web", "external_service")]


def test_two_extra_tools_with_one_name_are_one_tool():
    # First wins after sorting by (name, type, source file).
    extras = [
        ToolUsage(tool_name="pdf", tool_type="skill", source_file="skills/z/SKILL.md"),
        ToolUsage(tool_name="pdf", tool_type="skill", source_file="skills/a/SKILL.md"),
    ]
    assert [(t.id, t.source_file) for t in resolve([], [], extras).tools] == [("tool:pdf", "skills/a/SKILL.md")]


def test_an_external_service_types_every_same_named_definition():
    inv = resolve([], [tool("search", "src/a.py"), tool("search", "src/b.py")],
                  [ToolUsage(tool_name="search", tool_type="external_service", service_category="web_search")])
    assert [(t.id, t.tool_type, t.service_category) for t in inv.tools] == [
        ("tool:search@src/a.py", "external_service", "web_search"),
        ("tool:search@src/b.py", "external_service", "web_search"),
    ]


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


def test_one_config_key_in_two_crews_links_each_instance_to_its_own_yaml():
    crew = (
        "from crewai import Agent\n"
        "from crewai.project import agent\n"
        "class C:\n"
        "    @agent\n"
        "    def researcher(self) -> Agent:\n"
        "        return Agent(config=self.agents_config['researcher'], tools=[%s])\n"
    )
    sites = (
        agents_yaml("researcher:\n  role: Market Researcher\n  goal: g\n", "crewA/config/agents.yaml")
        + agents_yaml("researcher:\n  role: Code Researcher\n  goal: g\n", "crewB/config/agents.yaml")
        + python(crew % "web_search", "crewA/crew.py")
        + python(crew % "git", "crewB/crew.py")
    )
    inv = resolve(sites, [])
    assert [(a.id, a.source_file, a.flags, a.risk_signals) for a in inv.agents] == [
        ("agent:Code Researcher", "crewB/config/agents.yaml", [], []),
        ("agent:Market Researcher", "crewA/config/agents.yaml", [], []),
    ]
    assert [[(i.file, [t.name for t in i.tools]) for i in a.instances] for a in inv.agents] == [
        [("crewB/crew.py", ["git"])],
        [("crewA/crew.py", ["web_search"])],
    ]


def test_a_config_key_tied_between_two_yamls_is_left_unlinked_and_ambiguous():
    key = InstructionsRef("config", "researcher")
    inv = resolve([
        config_entry("Market Researcher", "crewA/config/agents.yaml", "researcher"),
        config_entry("Code Researcher", "crewB/config/agents.yaml", "researcher"),
        agent("researcher", "app/main.py", 4, instructions=key),
    ], [])
    assert [(a.id, a.source_file, a.flags) for a in inv.agents] == [
        ("agent:Code Researcher", "crewB/config/agents.yaml", []),
        ("agent:Market Researcher", "crewA/config/agents.yaml", []),
        ("agent:researcher", "app/main.py", ["ambiguous_instance"]),
    ]


def test_one_config_key_and_name_in_two_dirs_are_two_agents():
    key = InstructionsRef("config", "r")
    inv = resolve([
        config_entry("R", "a/config/agents.yaml", "r"),
        config_entry("R", "b/config/agents.yaml", "r"),
        agent("r", "a/crew.py", 3, instructions=key),
        agent("r", "b/crew.py", 3, instructions=key),
    ], [])
    assert [(a.id, a.flags, [i.file for i in a.instances]) for a in inv.agents] == [
        ("agent:R@a/config/agents.yaml", ["name_collision"], ["a/crew.py"]),
        ("agent:R@b/config/agents.yaml", ["name_collision"], ["b/crew.py"]),
    ]


def test_the_definition_site_is_the_source_even_when_a_both_site_sorts_first():
    inv = resolve([
        config_entry("Senior R", "crew/config/agents.yaml", "r"),
        agent("r", "app/main.py", 4, instructions=InstructionsRef("config", "r")),
    ], [])
    (a,) = inv.agents
    assert (a.id, a.source_file, [i.file for i in a.instances]) == (
        "agent:Senior R", "crew/config/agents.yaml", ["app/main.py"],
    )


def test_a_config_instance_without_tools_inherits_the_yaml_tools():
    sites = agents_yaml("researcher:\n  role: R\n  tools: [web]\n", "c/agents.yaml") + python(
        "from crewai import Agent\n"
        "@agent\n"
        "def researcher(self):\n"
        "    return Agent(config=self.agents_config['researcher'])\n",
        "c/crew.py",
    )
    inv = resolve(sites, [tool("web", "c/tools.py")])
    (a,) = inv.agents
    assert [[(t.name, t.tool_id) for t in i.tools] for i in a.instances] == [[("web", "tool:web")]]
    assert (a.tools, a.flags) == (["web"], [])
    assert [(r.tool_name, r.source_file, r.tool_id) for r in inv.relationships] == [("web", "c/crew.py", "tool:web")]


def test_an_explicit_non_literal_tools_argument_does_not_inherit_yaml_tools():
    sites = agents_yaml("researcher:\n  role: R\n  tools: [web]\n", "c/agents.yaml") + python(
        "from crewai import Agent\n"
        "a = Agent(config=self.agents_config['researcher'], tools=self.tools)\n",
        "c/crew.py",
    )
    (a,) = resolve(sites, [tool("web", "c/tools.py")]).agents
    assert [i.tools for i in a.instances] == [[]]
    assert a.tools == []


CREW = "from crewai import Agent\nr = Agent(config=self.agents_config['researcher'])\n"


def test_nested_crews_link_each_instance_to_its_own_yaml():
    sites = (
        agents_yaml("researcher:\n  role: Outer R\n  tools: [web]\n", "src/p/config/agents.yaml")
        + agents_yaml("researcher:\n  role: Inner R\n", "src/p/sub/config/agents.yaml")
        + python(CREW, "src/p/crew.py")
        + python(CREW, "src/p/sub/crew.py")
    )
    inv = resolve(sites, [])
    assert [(a.id, a.flags, [(i.file, [t.name for t in i.tools]) for i in a.instances]) for a in inv.agents] == [
        ("agent:Inner R", [], [("src/p/sub/crew.py", [])]),
        ("agent:Outer R", [], [("src/p/crew.py", ["web"])]),
    ]


def test_flow_crews_link_each_instance_to_its_own_yaml():
    sites = (
        agents_yaml("researcher:\n  role: A R\n", "src/flow/crews/a/config/agents.yaml")
        + agents_yaml("researcher:\n  role: B R\n", "src/flow/crews/b/config/agents.yaml")
        + python(CREW, "src/flow/crews/a/crew.py")
        + python(CREW, "src/flow/crews/b/crew.py")
    )
    inv = resolve(sites, [])
    assert [(a.id, a.flags, [i.file for i in a.instances]) for a in inv.agents] == [
        ("agent:A R", [], ["src/flow/crews/a/crew.py"]),
        ("agent:B R", [], ["src/flow/crews/b/crew.py"]),
    ]


def test_inherited_yaml_tools_count_for_divergence():
    key = InstructionsRef("config", "r")
    inv = resolve([
        config_entry("R", "c/agents.yaml", "r", tools=("web",)),
        agent("r", "c/a.py", instructions=key, tools=None),
        agent("r", "c/b.py", instructions=key, tools=("web", "shell")),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["tool_divergence"]
    assert [s.threat_id for s in a.risk_signals] == ["T006"]


def test_subclass_definitions_link_to_constructors_in_their_own_file_only():
    source = (
        "from autogen import AssistantAgent\n"
        "class Researcher(AssistantAgent):\n"
        "    pass\n"
        "r = Researcher(system_message='%s')\n"
    )
    inv = resolve(python(source % "X", "a.py") + python(source % "Y", "b.py"), [])
    assert [(a.id, a.source_file, a.flags, [(i.file, i.line) for i in a.instances]) for a in inv.agents] == [
        ("agent:Researcher@a.py", "a.py", ["name_collision"], [("a.py", 4)]),
        ("agent:Researcher@b.py", "b.py", ["name_collision"], [("b.py", 4)]),
    ]


def test_a_definition_does_not_join_a_same_named_agent_in_another_file():
    inv = resolve([
        agent("Researcher", "a.py", 2, role="definition", kind="subclass", tools=None),
        agent("Researcher", "b.py", 5, instructions=PROMPT),
    ], [])
    assert [(a.id, a.source_file, [i.file for i in a.instances]) for a in inv.agents] == [
        ("agent:Researcher@a.py", "a.py", ["a.py"]),
        ("agent:Researcher@b.py", "b.py", ["b.py"]),
    ]


def test_same_named_definitions_in_two_files_are_two_agents():
    inv = resolve([
        agent("W", "a.py", 2, role="definition", kind="subclass", tools=None),
        agent("W", "b.py", 2, role="definition", kind="subclass", tools=None),
    ], [])
    assert [(a.id, a.flags) for a in inv.agents] == [
        ("agent:W@a.py", ["name_collision"]),
        ("agent:W@b.py", ["name_collision"]),
    ]


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
def test_agent_scope_is_production_if_any_instance_is(paths, scope):
    (a,) = resolve([agent("r", p, instructions=PROMPT) for p in paths], []).agents
    assert a.scope == scope


def test_agent_scope_comes_from_instances_not_the_definition():
    inv = resolve([
        config_entry("R", "src/agents.yaml", "r"),
        agent("x", "tests/test_c.py", 3, instructions=InstructionsRef("config", "r")),
    ], [])
    (a,) = inv.agents
    assert (a.source_file, a.scope) == ("src/agents.yaml", "test")


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


def test_sites_that_tie_on_file_line_and_name_do_not_depend_on_input_order():
    for name in (None, "r"):
        sites = [agent(name, "a.py", 3, tools=("x",)), agent(name, "a.py", 3, tools=("y",)),
                 agent(name, "a.py", 3, tools=None), agent(name, "a.py", 3, model="m")]
        forward = resolve(sites, [])
        backward = resolve(list(reversed(sites)), [])
        assert [a.to_dict() for a in forward.agents] == [a.to_dict() for a in backward.agents]
        assert [r.to_dict() for r in forward.relationships] == [r.to_dict() for r in backward.relationships]


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


def test_an_exact_case_tool_name_wins_over_a_casefold_match():
    inv = resolve([agent("r", "src/c.py", tools=("search",))], [tool("Search", "src/a.py"), tool("search", "src/b.py")])
    assert inv.agents[0].instances[0].tools[0].tool_id == "tool:search"


def test_a_colliding_tool_name_from_other_files_stays_unresolved():
    inv = resolve([agent("r", "src/a.py", tools=("search",))], [tool("search", "src/b.py"), tool("search", "src/c.py")])
    assert inv.agents[0].instances[0].tools[0].resolved is False


def test_a_dotted_tool_ref_resolves_by_its_last_component():
    inv = resolve(
        [agent("r", "src/crew.py", tools=("SearchTools.search_internet", "tools.Search", "a.ghost", "x.dup"))],
        [tool("search_internet", "src/tools/search.py"), tool("Search", "src/tools/s.py"),
         tool("dup", "src/p.py"), tool("dup", "src/sub/q.py")],
    )
    assert [t.to_dict() for t in inv.agents[0].instances[0].tools] == [
        {"name": "SearchTools.search_internet", "tool_id": "tool:search_internet", "resolved": True},
        {"name": "tools.Search", "tool_id": "tool:Search", "resolved": True},
        {"name": "a.ghost", "tool_id": None, "resolved": False},
        {"name": "x.dup", "tool_id": None, "resolved": False},
    ]
    assert inv.relationships[0].tool_name == "SearchTools.search_internet"


def test_a_dotted_tool_ref_prefers_its_full_name():
    inv = resolve([agent("r", "src/a.py", tools=("m.run",))], [tool("m.run", "src/b.py"), tool("run", "src/a.py")])
    assert inv.agents[0].instances[0].tools[0].tool_id == "tool:m.run"


def test_a_dotted_ref_never_links_to_a_tool_in_an_unrelated_directory():
    inv = resolve(
        [agent("t", "python/samples/03-workflows/x/main.py", tools=("plugin.send_notification",))],
        [tool("send_notification", "python/samples/02-agents/y/z.py")],
    )
    assert inv.agents[0].instances[0].tools[0].resolved is False


def test_a_dotted_ref_links_to_a_tool_below_or_beside_its_directory():
    inv = resolve([
        agent("a", "crew/crew.py", tools=("SearchTools.search_instagram",)),
        agent("b", "app/agents/main.py", tools=("Calc.calculate",)),
        agent("c", "app/agents/two.py", tools=("T.twin",)),
        agent("d", "top.py", tools=("T.rooted",)),
    ], [
        tool("search_instagram", "crew/tools/search_tools.py"),
        tool("calculate", "app/tools/calc.py"),           # a sibling of app/agents
        tool("twin", "app/tools/a.py"), tool("twin", "app/lib/b.py"),   # two siblings: ambiguous
        tool("rooted", "lib/r.py"),                       # an instance at the root never looks repo-wide
    ])
    got = {a.name: a.instances[0].tools[0].tool_id for a in inv.agents}
    assert got == {"a": "tool:search_instagram", "b": "tool:calculate", "c": None, "d": None}


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
    assert a.provenance["risk_signals"] == "static"
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


def test_tools_known_is_false_only_when_the_instance_tools_are_unknown():
    sites = agents_yaml("researcher:\n  role: R\n  tools: [web]\n", "c/agents.yaml") + python(
        "from crewai import Agent\n"
        "a = Agent(config=self.agents_config['researcher'])\n",
        "c/crew.py",
    )
    (a,) = resolve(sites, [tool("web", "c/tools.py")]).agents
    assert [i.tools_known for i in a.instances] == [True]  # inherited YAML tools are known

    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, tools=("search",)),
        agent("r", "src/b.py", instructions=PROMPT, tools=None),
        agent("r", "src/c.py", instructions=PROMPT, tools=()),
    ], [])
    assert [i.tools_known for i in inv.agents[0].instances] == [True, False, True]


def test_many_definitions_resolve_in_near_linear_time():
    import time

    sites = [agent(f"A{i}", f"src/f{i}.py", 1, role="definition", kind="subclass") for i in range(8000)]
    sites += [agent(f"A{i}", f"src/f{i}.py", 9, instructions=PROMPT) for i in range(0, 8000, 2)]
    start = time.perf_counter()
    inv = resolve(sites, [])
    assert time.perf_counter() - start < 1.0
    assert len(inv.agents) == 8000
    assert all(len(a.instances) == 1 for a in inv.agents)


def test_a_definition_joins_its_same_file_agent_via_the_index():
    inv = resolve([
        agent("A", "src/x.py", 1, role="definition", kind="subclass"),
        agent("A", "src/x.py", 5, instructions=PROMPT),
        agent("A", "src/y.py", 1, role="definition", kind="subclass"),
        agent("A", "src/y.py", 2, role="definition", kind="subclass"),
    ], [])
    assert sorted((a.id, len(a.instances)) for a in inv.agents) == [
        ("agent:A@src/x.py", 1), ("agent:A@src/y.py", 2),
    ]
