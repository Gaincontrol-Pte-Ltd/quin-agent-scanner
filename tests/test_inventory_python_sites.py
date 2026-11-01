"""Agent sites from one ast pass over a Python file."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef
from quin_scanner.inventory.python_sites import agent_sites, parse_python


def _sites(source: str, path: str = "app.py"):
    tree = parse_python(source)
    assert tree is not None
    return agent_sites(tree, path)


def test_inline_constructor_carries_identity_and_instance_attributes():
    (site,) = _sites(
        'researcher = Agent(name="researcher", instructions="Find  facts.", model="gpt-4o",'
        ' tools=[search, "fetch", Tool(name="calc")])\n'
    )
    assert (site.role, site.kind, site.name, site.file_path, site.line) == ("both", "constructor", "researcher", "app.py", 1)
    assert site.instructions == InstructionsRef.literal("Find facts.")
    assert site.model_expr == "gpt-4o"
    assert site.tool_refs == ("search", "fetch", "calc")
    assert site.in_loop is False


def test_no_tools_argument_means_none_passed_and_a_non_literal_list_means_unknown():
    a, b = _sites('a = Agent(name="a")\nb = Agent(name="b", tools=TOOLS)\n')
    assert a.tool_refs == ()
    assert b.tool_refs is None


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("PROMPT", InstructionsRef("var", "PROMPT")),
        ("prompts.RESEARCHER", InstructionsRef("var", "prompts.RESEARCHER")),
        ('open("prompts/r.md").read()', InstructionsRef("file", "prompts/r.md")),
        ('Path("prompts/r.md").read_text()', InstructionsRef("file", "prompts/r.md")),
        ('f"Be {x}"', NO_INSTRUCTIONS),
    ],
)
def test_instruction_references(expr, expected):
    (site,) = _sites(f'a = Agent(name="a", instructions={expr})\n')
    assert site.instructions == expected


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ('os.getenv("MODEL")', "env:MODEL"),
        ('os.environ["MODEL"]', "env:MODEL"),
        ('os.environ.get("MODEL", "gpt-4o")', "env:MODEL"),
        ("settings.llm", "var:settings.llm"),
        ('OpenAIChat("gpt-4o")', "OpenAIChat('gpt-4o')"),
    ],
)
def test_model_expressions(expr, expected):
    (site,) = _sites(f'a = Agent(name="a", model={expr})\n')
    assert site.model_expr == expected


def test_autogen_keywords_and_positional_name():
    (site,) = _sites('a = AssistantAgent("helper", system_message=SYS, model_client=client)\n')
    assert (site.name, site.instructions, site.model_expr) == ("helper", InstructionsRef("var", "SYS"), "var:client")


def test_agents_built_in_loops_are_marked():
    sites = _sites('agents = [Agent(name="w", tools=[t]) for t in tools]\nfor i in range(3):\n    x = Agent(name="v")\n')
    assert [(s.name, s.in_loop) for s in sites] == [("w", True), ("v", True)]


def test_anonymous_agent_constructor_is_a_weak_site_but_other_agent_calls_are_not():
    sites = _sites(
        'a = Agent("openai:gpt-4o", system_prompt="Be brief.")\n'
        "b = create_react_agent(model, tools)\n"
        "c = evaluate_agent(agent=a)\n"
    )
    assert [(s.name, s.instructions.kind) for s in sites] == [(None, "literal")]


def test_subclass_definition_and_its_instances_in_the_same_file():
    sites = _sites("class Writer(BaseAgent):\n    pass\n\nw = Writer(tools=[pen])\nx = Writer()\n")
    assert [(s.role, s.kind, s.name, s.line, s.tool_refs) for s in sites] == [
        ("definition", "subclass", "Writer", 1, None),
        ("instance", "constructor", "Writer", 4, ("pen",)),
        ("instance", "constructor", "Writer", 5, None),
    ]


def test_crewai_agent_method_names_the_agent_it_builds():
    source = (
        "class Crew:\n"
        "    @agent\n"
        "    def researcher(self) -> Agent:\n"
        "        return Agent(config=self.agents_config['researcher'], tools=[search])\n"
    )
    (site,) = _sites(source)
    assert (site.name, site.instructions, site.tool_refs, site.line) == (
        "researcher", InstructionsRef("config", "researcher"), ("search",), 4,
    )


def test_a_decorated_agent_function_without_a_constructor_is_a_definition_and_its_calls_are_instances():
    sites = _sites("@agent\ndef planner():\n    pass\n\nplanner()\n")
    assert [(s.role, s.kind, s.name, s.line) for s in sites] == [
        ("definition", "decorator", "planner", 1),
        ("instance", "decorator", "planner", 5),
    ]


def test_literal_model_text_is_redacted():
    (site,) = _sites('a = Agent(name="a", model="https://user:sk-abc123def456ghi789jkl@host/v1")\n')
    assert "sk-abc123" not in site.model_expr


def test_unparseable_source_gives_none():
    assert parse_python("this is not python (\n") is None


# ── Review fixes ─────────────────────────────────────────────────────────────

def test_deeply_nested_expression_gives_no_sites_instead_of_recursion_error():
    tree = parse_python("x = " + "+".join(["a"] * 1000) + "\n")
    assert tree is not None
    assert agent_sites(tree, "deep.py") == []


@pytest.mark.parametrize(
    ("tools", "expected"),
    [
        ('[*BASE, x]', None),
        ('[x, Tool(name="t"), get_tool("u")]', None),
        ('[x, lambda: 1]', None),
        ("[search.run, x]", ("search.run", "x")),
        ("[make().run]", None),
        ("None", ()),
        ("[]", ()),
    ],
)
def test_tool_lists_are_known_only_when_every_element_is_named(tools, expected):
    (site,) = _sites(f'a = Agent(name="a", tools={tools})\n')
    assert site.tool_refs == expected


def test_user_content_in_sites_is_redacted():
    key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    a, b = _sites(
        f'a = Agent(name="{key}", instructions=open("prompts/{key}.md").read(), tools=["{key}", x])\n'
        f'b = Agent(name="b", config=self.agents_config["{key}"])\n'
    )
    assert a.name == "[REDACTED]"
    assert a.instructions == InstructionsRef("file", "prompts/[REDACTED].md")
    assert a.tool_refs == ("[REDACTED]", "x")
    assert b.instructions == InstructionsRef("config", "[REDACTED]")


def test_a_function_defined_in_a_loop_is_not_itself_in_a_loop():
    sites = _sites(
        "for i in range(3):\n"
        "    def make():\n"
        '        return Agent(name="inner")\n'
        "    class K:\n"
        '        a = Agent(name="cls")\n'
        '    f = lambda: Agent(name="lam")\n'
    )
    assert [(s.name, s.in_loop) for s in sites] == [("inner", False), ("cls", False), ("lam", False)]


def test_loop_iterables_are_not_in_the_loop():
    sites = _sites(
        'for a in [Agent(name="it")]:\n'
        "    pass\n"
        "else:\n"
        '    Agent(name="els")\n'
        'xs = [Agent(name="el") for t in [Agent(name="first")] for u in [Agent(name="second")]]\n'
    )
    assert sorted((s.name, s.in_loop) for s in sites) == [
        ("el", True), ("els", False), ("first", False), ("it", False), ("second", True),
    ]


def test_subscripted_generic_base_class_is_an_agent_definition():
    sites = _sites("class Writer(BaseAgent[Ctx]):\n    pass\n")
    assert [(s.role, s.kind, s.name) for s in sites] == [("definition", "subclass", "Writer")]


def test_keyword_unpacking_without_tools_means_tools_are_unknown():
    sites = _sites('a = Agent(name="a", **cfg)\nclass W(BaseAgent):\n    pass\nw = W(**cfg)\nb = Agent(name="b", tools=[t], **cfg)\n')
    assert [(s.name, s.tool_refs) for s in sites] == [("a", None), ("W", None), ("W", None), ("b", ("t",))]


def test_a_crewai_config_constructor_without_tools_has_unknown_tools():
    # The agents.yaml entry may list the tools; the resolver inherits them (plan clarification 13).
    (site,) = _sites("r = Agent(config=self.agents_config['r'])\n")
    assert site.instructions == InstructionsRef("config", "r")
    assert site.tool_refs is None
