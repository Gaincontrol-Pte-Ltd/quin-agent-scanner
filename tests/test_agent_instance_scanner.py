"""AgentInstanceScanner: agent names come from real constructor arguments, not from text inside strings."""
from __future__ import annotations

import pytest

from quin_scanner.file_index import FileIndex
from quin_scanner.inventory import python_sites
from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.agent_instance_scanner import AgentInstanceScanner
from quin_scanner.scanners.base import EvidenceProducer


def _names(tmp_path, source: str, filename: str = "agents.py") -> list[str]:
    (tmp_path / filename).write_text(source, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return sorted(f.match_text for f in AgentInstanceScanner().scan(accessor, index))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('agent = Agent(name="researcher")\n', ["researcher"]),
        ('agent = Agent(\n    model=m,\n    name="researcher",\n    tools=[],\n)\n', ["researcher"]),
        ("agent = Agent(name='single')\n", ["single"]),
        ('a = autogen.AssistantAgent(name="x")\nb = agents.Agent(name="y")\n', ["x", "y"]),
        ('a = UserProxyAgent(name="user")\nb = ConversableAgent(name="c")\n', ["c", "user"]),
        ('graph = create_react_agent(model, tools, name="react")\n', ["react"]),
        ('agent = Agent(name="boss", tools=[Tool(name="search")])\n', ["boss"]),
        ('agent = FoundryAgent(agent_name="my-prompt-agent", agent_version="1.0")\n', ["my-prompt-agent"]),
    ],
)
def test_keyword_names_are_found(tmp_path, source, expected):
    assert _names(tmp_path, source) == expected


@pytest.mark.parametrize(
    "source",
    [
        # issue #70: text inside a string argument is not an argument
        'agent = Agent(task="""\n  1. Fill the form:\n   - Customer name: "Alice Johnson"\n""")\n',
        "agent = Agent(task=\"\"\"Use fill_field with vault_name='prod-secrets' and item_name='X'\"\"\")\n",
        # a nested call's name is not the agent's
        'agent = Agent(tools=[Tool(name="search")])\n',
        # the tail of another keyword is not `name`
        'results = evaluate_agent(agent=agent, eval_name="claw-step04-production-ready")\n',
        # not a literal
        'agent = Agent(name=NAME)\nb = Agent(name=f"agent_{i}")\n',
        # the first positional argument of a bare Agent(...) is a task or a model, not a name
        "Agent('Find the founders of browser-use').run()\n",
        "agent = Agent('openai:gpt-4o', system_prompt='Be brief.')\n",
    ],
)
def test_text_that_is_not_a_name_argument_is_not_an_agent(tmp_path, source):
    assert _names(tmp_path, source) == []


def test_a_positional_name_is_kept_for_classes_that_take_the_name_first(tmp_path):
    source = 'a = AssistantAgent("assistant", model_client=client)\nb = UserProxyAgent("user")\n'
    assert _names(tmp_path, source) == ["assistant", "user"]


def test_decorated_and_subclassed_agents_are_still_found(tmp_path):
    source = "@agent\ndef planner():\n    pass\n\nclass Writer(BaseAgent):\n    pass\n"
    assert _names(tmp_path, source) == ["Writer", "planner"]


def test_a_file_that_does_not_parse_still_gets_anchored_matching(tmp_path):
    source = 'agent = Agent(name="ok",\nthis is not python (\nb = Agent(task="vault_name=\'nope\'")\n'
    assert _names(tmp_path, source) == ["ok"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('const a = new Agent({ name: "triage", instructions: "x" });\n', ["triage"]),
        ('const a = new Agent({ instructions: "Look up vault_name: \'secret\'" });\n', []),
    ],
)
def test_typescript_names(tmp_path, source, expected):
    assert _names(tmp_path, source, "agents.ts") == expected


def test_findings_keep_their_line_numbers(tmp_path):
    (tmp_path / "a.py").write_text('x = 1\n\nagent = Agent(\n    name="late",\n)\n', encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    (finding,) = AgentInstanceScanner().scan(accessor, index)
    assert (finding.match_text, finding.line_number) == ("late", 3)


# --- Workflow graphs in YAML (issue #72) --------------------------------------------------------------------------

WORKFLOW = """\
graph:
  id: Demo
  nodes:
    - id: Counter
      type: loop_counter
      config: {max_iterations: 3}
    - id: Programmer Code Review
      type: agent
      config:
        name: gpt-4o
        role: You are Programmer.
    - id: Reviewer
      type: agent
      config: {name: gpt-4o}
    - id: FINAL
      type: passthrough
  edges: []
"""


def test_agent_nodes_of_a_workflow_graph_are_agents_whatever_the_file_is_called(tmp_path):
    names = _names(tmp_path, WORKFLOW, "ChatDev_v1.yaml")
    assert names == ["Programmer Code Review", "Reviewer"]  # the node ids, not the model name or other node types


def test_a_workflow_graph_with_no_agent_nodes_has_no_agents(tmp_path):
    source = WORKFLOW.replace("type: agent", "type: passthrough")
    assert _names(tmp_path, source, "flow.yml") == []


@pytest.mark.parametrize(
    "source",
    [
        "type: agent\nname: not-a-graph\n",  # no nodes
        "steps:\n  - id: a\n    type: agent\n",  # not graph.nodes
        "graph:\n  nodes: not-a-list\n  type: agent\n",
        "graph: [unbalanced\n  nodes:\n    type: agent\n",  # invalid YAML
    ],
)
def test_yaml_that_is_not_a_workflow_graph_is_ignored(tmp_path, source):
    assert _names(tmp_path, source, "other.yaml") == []


def test_a_very_large_yaml_file_is_not_parsed(tmp_path):
    filler = "# " + "x" * 80 + "\n"
    source = WORKFLOW + filler * 8000  # well over the size limit
    assert _names(tmp_path, source, "huge.yaml") == []


def test_agents_yaml_and_flow_dag_keep_their_own_parsers(tmp_path):
    (tmp_path / "flow.dag.yaml").write_text("nodes:\n  - name: planner\n    type: llm\n", encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    assert [f.match_text for f in AgentInstanceScanner().scan(accessor, index)] == ["planner"]


# --- typed evidence for the inventory ---------------------------------------------------------------------------


def _evidence(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    scanner = AgentInstanceScanner()
    findings = scanner.scan(accessor, index)
    return findings, scanner.evidence()


def test_scanner_is_an_evidence_producer():
    assert isinstance(AgentInstanceScanner(), EvidenceProducer)


def test_python_evidence_carries_instance_details(tmp_path):
    findings, sites = _evidence(tmp_path, {"app.py": 'a = Agent(name="r", instructions="x", tools=[s])\n'})
    assert [f.match_text for f in findings] == ["r"]
    (site,) = sites
    assert (site.name, site.file_path, site.tool_refs) == ("r", "app.py", ("s",))


def test_test_files_give_evidence_but_no_findings(tmp_path):
    findings, sites = _evidence(tmp_path, {"tests/test_app.py": 'a = Agent(name="r")\n'})
    assert findings == []
    assert [(s.name, s.file_path) for s in sites] == [("r", "tests/test_app.py")]


def test_crew_yaml_entries_are_config_definitions(tmp_path):
    _, sites = _evidence(tmp_path, {"config/agents.yaml": "researcher:\n  role: Senior Researcher\n  goal: g\n"})
    (site,) = sites
    assert (site.role, site.kind, site.name, site.instructions) == (
        "definition", "config_entry", "Senior Researcher", InstructionsRef("config", "researcher"),
    )


def test_adk_root_agent_details(tmp_path):
    source = (
        "name: root\nmodel: gemini-2.0-flash\ninstruction: Help.\n"
        "tools:\n  - name: google_search\nsub_agents:\n  - name: helper\n"
    )
    _, sites = _evidence(tmp_path, {"root_agent.yaml": source})
    helper, root = sorted(sites, key=lambda s: s.name)
    assert (root.model_expr, root.tool_refs, root.instructions) == (
        "gemini-2.0-flash", ("google_search",), InstructionsRef.literal("Help."),
    )
    assert helper.tool_refs is None


def test_unparseable_python_falls_back_to_regex_sites(tmp_path):
    _, sites = _evidence(tmp_path, {"bad.py": 'agent = Agent(name="ok",\nthis is not python (\n'})
    assert [(s.name, s.tool_refs, s.instructions) for s in sites] == [("ok", None, NO_INSTRUCTIONS)]


def test_typescript_evidence(tmp_path):
    _, sites = _evidence(tmp_path, {"a.ts": 'const a = new Agent({ name: "triage", tools: [x] });\n'})
    assert [(s.name, s.tool_refs) for s in sites] == [("triage", ("x",))]


def test_workflow_graph_and_markdown_specs(tmp_path):
    _, sites = _evidence(tmp_path, {"flow.yaml": WORKFLOW, "agents/research.md": "# Research Agent\n**Role:** Researcher\n"})
    assert sorted((s.kind, s.name) for s in sites) == [
        ("config_entry", "Research Agent"),
        ("graph_node", "Programmer Code Review"),
        ("graph_node", "Reviewer"),
    ]


def test_evidence_failure_never_costs_a_file_its_findings(tmp_path, monkeypatch):
    def boom(tree, path):
        raise RuntimeError("evidence extraction failed")

    monkeypatch.setattr(python_sites, "agent_sites", boom)
    findings, sites = _evidence(tmp_path, {"app.py": 'a = Agent(name="r")\n'})
    assert [f.match_text for f in findings] == ["r"]
    assert sites == []
