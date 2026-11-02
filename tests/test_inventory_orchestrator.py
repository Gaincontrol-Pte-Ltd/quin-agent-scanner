"""End to end: the report's agents, tools and relationships come from the inventory."""
from __future__ import annotations

import json

from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor


def _scan(tmp_path, files: dict[str, str], **config):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    settings = {"enabled_scanners": ["agent_instance", "tool_definition"], "no_llm": True, "vuln_check_enabled": False}
    settings.update(config)
    return ScanOrchestrator().run(LocalRepoAccessor(tmp_path), ScannerConfig(**settings), verbose=False)


def test_static_scan_reports_agents_with_instances(tmp_path):
    report = _scan(tmp_path, {
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/admin.py": "from fw import Agent\nfrom ops import shell_exec\n"
                        "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
        "tests/test_a.py": "r = Agent(name='researcher', instructions='Find.', tools=[])\n",
    })
    (agent,) = report.agents
    assert (agent.id, agent.scope, agent.flags) == ("agent:researcher", "production", ["tool_divergence"])
    assert [i.file for i in agent.instances] == ["src/a.py", "src/admin.py", "tests/test_a.py"]
    assert [s.threat_id for s in agent.risk_signals] == ["T006"]
    assert [t.id for t in report.tool_usages] == ["tool:search"]
    assert report.llm_inferred_agents == [] and report.llm_inferred_tools == []


def test_static_t006_evidence_refs_survive_files_without_findings(tmp_path):
    """Static signals cite instance sites; they are not validated against finding paths.

    The CrewAI call in other.py has no name= and passes no tools, so no scanner reports a finding there,
    yet it is an instance of the YAML agent and the T006 signal cites it.
    """
    report = _scan(tmp_path, {
        "src/p/config/agents.yaml": "writer:\n  role: Writer\n  goal: Write\n  backstory: b\n",
        "src/p/crew.py": "from crewai import Agent\nclass C:\n    def w(self):\n"
                         "        return Agent(config=self.agents_config['writer'], tools=[search])\n",
        "src/p/other.py": "from crewai import Agent\nclass D:\n    def w(self):\n"
                          "        return Agent(config=self.agents_config['writer'], tools=[])\n",
    })
    assert "src/p/other.py" not in {f.file_path for f in report.artifacts}
    (agent,) = report.agents
    (signal,) = agent.risk_signals
    assert [(r.file_path, r.line_number) for r in signal.evidence_refs] == [("src/p/crew.py", 4), ("src/p/other.py", 4)]


def test_agent_skills_are_instance_tools_linked_to_a_skill(tmp_path):
    report = _scan(tmp_path, {
        ".claude/skills/x/SKILL.md": "---\nname: x\ndescription: Does x.\n---\n# X\n",
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='a', tools=['x', search])\n",
    }, enabled_scanners=["agent_instance", "tool_definition", "skills"])
    (agent,) = report.agents
    assert (agent.skills, agent.tools, agent.provenance.get("skills")) == (["x"], ["search"], "static")
    # Instance tools and relationships are unchanged: the skill is still a linked tool of the instance.
    assert [(t.name, t.tool_id) for t in agent.instances[0].tools] == [("x", "tool:x"), ("search", "tool:search")]
    assert sorted(e.tool_name for e in report.agent_tool_relationships) == ["search", "x"]


def test_no_cap_on_agents(tmp_path):
    source = "".join(f"a{i} = Agent(name='agent{i}')\n" for i in range(60))
    report = _scan(tmp_path, {"src/many.py": source})
    assert len(report.agents) == 60


def test_relationships_come_from_the_inventory(tmp_path):
    report = _scan(tmp_path, {
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='researcher', tools=[search])\n",
    })
    (edge,) = report.agent_tool_relationships
    assert (edge.agent_id, edge.instance_id, edge.tool_id) == (
        "agent:researcher", "agent:researcher/src/a.py#1", "tool:search",
    )


def test_an_inventory_error_does_not_lose_the_report(tmp_path, monkeypatch):
    import quin_scanner.orchestrator as orchestrator

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(orchestrator, "resolve_inventory", broken)
    report = _scan(tmp_path, {
        "src/a.py": "r = Agent(name='researcher')\n",
        ".claude/skills/x/SKILL.md": "---\nname: x\ndescription: Does x.\n---\n# X\n",
        "requirements.txt": "chromadb==0.4.0\n",
    }, enabled_scanners=["agent_instance", "tool_definition", "skills", "dependency"])
    assert [(a.id, a.name) for a in report.agents] == [("agent:@src/a.py#1", "researcher")]
    assert report.metadata["inventory_error"] == "RuntimeError: boom"
    # Skills and external services never depended on the resolver, so they survive its failure.
    assert [(t.id, t.tool_type, t.scope) for t in report.tool_usages] == [
        ("tool:chromadb", "external_service", "production"), ("tool:x", "skill", "production"),
    ]


def test_an_evidence_error_does_not_lose_the_report(tmp_path, monkeypatch):
    from quin_scanner.scanners.tool_definition_scanner import ToolDefinitionScanner

    def broken(self):
        raise RuntimeError("bad evidence")

    monkeypatch.setattr(ToolDefinitionScanner, "evidence", broken)
    report = _scan(tmp_path, {"src/a.py": "r = Agent(name='researcher')\n"})
    assert [a.id for a in report.agents] == ["agent:@src/a.py#1"]
    assert report.metadata["inventory_error"] == "RuntimeError: bad evidence"


class _SynthesisStub:
    """Answers every prompt with a synthesis that invents an agent and a tool and cites a file nobody scanned."""

    def generate(self, prompt):
        import json
        return json.dumps({
            "is_ai_application": True,
            "framework": "unknown",
            "summary": "stub",
            "risk_signals": [{
                "signal": "repo-level", "threat_id": "T001", "recommended_controls": [],
                "evidence_refs": [{"file_path": "invented.py", "line_number": 1, "scanner": "X"},
                                  {"file_path": "src/a.py", "line_number": 5, "scanner": "AgentInstanceScanner"}],
            }],
            "agents": [{"name": "phantom", "agent_type": "worker", "goal": "", "tools": ["gpt-4o"]}],
            "tool_usages": [{"tool_name": "phantom_tool", "tool_type": "tool_definition"}],
        })


def test_llm_scan_still_reports_the_inventory(tmp_path, monkeypatch):
    stub = _SynthesisStub()
    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: stub)
    report = _scan(tmp_path, {
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='researcher', tools=[search])\n",
    }, no_llm=False)
    assert [a.id for a in report.agents] == ["agent:researcher"]
    assert [t.id for t in report.tool_usages] == ["tool:search"]
    assert [e.instance_id for e in report.agent_tool_relationships] == ["agent:researcher/src/a.py#1"]
    (signal,) = [s for s in report.risk_signals if s.signal == "repo-level"]
    assert [r.file_path for r in signal.evidence_refs] == ["src/a.py"]  # LLM refs are still validated


def test_the_llm_enriches_by_id_and_cannot_change_the_inventory(tmp_path, monkeypatch):
    prompts: list[str] = []
    synthesis = {
        "is_ai_application": True, "framework": "x", "summary": "s",
        "enrichment": {
            "agent:researcher": {"agent_type": "worker", "goal": "Finds facts", "capabilities": ["search"]},
            "agent:ghost": {"goal": "invented"},
        },
        "tool_enrichment": {"tool:search": {"service_category": "web_search"}},
        "suggested_agents": [{"name": "planner", "evidence": "factory", "file": "src/a.py"}],
        "agents": [{"name": "invented"}],
    }

    class Stub:
        def generate(self, prompt):
            prompts.append(prompt)
            if "--- AGENT INVENTORY" in prompt:
                return json.dumps(synthesis)
            return '{"system_types": ["agentic_ai"], "relevant_threats": []}'

    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: Stub())
    report = _scan(
        tmp_path,
        {"src/a.py": "@tool\ndef search():\n    pass\nr = Agent(name='researcher', tools=[search])\n"},
        no_llm=False, llm_provider="openai", llm_api_key="x",
    )
    (agent,) = report.agents
    assert (agent.id, agent.goal, agent.agent_type, agent.capabilities) == (
        "agent:researcher", "Finds facts", "worker", ["search"],
    )
    assert agent.provenance == {
        "name": "static", "tools": "static", "agent_type": "llm", "goal": "llm", "capabilities": "llm",
    }
    assert report.tool_usages[0].service_category == "web_search"
    assert report.metadata["llm_unknown_ids"] == 1
    assert [i.name for i in report.llm_inferred_agents] == ["planner"]
    assert "id=agent:researcher" in next(p for p in prompts if "--- AGENT INVENTORY" in p)


def test_enrichment_never_overwrites_static_facts():
    from quin_scanner.models import (
        AgentEnrichment, AgentProfile, EvidenceRef, RiskIndicator, SynthesisResult, ToolUsage,
    )
    from quin_scanner.orchestrator import _apply_enrichment

    static_signal = RiskIndicator(signal="T006", recommended_controls=[], threat_id="T006",
                                  evidence_refs=[EvidenceRef(file_path="no_finding.py", line_number=1)])
    agent = AgentProfile(name="r", agent_type="unknown", goal="", id="agent:r", tools=["search"],
                         risk_signals=[static_signal], provenance={"name": "static", "tools": "static", "goal": "static"})
    agent.goal = "From YAML"
    tools = [ToolUsage(tool_name="search", tool_type="tool_definition", service_category="", id="tool:search"),
             ToolUsage(tool_name="api", tool_type="external_service", service_category="api_integration", id="tool:api")]
    llm_signal = RiskIndicator(signal="llm", recommended_controls=[], threat_id="T001",
                               evidence_refs=[EvidenceRef(file_path="invented.py"), EvidenceRef(file_path="src/a.py")])
    synthesis = SynthesisResult(
        is_ai_application=True, framework="x", summary="",
        enrichment={"agent:r": AgentEnrichment(agent_type="worker", goal="LLM goal", capabilities=[],
                                               risk_signals=[llm_signal])},
        tool_enrichment={"tool:search": "web_search", "tool:api": "database", "tool:ghost": "other"},
    )
    listed = ({"agent:r"}, {"tool:search", "tool:api"})
    assert _apply_enrichment([agent], tools, synthesis, {"src/a.py"}, *listed) == (1, 0)
    assert (agent.name, agent.tools, agent.goal, agent.agent_type, agent.capabilities) == (
        "r", ["search"], "From YAML", "worker", [],
    )
    assert agent.provenance == {
        "name": "static", "tools": "static", "goal": "static", "agent_type": "llm", "risk_signals": "mixed",
    }
    assert agent.risk_signals == [static_signal, llm_signal]
    assert [r.file_path for r in static_signal.evidence_refs] == ["no_finding.py"]
    assert [r.file_path for r in llm_signal.evidence_refs] == ["src/a.py"]
    assert [t.service_category for t in tools] == ["web_search", "api_integration"]


def test_agents_beyond_the_llm_cap_are_counted_as_unenriched(tmp_path, monkeypatch):
    prompts: list[str] = []

    class Stub:
        def generate(self, prompt):
            prompts.append(prompt)
            return '{"is_ai_application": true, "framework": "x", "summary": "s"}'

    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: Stub())
    code = "".join(f"a{i:02d} = Agent(name='agent{i:02d}')\n" for i in range(32))
    report = _scan(tmp_path, {"src/a.py": code}, no_llm=False)
    assert len(report.agents) == 32
    assert report.metadata["llm_unenriched_agents"] == 2
    synthesis_prompt = next(p for p in prompts if "--- AGENT INVENTORY" in p)
    assert "id=agent:agent29" in synthesis_prompt and "id=agent:agent30" not in synthesis_prompt


def _routing_stub(synthesis: dict, prompts: list[str]):
    class Stub:
        def generate(self, prompt):
            prompts.append(prompt)
            if "--- AGENT INVENTORY" in prompt:
                return json.dumps(synthesis)
            return '{"system_types": ["agentic_ai"], "relevant_threats": []}'
    return Stub()


def test_enrichment_of_items_not_listed_to_the_llm_is_ignored(tmp_path, monkeypatch):
    synthesis = {
        "is_ai_application": True, "framework": "x", "summary": "s",
        "enrichment": {"agent:p31": {"goal": "beyond the cap"}, "agent:p00": {"goal": "listed"},
                       "agent:ghost": {"goal": "invented"}},
        "tool_enrichment": {"tool:t31": {"service_category": "web_search"},
                            "tool:t00": {"service_category": "database"}},
    }
    prompts: list[str] = []
    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: _routing_stub(synthesis, prompts))
    tools = "".join(f"@tool\ndef t{i:02d}():\n    pass\n" for i in range(32))
    agents = "".join(f"a{i:02d} = Agent(name='p{i:02d}')\n" for i in range(32))
    report = _scan(tmp_path, {"src/t.py": tools, "src/a.py": agents}, no_llm=False)
    goals = {a.id: a.goal for a in report.agents}
    assert goals["agent:p00"] == "listed" and goals["agent:p31"] == ""
    categories = {t.id: t.service_category for t in report.tool_usages}
    assert categories["tool:t00"] == "database" and categories["tool:t31"] == ""
    assert report.metadata["llm_unknown_ids"] == 1
    assert report.metadata["llm_unlisted_ids"] == 2
    assert report.metadata["llm_unenriched_agents"] == 2
    assert report.metadata["llm_unlisted_tools"] == 2


def test_the_llm_sees_production_agents_first(tmp_path, monkeypatch):
    prompts: list[str] = []
    synthesis = {"is_ai_application": True, "framework": "x", "summary": "s",
                 "enrichment": {"agent:aaa": {"goal": "a test agent"}}}
    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: _routing_stub(synthesis, prompts))
    agents = "".join(f"a{i:02d} = Agent(name='p{i:02d}')\n" for i in range(30))
    report = _scan(tmp_path, {"src/a.py": agents, "tests/test_a.py": "x = Agent(name='aaa')\n"}, no_llm=False)
    prompt = next(p for p in prompts if "--- AGENT INVENTORY" in p)
    assert "id=agent:p29" in prompt and "id=agent:aaa" not in prompt
    assert {a.id: a.goal for a in report.agents}["agent:aaa"] == ""
    assert report.metadata["llm_unlisted_ids"] == 1


def test_the_llm_sees_the_final_tool_type(tmp_path, monkeypatch):
    prompts: list[str] = []
    synthesis = {"is_ai_application": True, "framework": "x", "summary": "s"}
    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: _routing_stub(synthesis, prompts))
    report = _scan(tmp_path, {
        ".mcp.json": '{"mcpServers": {"github": {"command": "npx"}}}',
        "src/a.py": "@tool\ndef github():\n    pass\nr = Agent(name='r', tools=[github])\n",
    }, no_llm=False, enabled_scanners=["agent_instance", "tool_definition", "mcp"])
    assert [(t.id, t.tool_type) for t in report.tool_usages if t.tool_name == "github"] == [("tool:github", "mcp_tool")]
    prompt = next(p for p in prompts if "--- AGENT INVENTORY" in p)
    assert 'name="github" type=mcp_tool' in prompt


def test_digest_lists_skills_and_uncategorised_tools_first():
    from quin_scanner.inventory import Inventory
    from quin_scanner.models import AgentProfile, ToolUsage
    from quin_scanner.orchestrator import _inventory_digest

    agent = AgentProfile(name="r", agent_type="unknown", goal="", id="agent:r", tools=["search"], skills=["x"])
    tools = [ToolUsage(tool_name=f"c{i:02d}", tool_type="external_service", service_category="database",
                       id=f"tool:c{i:02d}") for i in range(30)]
    tools.append(ToolUsage(tool_name="zz", tool_type="tool_definition", service_category="", id="tool:zz"))
    digest = _inventory_digest(Inventory(agents=[agent], tools=tools))
    assert digest.agents[0]["skills"] == ["x"]
    assert digest.tools[0]["id"] == "tool:zz"
    assert "tool:zz" in digest.tool_ids and "tool:c29" not in digest.tool_ids
    assert (digest.unlisted_agents, digest.unlisted_tools) == (0, 1)


def test_html_report_renders_instances_flags_and_unverified_suggestions(tmp_path):
    from quin_scanner.models import LLMInferredItem
    from quin_scanner.report import ReportGenerator

    report = _scan(tmp_path, {
        "src/a.py": "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/b.py": "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
    })
    report.llm_inferred_agents = [LLMInferredItem(name="planner", evidence="factory", file="src/a.py")]
    html = ReportGenerator.to_html(report)
    assert "inst-table" in html
    assert "inst-diff" in html
    assert "Suggested by the LLM" in html
    assert '"llm_inferred_agents"' in html and "planner" in html
    # data-dependent: the scanned agent id and instance files are embedded, and "planner" only because it was set
    agent = next(a for a in report.agents if a.name == "researcher")
    assert agent.id in html
    assert all(i.file in html for i in agent.instances) and len(agent.instances) == 2
    report.llm_inferred_agents = []
    assert "planner" not in ReportGenerator.to_html(report)


def test_production_tool_divergence_reaches_sarif(tmp_path):
    from quin_scanner.report import ReportGenerator

    report = _scan(tmp_path, {
        "src/a.py": "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/b.py": "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
    })
    sarif = json.loads(ReportGenerator.to_sarif(report))
    assert "T006" in [result["ruleId"] for result in sarif["runs"][0]["results"]]


def test_risk_signal_provenance_is_llm_mixed_or_static():
    from quin_scanner.models import AgentEnrichment, AgentProfile, RiskIndicator, SynthesisResult
    from quin_scanner.orchestrator import _apply_enrichment

    def signal(threat):
        return RiskIndicator(signal=threat, recommended_controls=[], threat_id=threat)

    plain = AgentProfile(name="p", agent_type="unknown", goal="", id="agent:p", provenance={"name": "static"})
    static_only = AgentProfile(name="s", agent_type="unknown", goal="", id="agent:s", risk_signals=[signal("T006")],
                               provenance={"name": "static", "risk_signals": "static"})
    both = AgentProfile(name="b", agent_type="unknown", goal="", id="agent:b", risk_signals=[signal("T006")],
                        provenance={"name": "static", "risk_signals": "static"})
    synthesis = SynthesisResult(
        is_ai_application=True, framework="x", summary="",
        enrichment={
            "agent:p": AgentEnrichment(risk_signals=[signal("T001")]),
            "agent:s": AgentEnrichment(goal="g"),
            "agent:b": AgentEnrichment(risk_signals=[signal("T002")]),
        },
    )
    _apply_enrichment([plain, static_only, both], [], synthesis, set(), {"agent:p", "agent:s", "agent:b"}, set())
    assert [a.provenance.get("risk_signals") for a in (plain, static_only, both)] == ["llm", "static", "mixed"]
