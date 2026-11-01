"""End to end: the report's agents, tools and relationships come from the inventory."""
from __future__ import annotations

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
    """Static signals cite instance sites; they are not validated against finding paths."""
    report = _scan(tmp_path, {
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/admin.py": "from fw import Agent\nfrom ops import shell_exec\n"
                        "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
    })
    (signal,) = report.agents[0].risk_signals
    assert [r.file_path for r in signal.evidence_refs] == ["src/a.py", "src/admin.py"]


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
    report = _scan(tmp_path, {"src/a.py": "r = Agent(name='researcher')\n"})
    assert [(a.id, a.name) for a in report.agents] == [("agent:@src/a.py#1", "researcher")]
    assert report.metadata["inventory_error"] == "RuntimeError: boom"


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
