"""ToolDefinitionScanner: typed tool sites for the inventory (definitions only)."""
from __future__ import annotations

from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.tool_definition_scanner import ToolDefinitionScanner


def _scan(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    scanner = ToolDefinitionScanner()
    findings = scanner.scan(accessor, index)
    return findings, scanner.evidence()


def test_decorated_tools_and_classes_are_tool_sites(tmp_path):
    _, sites = _scan(tmp_path, {"tools.py": "@tool\ndef search():\n    pass\n\nclass Calc(BaseTool):\n    pass\n"})
    assert [(s.name, s.kind, s.line) for s in sites] == [("search", "@tool", 1), ("Calc", "BaseTool", 5)]


def test_tools_list_references_are_findings_but_not_definitions(tmp_path):
    findings, sites = _scan(tmp_path, {"app.py": "a = Agent(name='a', tools=[search, fetch])\n"})
    assert sorted(f.match_text for f in findings) == ["fetch", "search"]
    assert sites == []


def test_test_files_give_tool_sites_but_no_findings(tmp_path):
    findings, sites = _scan(tmp_path, {"tests/test_tools.py": "@tool\ndef fake():\n    pass\n"})
    assert findings == []
    assert [(s.name, s.file_path) for s in sites] == [("fake", "tests/test_tools.py")]


def test_tools_yaml_entries(tmp_path):
    _, sites = _scan(tmp_path, {"tools.yaml": "tools:\n  - name: lookup\n"})
    assert [(s.name, s.kind, s.line) for s in sites] == [("lookup", "config", None)]


def test_flow_dag_nodes_are_graph_nodes(tmp_path):
    _, sites = _scan(tmp_path, {"flow.dag.yaml": "nodes:\n  - name: step\n    type: python_func\n"})
    assert [(s.name, s.kind, s.line) for s in sites] == [("step", "graph_node", None)]


def test_label_mapping_for_tools_dir_and_agent_spec(tmp_path):
    _, sites = _scan(tmp_path, {
        "tools/helpers.py": "def fetch_page(url):\n    pass\n",
        "agents/a.md": "# A\n\n## Tools Required\n- web search\n",
    })
    assert sorted((s.name, s.kind) for s in sites) == [("fetch_page", "function"), ("web search", "agent_spec")]


def test_yaml_tool_name_that_looks_like_a_label_stays_a_config_name(tmp_path):
    _, sites = _scan(tmp_path, {"tools.yaml": "tools:\n  - name: 'lookup (v2)'\n"})
    assert [(s.name, s.kind) for s in sites] == [("lookup (v2)", "config")]


def test_site_names_carry_no_credentials(tmp_path):
    secret = "sk-" + "a" * 30
    _, sites = _scan(tmp_path, {"tools.yaml": f"tools:\n  - name: {secret}\n"})
    assert sites and all(secret not in s.name for s in sites)


def test_evidence_is_sorted_by_location(tmp_path):
    _, sites = _scan(tmp_path, {
        "b.py": "@tool\ndef z():\n    pass\n",
        "a.py": "@tool\ndef y():\n    pass\n\n@tool\ndef x():\n    pass\n",
    })
    assert [(s.file_path, s.name) for s in sites] == [("a.py", "y"), ("a.py", "x"), ("b.py", "z")]


def test_evidence_failure_never_costs_a_file_its_findings(tmp_path, monkeypatch):
    def boom(self, found, kind):
        raise RuntimeError("evidence extraction failed")

    monkeypatch.setattr(ToolDefinitionScanner, "_sites_from", boom)
    findings, sites = _scan(tmp_path, {"t.py": "@tool\ndef search():\n    pass\n"})
    assert [f.match_text for f in findings] == ["search (@tool)"]
    assert sites == []
