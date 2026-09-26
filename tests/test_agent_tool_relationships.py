from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor


def test_scan_links_agent_to_explicitly_configured_tool(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from framework import Agent, tool\n"
        "@tool\n"
        "def lookup_customer():\n"
        "    return None\n"
        "researcher = Agent(name='researcher', tools=[lookup_customer])\n"
    )
    config = ScannerConfig(
        enabled_scanners=["agent_instance", "tool_definition"],
        no_llm=True,
        vuln_check_enabled=False,
    )

    report = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), config, verbose=False)

    assert [edge.to_dict() for edge in report.agent_tool_relationships] == [{
        "agent_name": "researcher",
        "tool_name": "lookup_customer",
        "source_file": "agent.py",
        "line_number": 5,
        "tool_source_file": "agent.py",
        "tool_line_number": 2,
        "evidence": "explicit_tools_argument",
    }]


def test_scan_links_imported_tool_definition_in_another_file(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from framework import Agent\n"
        "from tools import lookup_customer\n"
        "researcher = Agent(name='researcher', tools=[lookup_customer])\n"
    )
    (tmp_path / "tools.py").write_text(
        "from framework import tool\n"
        "@tool\n"
        "def lookup_customer():\n"
        "    return None\n"
    )
    config = ScannerConfig(
        enabled_scanners=["agent_instance", "tool_definition"],
        no_llm=True,
        vuln_check_enabled=False,
    )

    report = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), config, verbose=False)

    assert [edge.to_dict() for edge in report.agent_tool_relationships] == [{
        "agent_name": "researcher",
        "tool_name": "lookup_customer",
        "source_file": "agent.py",
        "line_number": 3,
        "tool_source_file": "tools.py",
        "tool_line_number": 2,
        "evidence": "explicit_tools_argument",
    }]


def test_scan_links_javascript_agent_object_tool_reference(tmp_path):
    (tmp_path / "agent.ts").write_text(
        'const researcher = new Agent({ name: "researcher", tools: [lookup_customer] });\n'
    )
    config = ScannerConfig(
        enabled_scanners=["agent_instance", "tool_definition"],
        no_llm=True,
        vuln_check_enabled=False,
    )

    report = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), config, verbose=False)

    assert [edge.to_dict() for edge in report.agent_tool_relationships] == [{
        "agent_name": "researcher",
        "tool_name": "lookup_customer",
        "source_file": "agent.ts",
        "line_number": 1,
        "tool_source_file": "",
        "tool_line_number": None,
        "evidence": "explicit_tools_argument",
    }]
