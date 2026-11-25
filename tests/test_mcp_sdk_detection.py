"""A repository that builds on the MCP SDK is recognised (issue #71).

Since schema 1.1 the servers it implements are listed in `mcp_servers` with `source: code`
(tests/test_mcp_code_servers.py).
"""
from __future__ import annotations

import json

from click.testing import CliRunner

from quin_scanner.cli import cli


def _scan(tmp_path, files: dict[str, str]) -> dict:
    repo = tmp_path / "repo"
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    out = tmp_path / "report.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


PY_SERVER = {
    "pyproject.toml": '[project]\nname = "demo-server"\nversion = "0.1.0"\ndependencies = ["mcp>=1.0.0"]\n',
    "server.py": 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("demo")\n\n@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n',
}
TS_SERVER = {
    "package.json": '{"name": "demo-server", "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}\n',
    "src/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n\nconst server = new McpServer({ name: "demo", version: "1.0.0" });\n',
}


def test_a_python_mcp_server_project_is_recognised(tmp_path):
    report = _scan(tmp_path, PY_SERVER)
    assert report["is_ai_application"] is True
    assert "tool-use" in report["capability_tags"]


def test_a_typescript_mcp_server_project_is_recognised(tmp_path):
    report = _scan(tmp_path, TS_SERVER)
    assert report["is_ai_application"] is True
    assert "tool-use" in report["capability_tags"]


def test_implemented_servers_are_listed_apart_from_configured_servers(tmp_path):
    # Schema 1.1: an implemented server is an mcp_servers entry with source "code", never a configured one.
    for name, files in (("py", PY_SERVER), ("ts", TS_SERVER)):
        (tmp_path / name).mkdir()
        servers = _scan(tmp_path / name, files)["mcp_servers"]
        assert [(s["name"], s["source"]) for s in servers] == [("demo", "code")]


def test_depending_on_the_sdk_does_not_name_a_framework(tmp_path):
    # An MCP client or a multi-agent system that also ships an MCP server is not "an MCP framework".
    assert _scan(tmp_path, PY_SERVER)["framework"] == "unknown"


def test_an_application_built_on_another_framework_keeps_it(tmp_path):
    files = {
        "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["langgraph>=0.2", "mcp>=1.0.0"]\n',
        "app.py": "from mcp import ClientSession\nfrom langgraph.graph import StateGraph\n",
    }
    assert _scan(tmp_path, files)["framework"].split()[0] == "LangGraph"
