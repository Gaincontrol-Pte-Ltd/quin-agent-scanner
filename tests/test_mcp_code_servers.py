"""MCP servers implemented in the repository are listed in `mcp_servers` with `source: code` (#71, schema 1.1).

Python is parsed with `ast`; TypeScript/JavaScript is read skipping comments and strings. The shapes mirror
modelcontextprotocol/servers (`MCPServer` / `FastMCP` with `@server.tool`, `new McpServer` with `registerTool`, tools
registered in other files on a server passed in) and the low-level servers of browser-use and Microsoft Agent Framework.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.file_index import FileIndex
from quin_scanner.inventory.mcp_sites import mcp_sites
from quin_scanner.models import MCPServer, ScanReport
from quin_scanner.report import ReportGenerator
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.mcp_scanner import discover_implemented_mcp_servers


def _py(code: str, path: str = "server.py"):
    servers, loose = mcp_sites(code, path)
    return {(s.name, s.sdk): sorted(t.name for t in s.tools) for s in servers}, loose


def _ts(code: str, path: str = "src/index.ts"):
    servers, loose = mcp_sites(code, path)
    return {s.name: sorted(t.name for t in s.tools) for s in servers}, loose


def _discover(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return discover_implemented_mcp_servers(accessor, index)


# ── Python: high-level servers ───────────────────────────────────────────────────────────────────────────────────────

def test_fastmcp_with_positional_name_and_its_decorated_tools():
    servers, loose = _py(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "@mcp.tool()\ndef add(a, b):\n    return a + b\n"
        "@mcp.tool\nasync def ping():\n    return 'pong'\n"
        "@mcp.tool(name='sub')\ndef subtract(a, b):\n    return a - b\n"
        "@mcp.resource('x://y')\ndef res():\n    return ''\n"
    )
    assert servers == {("demo", "mcp"): ["add", "ping", "sub"]}
    assert loose == []


def test_fastmcp_with_name_keyword_from_the_standalone_package():
    servers, _ = _py("from fastmcp import FastMCP\nserver = FastMCP(name='weather')\n@server.tool\ndef forecast(): ...\n")
    assert servers == {("weather", "fastmcp"): ["forecast"]}


def test_module_import_forms():
    servers, _ = _py("import fastmcp\napp = fastmcp.FastMCP('a')\n")
    assert servers == {("a", "fastmcp"): []}
    servers, _ = _py("import mcp.server.fastmcp as fm\napp = fm.FastMCP('b')\n")
    assert servers == {("b", "mcp"): []}


def test_mcpserver_inside_a_factory_with_enum_and_constant_tool_names():
    # modelcontextprotocol/servers git and time: MCPServer built in a function, tool names from an Enum or a constant.
    servers, _ = _py(
        "from enum import Enum\n"
        "from mcp.server.mcpserver import MCPServer\n"
        "class GitTools(str, Enum):\n    STATUS = 'git_status'\n    LOG = 'git_log'\n"
        "SHOW = 'git_show'\n"
        "def create_server():\n"
        "    server = MCPServer('mcp-git', version='1')\n"
        "    @server.tool(name=GitTools.STATUS.value, description='Shows the working tree status')\n"
        "    def status(): ...\n"
        "    @server.tool(name=GitTools.LOG)\n"
        "    def log(): ...\n"
        "    @server.tool(name=SHOW)\n"
        "    def show(): ...\n"
        "    @server.tool(name=compute_name())\n"
        "    def fallback(): ...\n"
        "    return server\n"
    )
    # A name the parser cannot resolve falls back to the function name, as the SDK does without one.
    assert servers == {("mcp-git", "mcp"): ["fallback", "git_log", "git_show", "git_status"]}


def test_two_servers_with_the_same_variable_in_different_functions_keep_their_own_tools():
    servers, _ = _py(
        "from fastmcp import FastMCP\n"
        "def calc():\n    server = FastMCP('calc')\n    @server.tool\n    def add(): ...\n    return server\n"
        "def greet():\n    server = FastMCP('greet')\n    @server.tool\n    def hello(): ...\n    return server\n"
    )
    assert servers == {("calc", "fastmcp"): ["add"], ("greet", "fastmcp"): ["hello"]}


def test_a_non_literal_server_name_is_left_for_the_caller():
    servers, _ = _py("from fastmcp import FastMCP\nimport os\nmcp = FastMCP(os.environ['NAME'])\n")
    assert servers == {(None, "fastmcp"): []}


# ── Python: low-level servers ────────────────────────────────────────────────────────────────────────────────────────

def test_low_level_server_with_list_tools_decorator():
    servers, _ = _py(
        "from mcp.server import Server\n"
        "from mcp import types\n"
        "server = Server('low')\n"
        "@server.list_tools()\n"
        "async def list_tools():\n"
        "    return [types.Tool(name='echo', inputSchema={}), types.Tool(name='sum', inputSchema={})]\n"
    )
    assert servers == {("low", "mcp"): ["echo", "sum"]}


def test_low_level_server_handlers_registered_by_keyword_and_by_method():
    # Microsoft Agent Framework samples: Server('x', on_list_tools=fn).
    servers, _ = _py(
        "from mcp.server.lowlevel import Server\nimport mcp.types as types\n"
        "async def list_tools(ctx, params):\n    return types.ListToolsResult(tools=[types.Tool(name='run', input_schema={})])\n"
        "server = Server('sample', on_list_tools=list_tools)\n"
    )
    assert servers == {("sample", "mcp"): ["run"]}
    # browser-use: self.server in __init__, add_request_handler('tools/list', ...) in another method, tools built by a helper.
    servers, _ = _py(
        "from mcp.server import Server\nimport mcp.types as types\n"
        "class BrowserServer:\n"
        "    def __init__(self):\n        self.server = Server('browser-use')\n        self._register()\n"
        "    def _definitions(self):\n        return [types.Tool(name='browser_exec', input_schema={})]\n"
        "    def _register(self):\n"
        "        async def handle_list_tools(ctx, params):\n"
        "            return types.ListToolsResult(tools=self._definitions())\n"
        "        self.server.add_request_handler('tools/list', types.PaginatedRequestParams, handle_list_tools)\n"
    )
    assert servers == {("browser-use", "mcp"): ["browser_exec"]}


def test_server_needs_the_mcp_import():
    assert _py("from http.server import Server\ns = Server('x')\n")[0] == {}
    assert _py("from mylib import Server\ns = Server('x')\n")[0] == {}
    assert _py("class FastMCP:\n    pass\nm = FastMCP('local')\n")[0] == {}
    assert _py("from mcp import ClientSession\ns = ClientSession('x')\n")[0] == {}


def test_calls_in_comments_and_strings_are_not_servers():
    code = (
        "from mcp.server.fastmcp import FastMCP\n"
        "# mcp = FastMCP('commented')\n"
        "EXAMPLE = \"mcp = FastMCP('in a string')\"\n"
        "def doc():\n    '''mcp = FastMCP(\"in a docstring\")'''\n"
    )
    assert _py(code)[0] == {}


def test_tool_decorator_on_another_object_is_not_an_mcp_tool():
    servers, loose = _py(
        "from fastmcp import FastMCP\nmcp = FastMCP('a')\nother = object()\n@other.tool\ndef nope(): ...\n"
    )
    assert servers == {("a", "fastmcp"): []}
    assert loose == []   # `other` is not imported, so it cannot be a server from another file


def test_unparseable_python_gives_nothing():
    assert _py("from fastmcp import FastMCP\nmcp = FastMCP('a'\n") == ({}, [])


# ── TypeScript / JavaScript ──────────────────────────────────────────────────────────────────────────────────────────

TS_SERVER = """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const name = "read_file";
const server = new McpServer({ name: "files", version: "1.0.0" });

server.tool("list_dir", "List a directory", { path: z.string() }, async () => ({ content: [] }));
server.registerTool(name, { description: "Read a file" }, async () => ({ content: [] }));
server.registerTool(
  "write_file",
  { title: "Write", description: "Write a file" },
  async () => ({ content: [] }),
);
// server.tool("commented_out", "x", async () => ({}));
const text = `server.tool("in_a_template", "x")`;
"""


def test_mcpserver_and_its_tools():
    servers, loose = _ts(TS_SERVER)
    assert servers == {"files": ["list_dir", "read_file", "write_file"]}
    assert loose == []


def test_the_new_server_package_and_require():
    servers, _ = _ts('import { McpServer } from "@modelcontextprotocol/server";\nconst s = new McpServer({ name: "memory-server" });\n')
    assert servers == {"memory-server": []}
    servers, _ = _ts(
        'const { McpServer: M } = require("@modelcontextprotocol/sdk/server/mcp.js");\nconst s = new M({ name: "cjs" });\n',
        "index.js",
    )
    assert servers == {"cjs": []}


def test_low_level_server_tools_from_the_list_tools_handler():
    servers, _ = _ts("""
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "low", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "echo", description: "Echo", inputSchema: { type: "object", properties: { name: { type: "string" } } } },
    { name: "add", inputSchema: {} },
    SOME_TOOL,
  ],
}));
""")
    assert servers == {"low": ["add", "echo"]}


def test_typescript_negatives():
    # Not imported from the MCP SDK.
    assert _ts('import { McpServer } from "./my-server";\nconst s = new McpServer({ name: "x" });\n')[0] == {}
    # A type-only import cannot be constructed.
    assert _ts('import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst s = new McpServer({ name: "x" });\n')[0] == {}
    # In a comment or a string.
    code = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        '// const a = new McpServer({ name: "commented" });\n'
        '/* const b = new McpServer({ name: "block" }); */\n'
        'const c = "new McpServer({ name: \\"string\\" })";\n'
        'const d = `new McpServer({ name: "template" })`;\n'
    )
    assert _ts(code)[0] == {}


def test_a_non_literal_typescript_name_is_left_for_the_caller():
    servers, _ = _ts('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst s = new McpServer({ name: NAME });\n')
    assert servers == {None: []}


def test_tools_on_a_server_from_another_file_are_loose():
    servers, loose = _ts(
        'import { McpServer } from "@modelcontextprotocol/server";\n'
        'const name = "echo";\n'
        'export const registerEchoTool = (server: McpServer) => {\n'
        '  server.registerTool(name, {}, async () => ({ content: [] }));\n'
        '};\n',
        "src/everything/tools/echo.ts",
    )
    assert servers == {}
    assert [(t.receiver, t.name) for t in loose] == [("server", "echo")]


# ── Discovery: names, linking, IDs ───────────────────────────────────────────────────────────────────────────────────

def test_discovery_names_links_and_sorts(tmp_path):
    servers, tool_sites = _discover(tmp_path, {
        # TypeScript: tools registered in other files on the server passed in (modelcontextprotocol/servers "everything").
        "src/everything/server/index.ts": 'import { McpServer } from "@modelcontextprotocol/server";\n'
                                          'export const createServer = () => {\n'
                                          '  const server = new McpServer({ name: "everything" });\n'
                                          '  registerEchoTool(server);\n  return server;\n};\n',
        "src/everything/tools/echo.ts": 'import { McpServer } from "@modelcontextprotocol/server";\nconst name = "echo";\n'
                                        'export const registerEchoTool = (server: McpServer) => {\n'
                                        '  server.registerTool(name, {}, async () => ({ content: [] }));\n};\n',
        # A test server with the same variable name does not take the production tool.
        "src/everything/__tests__/server.test.ts": 'import { McpServer } from "@modelcontextprotocol/server";\n'
                                                    'const server = new McpServer({ name: "s" });\n',
        # Python: no literal name → the nearest pyproject.toml; tools in a module importing the server.
        "py/pyproject.toml": '[project]\nname = "mcp-server-demo"\n',
        "py/src/weather/app.py": "import os\nfrom fastmcp import FastMCP\nmcp = FastMCP(os.environ.get('N'))\n",
        "py/src/weather/tools.py": "from .app import mcp\n@mcp.tool\ndef greet(): ...\n",
        # No manifest at all → the directory name.
        "bare/srv/main.py": "from fastmcp import FastMCP\nimport os\nmcp = FastMCP(os.environ['N'])\n",
    })
    rows = [(s.name, s.source, s.source_file, s.scope, s.language, s.sdk, s.tools) for s in servers]
    assert rows == [
        ("srv", "code", "bare/srv/main.py", "production", "python", "fastmcp", []),
        ("mcp-server-demo", "code", "py/src/weather/app.py", "production", "python", "fastmcp", ["greet"]),
        ("s", "code", "src/everything/__tests__/server.test.ts", "test", "typescript", "@modelcontextprotocol/server", []),
        ("everything", "code", "src/everything/server/index.ts", "production", "typescript",
         "@modelcontextprotocol/server", ["echo"]),
    ]
    assert sorted((t.name, t.kind, t.file_path) for t in tool_sites) == [
        ("echo", "mcp", "src/everything/tools/echo.ts"), ("greet", "mcp", "py/src/weather/tools.py"),
    ]


def test_an_ambiguous_loose_tool_is_not_linked(tmp_path):
    servers, tool_sites = _discover(tmp_path, {
        "pkg/a/server.ts": 'import { McpServer } from "@modelcontextprotocol/server";\nconst server = new McpServer({ name: "a" });\n',
        "pkg/b/server.ts": 'import { McpServer } from "@modelcontextprotocol/server";\nconst server = new McpServer({ name: "b" });\n',
        "pkg/tools/echo.ts": 'import { McpServer } from "@modelcontextprotocol/server";\n'
                             'export const r = (server: McpServer) => server.registerTool("echo", {}, async () => ({}));\n',
    })
    assert [s.tools for s in servers] == [[], []]
    assert tool_sites == []


# ── End to end: report, inventory, schema, HTML ──────────────────────────────────────────────────────────────────────

REPO = {
    ".mcp.json": '{"mcpServers": {"docs": {"type": "http", "url": "https://example.com/mcp"}}}',
    "servers/py/pyproject.toml": '[project]\nname = "py-server"\ndependencies = ["mcp"]\n',
    "servers/py/server.py": "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('py-demo')\n"
                            "@mcp.tool()\ndef search(q: str) -> str:\n    '''Search the web.'''\n    return q\n",
    "servers/ts/package.json": '{"name": "ts-server", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}',
    "servers/ts/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
                           'const server = new McpServer({ name: "ts-demo", version: "1" });\n'
                           'server.tool("search", "Search", async () => ({ content: [] }));\n'
                           'server.registerTool("fetch", { description: "Fetch a URL" }, async () => ({ content: [] }));\n',
    "tests/test_server.py": "from fastmcp import FastMCP\nmcp = FastMCP('fixture')\n@mcp.tool\ndef fake(): ...\n",
}


def _write(root, files):
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _cli_scan(tmp_path) -> dict:
    repo = tmp_path / "repo"
    _write(repo, REPO)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


def test_cli_json_lists_configured_and_implemented_servers(tmp_path):
    report = _cli_scan(tmp_path)
    assert report["mcp_servers"] == [
        {"name": "docs", "transport": "http", "source_file": ".mcp.json", "source": "config"},
        {"name": "py-demo", "transport": "unknown", "source_file": "servers/py/server.py", "source": "code", "line": 2,
         "scope": "production", "language": "python", "sdk": "mcp", "tools": ["search"]},
        {"name": "ts-demo", "transport": "unknown", "source_file": "servers/ts/index.ts", "source": "code", "line": 2,
         "scope": "production", "language": "typescript", "sdk": "@modelcontextprotocol/sdk",
         "tools": ["fetch", "search"]},
        {"name": "fixture", "transport": "unknown", "source_file": "tests/test_server.py", "source": "code", "line": 2,
         "scope": "test", "language": "python", "sdk": "fastmcp", "tools": ["fake"]},
    ]
    mcp_tools = sorted((t["id"], t["tool_type"], t["source_file"], t["scope"])
                       for t in report["tool_usages"] if t["tool_type"] == "mcp_tool")
    # `search` is defined in two files, so its IDs carry the path, as for any tool name defined in several files.
    assert mcp_tools == [
        ("tool:fake", "mcp_tool", "tests/test_server.py", "test"),
        ("tool:fetch", "mcp_tool", "servers/ts/index.ts", "production"),
        ("tool:search@servers/py/server.py", "mcp_tool", "servers/py/server.py", "production"),
        ("tool:search@servers/ts/index.ts", "mcp_tool", "servers/ts/index.ts", "production"),
    ]


def test_an_implemented_server_name_does_not_retype_tools_of_that_name():
    # langchain has an example server named "calculator" and unrelated `calculator` tools in its tests.
    from quin_scanner.models import ToolUsage
    from quin_scanner.orchestrator import _classify_tool_usages

    tools = [ToolUsage(tool_name="calculator", source_file="tests/test_tools.py"),
             ToolUsage(tool_name="docs", source_file="app.py")]
    _classify_tool_usages(tools, [MCPServer(name="calculator", source="code"), MCPServer(name="docs")])
    assert [t.tool_type for t in tools] == ["tool_definition", "mcp_tool"]


def test_mcp_servers_do_not_depend_on_the_hash_seed(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, REPO)
    outputs = set()
    for seed in ("1", "2", "3"):
        out = tmp_path / f"r{seed}.json"
        env = {**os.environ, "PYTHONHASHSEED": seed, "NO_COLOR": "1"}
        subprocess.run([sys.executable, "-c", "from quin_scanner.cli import cli; cli()", "scan", str(repo), "--no-llm",
                        "--no-vuln-check", "-o", "json", "-f", str(out)], env=env, check=True, capture_output=True)
        report = json.loads(out.read_text(encoding="utf-8"))
        outputs.add(json.dumps([report["mcp_servers"], report["tool_usages"]], sort_keys=True))
    assert len(outputs) == 1


@pytest.mark.parametrize("server", [
    MCPServer(name="cfg", transport="stdio", source_file=".mcp.json"),
    MCPServer(name="impl", source_file="s.py", source="code", line=3, scope="example", language="python", sdk="mcp",
              tools=["a", "b"]),
])
def test_entries_validate_and_every_field_is_documented(server):
    from tests.test_report_schema import REPORT_SCHEMA, _rich_report, _undocumented, _validate_report

    report = _rich_report()
    report.mcp_servers = [server]
    data = report.to_dict()
    _validate_report(data)
    assert _undocumented(data, REPORT_SCHEMA, REPORT_SCHEMA) == []


def test_a_1_0_entry_without_source_still_validates():
    from tests.test_report_schema import _rich_report, _validate_report

    data = _rich_report().to_dict()
    data["schema_version"] = "1.0"
    data["mcp_servers"] = [{"name": "n", "transport": "stdio", "source_file": "mcp.json"}]
    _validate_report(data)


def test_config_entries_carry_only_source_and_code_entries_the_rest():
    assert MCPServer(name="c").to_dict() == {"name": "c", "transport": "unknown", "source_file": "", "source": "config"}
    assert set(MCPServer(name="i", source="code").to_dict()) == {
        "name", "transport", "source_file", "source", "line", "scope", "language", "sdk", "tools",
    }


def test_html_report_embeds_code_servers_escaped():
    report = ScanReport(repo_path=".", scan_timestamp="2026-11-25T00:00:00+00:00", is_ai_application=True,
                        confidence=1.0, capability_tags=[], artifacts=[])
    report.mcp_servers = [
        MCPServer(name="<script>alert(1)</script>", source_file="s.py", source="code", line=1, language="python",
                  sdk="mcp", tools=["t"]),
        MCPServer(name="cfg", transport="stdio", source_file=".mcp.json"),
    ]
    html = ReportGenerator.to_html(report)
    assert "<script>alert(1)" not in html
    assert 'origin:code?"implemented":"configured"' in html
