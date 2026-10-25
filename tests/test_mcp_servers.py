"""MCP servers are read from the config files: name and transport (gap 18.15).

The orchestrator used to guess both from the scanner's finding text, which never contains the transport: in ten real
repositories 0 of 6 servers had the right transport and mem0's were named after their script paths. The shapes below are
the real ones from those repositories."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.mcp_scanner import discover_mcp_servers, infer_transport


@pytest.mark.parametrize("cfg,expected", [
    ({"command": "uvx", "args": ["gpt-researcher"]}, "stdio"),                                       # gpt-researcher/.mcp.json
    ({"type": "http", "url": "https://modelcontextprotocol.io/mcp"}, "http"),                        # modelcontextprotocol/servers
    ({"type": "stdio", "command": "python3", "args": ["./core/mcp_server.py"], "cwd": "."}, "stdio"),  # mem0, four files
    ({"url": "https://example.com/sse"}, "sse"), ({"url": "https://example.com/sse/"}, "sse"),
    ({"url": "https://example.com/sse?token=x"}, "sse"), ({"url": "https://example.com/mcp"}, "http"),
    ({"serverUrl": "https://example.com/mcp"}, "http"), ({"httpUrl": "https://example.com/mcp"}, "http"),
    ({"type": "streamable-http", "url": "https://x/mcp"}, "http"), ({"type": "streamable_http"}, "http"),   # no URL: only the type says http
    ({"type": "STDIO"}, "stdio"), ({"type": "sse", "url": "https://x/mcp"}, "sse"),
    ({"transport": "stdio", "command": "node"}, "stdio"), ({"transport": {"type": "sse"}, "url": "https://x"}, "sse"),
    ({"type": "http", "command": "ignored"}, "http"),                                                  # an explicit type wins
    ({}, "unknown"), ({"args": ["x"]}, "unknown"), ({"type": "websocket-ish"}, "unknown"),
])
def test_transport_is_read_from_the_entry(cfg, expected):
    assert infer_transport(cfg) == expected


def _discover(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body if isinstance(body, str) else json.dumps(body))
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return discover_mcp_servers(accessor, index)


def test_the_name_is_the_key_not_the_script_path_and_the_transport_is_right(tmp_path):
    servers = _discover(tmp_path, {
        ".mcp.json": {"mcpServers": {"gpt-researcher": {"command": "uvx", "args": ["gpt-researcher"]}}},
        "integrations/codex/.mcp.json": {"mcpServers": {"mem0": {"type": "stdio", "command": "python3", "args": ["./core/mcp_server.py"]}}},
        "docs/mcp.json": {"mcpServers": {"mcp-docs": {"type": "http", "url": "https://modelcontextprotocol.io/mcp"}}},
    })
    assert sorted((s.name, s.transport, s.source_file) for s in servers) == [
        ("gpt-researcher", "stdio", ".mcp.json"), ("mcp-docs", "http", "docs/mcp.json"), ("mem0", "stdio", "integrations/codex/.mcp.json"),
    ]


def test_the_vs_code_servers_key_is_read_too(tmp_path):
    servers = _discover(tmp_path, {".vscode/mcp.json": {"servers": {"fs": {"type": "stdio", "command": "npx"}, "web": {"type": "sse", "url": "https://x/sse"}}}})
    assert sorted((s.name, s.transport) for s in servers) == [("fs", "stdio"), ("web", "sse")]


def test_one_server_per_entry_not_one_per_risk_finding(tmp_path):
    # a server whose name matches several risk patterns produces extra scanner findings; it is still one server
    servers = _discover(tmp_path, {".mcp.json": {"mcpServers": {"shell-filesystem-fetch": {"command": "node", "tools": ["bash", "write_file", "web_fetch"]}}}})
    assert [(s.name, s.transport) for s in servers] == [("shell-filesystem-fetch", "stdio")]


def test_odd_files_are_skipped_not_fatal(tmp_path):
    servers = _discover(tmp_path, {
        ".mcp.json": "{ not json", "mcp.json": json.dumps(["a list"]), ".cursor/mcp.json": {"mcpServers": ["a", "list"]},
        ".roo/mcp.json": {"mcpServers": {"bad": "a string", "ok": {"command": "x"}}},
    })
    assert [(s.name, s.transport) for s in servers] == [("ok", "stdio")]


def test_a_repository_without_mcp_config_has_no_servers(tmp_path):
    assert _discover(tmp_path, {"agent.py": "print('hi')\n"}) == []


def _scan(tmp_path, *extra):
    out = tmp_path / "report.json"
    res = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out), *extra])
    assert res.exit_code == 0, res.output
    return json.loads(out.read_text())


def test_the_report_carries_the_real_names_and_transports(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"gpt-researcher": {"command": "uvx", "args": ["gpt-researcher"]}, "docs": {"type": "http", "url": "https://x/mcp"}}}))
    report = _scan(tmp_path)
    assert sorted((s["name"], s["transport"]) for s in report["mcp_servers"]) == [("docs", "http"), ("gpt-researcher", "stdio")]


def test_with_the_mcp_scanner_switched_off_no_server_is_reported(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("scanners:\n  enabled: [dependency]\n")
    assert _scan(tmp_path, "--config", str(cfg))["mcp_servers"] == []
