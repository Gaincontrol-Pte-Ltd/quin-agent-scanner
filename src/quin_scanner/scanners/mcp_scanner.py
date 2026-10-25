from __future__ import annotations

import json

from quin_scanner.file_index import FileIndex
from quin_scanner.models import MCPServer, ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner

# Known MCP config file locations
_MCP_CONFIG_GLOBS = [
    "**/.mcp.json",
    "**/mcp.json",
    "**/.cursor/mcp.json",
    "**/.cursor/settings.json",
    "**/.claude/settings.json",
    "**/claude_desktop_config.json",
    "**/.config/claude/claude_desktop_config.json",
    "**/cline_mcp_settings.json",
    "**/.roo/mcp.json",
    "**/.vscode/mcp.json",
]

# Known high-risk MCP tool name patterns (internet, file, code execution)
_HIGH_RISK_TOOL_PATTERNS = {
    "internet_access": ["fetch", "browse", "web", "http", "search", "crawl", "scrape", "request"],
    "file_write": ["filesystem", "file", "write", "disk", "storage", "edit", "create"],
    "code_execution": ["bash", "shell", "exec", "run", "terminal", "python", "node", "eval", "repl"],
    "credential_access": ["vault", "secret", "credential", "password", "keychain", "1password", "bitwarden"],
}


def infer_transport(server_cfg: dict) -> str:
    """The transport of one MCP server entry, read from its configuration: ``stdio``, ``http``, ``sse`` or ``unknown``.

    An explicit ``type`` (or ``transport``) wins; otherwise a ``command`` means a local process (stdio) and a ``url`` means a
    remote one (``sse`` when the address ends in ``/sse``, else streamable ``http``)."""
    declared = server_cfg.get("type") or server_cfg.get("transport")
    if isinstance(declared, dict):
        declared = declared.get("type")
    declared = str(declared or "").strip().lower().replace("_", "-")
    if declared == "stdio":
        return "stdio"
    if declared == "sse":
        return "sse"
    if declared in ("http", "streamable-http", "streamablehttp"):
        return "http"
    if server_cfg.get("command"):
        return "stdio"
    url = str(server_cfg.get("url") or server_cfg.get("serverUrl") or server_cfg.get("httpUrl") or "").strip()
    if url:
        return "sse" if url.split("?")[0].rstrip("/").endswith("/sse") else "http"
    return "unknown"


def _servers_in(raw: str) -> dict:
    """The ``mcpServers`` (Claude Desktop, Cursor, ...) or ``servers`` (VS Code) mapping of an MCP config file, or {}."""
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    servers = (data.get("mcpServers") or data.get("servers") or {}) if isinstance(data, dict) else {}
    return servers if isinstance(servers, dict) else {}


def discover_mcp_servers(accessor: RepoAccessor, file_index: FileIndex) -> list[MCPServer]:
    """The MCP servers declared in the repository's config files, with the name (the key of the entry) and the transport read from
    the configuration itself. The orchestrator used to derive both from the scanner's finding text, which never contains the
    transport and put a script path in the name: 0 of 6 servers in ten real repositories had the right transport."""
    paths: set[str] = set()
    for glob in _MCP_CONFIG_GLOBS:
        paths.update(file_index.files_matching(glob))
    found: list[MCPServer] = []
    for path in sorted(paths):
        try:
            raw = accessor.read_file(path)
        except Exception:
            continue
        for name, cfg in _servers_in(raw).items():
            if isinstance(cfg, dict):
                found.append(MCPServer(name=str(name), transport=infer_transport(cfg), source_file=path))
    return found


def _classify_server_risk(server_name: str, tools: list[str]) -> list[str]:
    """Return list of risk signal types based on server name and tool names."""
    combined = (server_name + " " + " ".join(tools)).lower()
    risks = []
    for signal_type, keywords in _HIGH_RISK_TOOL_PATTERNS.items():
        if any(kw in combined for kw in keywords):
            risks.append(signal_type)
    return risks


class MCPScanner(BaseScanner):
    """Detects MCP (Model Context Protocol) server configurations."""

    def name(self) -> str:
        return "MCPScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        mcp_paths: set[str] = set()
        for glob in _MCP_CONFIG_GLOBS:
            mcp_paths.update(file_index.files_matching(glob))

        for path in mcp_paths:
            findings.extend(self._scan_mcp_config(accessor, path))
        return findings

    def _scan_mcp_config(self, accessor: RepoAccessor, path: str) -> list[ScanFinding]:
        findings = []
        try:
            raw = accessor.read_file(path)
        except Exception:
            return findings

        # MCP configs have a "mcpServers" key (Claude Desktop format)
        # or "servers" key (other formats)
        servers = _servers_in(raw)

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue

            tools = server_cfg.get("tools", []) or []
            if isinstance(tools, dict):
                tools = list(tools.keys())

            risk_signals = _classify_server_risk(server_name, tools)
            capability_tag = "tool-use"

            # Build match text summary
            cmd = server_cfg.get("command", "")
            args = server_cfg.get("args", [])
            match_text = f"MCP server: {server_name}"
            if cmd:
                match_text += f" (command: {cmd})"
            if args:
                match_text += f" args: {' '.join(str(a) for a in args[:5])}"

            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="mcp_server",
                file_path=path,
                line_number=None,
                match_text=match_text[:300],
                capability_tag=capability_tag,
                confidence=0.95,
            ))

            # Add a finding per high-risk signal for visibility
            for signal in risk_signals:
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category="mcp_risk",
                    file_path=path,
                    line_number=None,
                    match_text=f"MCP server '{server_name}' has {signal.replace('_', ' ')} capability",
                    capability_tag="tool-use",
                    confidence=0.85,
                ))

        return findings
