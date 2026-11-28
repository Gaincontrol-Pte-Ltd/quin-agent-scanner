from __future__ import annotations

import json
from pathlib import PurePosixPath

from quin_scanner.file_index import FileIndex
from quin_scanner.inventory.evidence import ToolSite
from quin_scanner.inventory.mcp_sites import CODE_SUFFIXES, LooseTool, McpServerSite, mcp_sites
from quin_scanner.inventory.scope import scope_of
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


# Cheap text filter before parsing: every server file and every file that registers tools on one contains one of these.
_CODE_MARKERS = ("mcp", "MCP", "modelcontextprotocol", ".tool")
_MANIFESTS = {"python": ("pyproject.toml", "package.json"), "typescript": ("package.json", "pyproject.toml"),
              "javascript": ("package.json", "pyproject.toml")}


def _manifest_name(accessor: RepoAccessor, path: str) -> str | None:
    """The package name declared by a ``pyproject.toml`` (``[project]`` or ``[tool.poetry]``) or ``package.json``."""
    try:
        raw = accessor.read_file(path)
    except Exception:
        return None
    try:
        if path.endswith(".json"):
            data = json.loads(raw)
            name = data.get("name") if isinstance(data, dict) else None
        else:
            import tomllib
            data = tomllib.loads(raw)
            name = (data.get("project") or {}).get("name") or ((data.get("tool") or {}).get("poetry") or {}).get("name")
    except Exception:
        return None
    return name.strip() if isinstance(name, str) and name.strip() else None


def _fallback_name(accessor: RepoAccessor, files: set[str], site: McpServerSite) -> str:
    """For a server without a literal name: the nearest package name, else its directory name (file stem at the root)."""
    parts = PurePosixPath(site.file_path).parts[:-1]
    for depth in range(len(parts), -1, -1):
        directory = "/".join(parts[:depth])
        for manifest in _MANIFESTS[site.language]:
            candidate = f"{directory}/{manifest}" if directory else manifest
            if candidate in files:
                name = _manifest_name(accessor, candidate)
                if name:
                    return name
    return parts[-1] if parts else PurePosixPath(site.file_path).stem


def _family(language: str) -> str:
    return "python" if language == "python" else "js"


def _link_loose(tool: LooseTool, servers: list[McpServerSite]) -> McpServerSite | None:
    """The server a tool registered on another file's server belongs to: same variable name and language family, and
    the same scope when one qualifies (a production tool file is not linked to a server built in a test), in the
    nearest directory (most shared leading directories). Never repository-wide unless the server is at the root; a tie
    leaves the tool unlinked."""
    scope = scope_of(tool.file_path)
    same_scope = [s for s in servers if scope_of(s.file_path) == scope]
    return _nearest_server(tool, same_scope) or _nearest_server(tool, servers)


def _nearest_server(tool: LooseTool, servers: list[McpServerSite]) -> McpServerSite | None:
    here = PurePosixPath(tool.file_path).parts[:-1]
    ranked: list[tuple[int, McpServerSite]] = []
    for server in servers:
        if server.var != tool.receiver or _family(server.language) != _family(tool.language):
            continue
        there = PurePosixPath(server.file_path).parts[:-1]
        shared = 0
        for a, b in zip(here, there):
            if a != b:
                break
            shared += 1
        if shared or not there:
            ranked.append((shared, server))
    if not ranked:
        return None
    best = max(shared for shared, _ in ranked)
    nearest = [server for shared, server in ranked if shared == best]
    return nearest[0] if len(nearest) == 1 else None


def discover_implemented_mcp_servers(
    accessor: RepoAccessor, file_index: FileIndex,
) -> tuple[list[MCPServer], list[ToolSite]]:
    """The MCP servers the repository implements (``source: code``) and their tools as tool definition sites.

    Test and example code is included and tagged by ``scope``. Output is sorted, so it does not depend on file order.
    """
    sites: list[McpServerSite] = []
    loose: list[LooseTool] = []
    for path in sorted(file_index.all_files()):
        if PurePosixPath(path).suffix.lower() not in CODE_SUFFIXES:
            continue
        try:
            text = accessor.read_file(path)
        except Exception:
            continue
        if not any(marker in text for marker in _CODE_MARKERS):
            continue
        try:
            found, unlinked = mcp_sites(text, path)
        except Exception:
            continue   # one unparseable file never costs the rest
        sites.extend(found)
        loose.extend(unlinked)
    # A tool is defined where it is registered: in the server's file, or in the file of a linked loose tool.
    tool_sites = [
        ToolSite(name=t.name, kind="mcp", file_path=site.file_path, line=t.line) for site in sites for t in site.tools
    ]
    linked: dict[int, set[str]] = {}
    for tool in loose:
        server = _link_loose(tool, sites)
        if server is not None:
            linked.setdefault(id(server), set()).add(tool.name)
            tool_sites.append(ToolSite(name=tool.name, kind="mcp", file_path=tool.file_path, line=tool.line))
    files = set(file_index.all_files())
    servers: list[MCPServer] = []
    for site in sites:
        servers.append(MCPServer(
            name=site.name or _fallback_name(accessor, files, site), transport="unknown", source_file=site.file_path,
            source="code", line=site.line, scope=scope_of(site.file_path), language=site.language, sdk=site.sdk,
            tools=sorted({t.name for t in site.tools} | linked.get(id(site), set())),
        ))
    servers.sort(key=lambda s: (s.source_file, s.line or 0, s.name))
    return servers, tool_sites


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

        for path in sorted(mcp_paths):
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
