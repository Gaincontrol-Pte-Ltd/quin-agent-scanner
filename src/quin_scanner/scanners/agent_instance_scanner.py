"""AgentInstanceScanner — extracts named agent instantiations from code and config files."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from quin_scanner.inventory import js_sites, python_sites
from quin_scanner.inventory.evidence import AgentSite, InstructionsRef, clean_site
from quin_scanner.models import ScanFinding
from quin_scanner.scanners.base import BaseScanner

if TYPE_CHECKING:
    from quin_scanner.file_index import FileIndex
    from quin_scanner.repo_accessor import RepoAccessor

# Code extensions to scan
_CODE_EXTENSIONS = {".py", ".ts", ".js", ".jsx", ".tsx", ".mjs"}
_JS_EXTENSIONS = {".ts", ".js", ".jsx", ".tsx", ".mjs"}

# Named agent instantiation, as regexes. Python files are parsed with ``ast`` instead (see
# ``_python_agent_calls``); these cover TypeScript/JavaScript and Python files that do not parse.
# ``name`` (or ``agent_name``) must be a real keyword or property: not the tail of another identifier
# (``vault_name=``, ``eval_name=``).
_NAME_ARG = r'(?<![\w.])(?:agent_)?name\s*[:=]\s*["\']([^"\']+)["\']'
_AGENT_CODE_PATTERNS = [
    # Multi-line aware patterns (re.DOTALL): Agent(... name="..." ...) spanning multiple lines.
    # Cap lookahead to 500 chars to avoid catastrophic backtracking.
    # Generic Agent(name="...", ...) — also matches TS/JS object-literal syntax
    # new Agent({ name: "..." }), e.g. Mastra.
    re.compile(r'Agent\s*\([^)]{0,500}?' + _NAME_ARG, re.IGNORECASE | re.DOTALL),
    # GroupChatManager(name="...", ...)
    re.compile(r'GroupChatManager\s*\([^)]{0,500}?' + _NAME_ARG, re.IGNORECASE | re.DOTALL),
    # <Something>Agent("name", ...): classes that take the name as their first positional argument
    # (AutoGen's AssistantAgent, UserProxyAgent). A bare Agent("...") is not matched: for the agent
    # frameworks that use that spelling the first argument is a task or a model, not a name.
    re.compile(r'\w+Agent\s*\(\s*["\']([^"\']{2,50})["\']'),
]

# @agent decorator followed by def function_name (any language of the code extensions)
_AGENT_DECORATOR_PATTERN = re.compile(r'@agent\s*\ndef\s+(\w+)', re.MULTILINE)

# Class inheritance patterns that define agent roles
# e.g. class ProductManager(Role): ... — MetaGPT, custom frameworks
_AGENT_CLASS_PATTERNS = [
    # class X(Role) — MetaGPT and generic role-based agent frameworks
    (re.compile(r'class\s+(\w+)\s*\(\s*Role\s*\)'), 0.82),
    # class X(BaseAgent) — generic agent base class
    (re.compile(r'class\s+(\w+)\s*\(\s*BaseAgent\s*\)'), 0.85),
    # class X(AssistantAgent) / class X(ConversableAgent) — AutoGen inheritance
    (re.compile(r'class\s+(\w+)\s*\(\s*(?:Assistant|Conversable|UserProxy)Agent\s*\)'), 0.85),
]

# Config file names that define agents
_AGENT_CONFIG_NAMES = {"agents.yaml", "agents.yml", "crew.yaml", "crew.yml"}

# Google ADK config-based agent files (adk create --type=config)
_ADK_ROOT_AGENT_NAMES = {"root_agent.yaml", "root_agent.yml"}

# Workflow graphs (ChatDev and similar): `graph: {nodes: [{id: ..., type: agent}, ...]}` in a YAML file with any name.
# Only files that mention both markers are parsed, and very large files are skipped.
_WORKFLOW_YAML_SUFFIXES = {".yaml", ".yml"}
_MAX_WORKFLOW_YAML_BYTES = 512 * 1024

# Markdown agent spec patterns
_MD_AGENT_TITLE_RE = re.compile(
    r'^#\s+(?:Agent\s*\d*[:\-—]\s*)?(.+)', re.MULTILINE,
)
_MD_ROLE_RE = re.compile(
    r'\*\*Role[:\s]*\*\*\s*(.+)', re.MULTILINE,
)
_MD_PURPOSE_RE = re.compile(
    r'\*\*Purpose[:\s]*\*\*\s*(.+)', re.MULTILINE,
)
# Directories that typically hold agent spec markdown files
_AGENT_DIR_NAMES = {"agents", "agent", "agent_specs", "agent-specs"}

# Test path patterns to skip
_TEST_PATH_RE = re.compile(
    r"(^|[\\/])(test_|tests[\\/]|test[\\/]|__tests__[\\/]|fixtures[\\/]"
    r"|conftest\.py)"
    r"|\.spec\.|_test\.",
    re.IGNORECASE,
)


def _is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path))


_NO_TOOLS = object()   # sentinel: no ``tools`` value to read


def _tools_value(entry: object) -> object:
    """An entry's raw ``tools:`` value, or ``_NO_TOOLS`` when the key is absent (the entry gives no tools)."""
    return entry["tools"] if isinstance(entry, dict) and "tools" in entry else _NO_TOOLS


def _literal_tool_refs(value: object) -> tuple[str, ...] | None:
    """Tool names from a YAML ``tools:`` list (strings, or mappings with a ``name``); None when absent."""
    if not isinstance(value, list):
        return None
    names = [item.get("name") if isinstance(item, dict) else item for item in value]
    return tuple(str(n) for n in names if isinstance(n, str) and n)


def _python_agent_calls(tree: ast.Module) -> list[tuple[int, str]]:
    """(line, name) of every named agent construction in a parsed Python module.

    A name is the literal ``name=`` (or ``agent_name=``) keyword of a call to ``...Agent(...)`` / ``GroupChatManager(...)``, or,
    for a class such as ``AssistantAgent`` that is not the bare ``Agent``, its first positional string.
    Text inside a string argument and the keywords of nested calls are not arguments of the agent.
    """
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = python_sites.callee_name(node.func)
        if not callee:
            continue
        lowered = callee.lower()
        if lowered != "groupchatmanager" and not lowered.endswith("agent"):
            continue
        name = python_sites.agent_name(node, callee)
        if name:
            found.append((node.lineno, node.col_offset, name))
    return [(line, name) for line, _, name in sorted(found)]


class AgentInstanceScanner(BaseScanner):
    """Scans for named agent instantiations in code and agent config files."""

    def name(self) -> str:
        return "AgentInstanceScanner"

    def scan(self, accessor: "RepoAccessor", file_index: "FileIndex") -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        seen: set[str] = set()
        self._sites: list[AgentSite] = []

        for path in file_index.all_files():
            # Test files give the inventory evidence (tagged scope: test) but no findings, as before.
            is_test = _is_test_path(path)
            p = Path(path)
            fname = p.name.lower()
            suffix = p.suffix.lower()

            try:
                if suffix in _CODE_EXTENSIONS:
                    found = self._scan_code(accessor.read_file(path), path, seen)
                elif fname in _AGENT_CONFIG_NAMES:
                    found = self._scan_agent_yaml(accessor.read_file(path), path, seen)
                elif fname in _ADK_ROOT_AGENT_NAMES:
                    found = self._scan_adk_root_agent(accessor.read_file(path), path, seen)
                elif fname == "flow.dag.yaml":
                    found = self._scan_flow_dag(accessor.read_file(path), path, seen)
                elif suffix in _WORKFLOW_YAML_SUFFIXES:
                    found = self._scan_workflow_graph(accessor.read_file(path), path, seen)
                elif suffix == ".md" and self._in_agent_dir(path):
                    found = self._scan_agent_markdown(accessor.read_file(path), path, seen)
                else:
                    continue
            except Exception:
                continue
            if not is_test:
                findings.extend(found)

        return findings

    def _add_site(self, *, literal: object = None, tools: object = _NO_TOOLS, **fields: object) -> None:
        """Build, redact and record one site from raw values. Evidence only: any failure skips the site, never the findings.

        ``literal`` is raw instruction text (hashed when it is a string); ``tools`` is a raw YAML ``tools:`` value
        (``_NO_TOOLS`` leaves ``tool_refs`` unknown). Everything evidence-related is evaluated inside the guard.
        """
        try:
            if isinstance(literal, str):
                fields["instructions"] = InstructionsRef.literal(literal)
            if tools is not _NO_TOOLS:
                fields["tool_refs"] = _literal_tool_refs(tools)
                fields["tools_given"] = True
            self._sites.append(clean_site(AgentSite(**fields)))  # type: ignore[arg-type]
        except Exception:
            pass

    def evidence(self) -> list[AgentSite]:
        """Typed agent sites from the last scan(), test files included."""
        return list(getattr(self, "_sites", []))

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        origins: list[tuple[str, str, int]] = []   # (role, kind, match offset) of each finding, for fallback sites

        def add(lineno: int, agent_name: str, offset: int, origin: tuple[str, str] = ("both", "constructor")) -> None:
            agent_name = agent_name.strip()
            if not agent_name or len(agent_name) > 80:
                return
            key = f"{path}:{lineno}:{agent_name}"
            if key in seen:
                return
            seen.add(key)
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="agent_instance",
                file_path=path,
                line_number=lineno,
                match_text=agent_name,
                capability_tag="multi-agent",
                confidence=0.85,
            ))
            origins.append((*origin, offset))

        tree = python_sites.parse_python(content) if path.lower().endswith(".py") else None
        calls = _python_agent_calls(tree) if tree is not None else None
        if calls is not None:
            for lineno, agent_name in calls:
                add(lineno, agent_name, -1)
        else:
            # Scan full content (not per-line): the patterns are compiled with re.DOTALL specifically to
            # match constructor calls formatted with one kwarg per line (Agent(\n  name="...",\n  ...\n)),
            # the dominant style for well-formatted code. A per-line search would defeat DOTALL entirely.
            for pattern in _AGENT_CODE_PATTERNS:
                for m in pattern.finditer(content):
                    add(content[:m.start()].count("\n") + 1, m.group(1), m.start())
        for m in _AGENT_DECORATOR_PATTERN.finditer(content):
            add(content[:m.start()].count("\n") + 1, m.group(1), m.start(), ("definition", "decorator"))
        # Class inheritance patterns: class X(Role), class X(BaseAgent), etc.
        for pattern, conf in _AGENT_CLASS_PATTERNS:
            for m in pattern.finditer(content):
                class_name = m.group(1).strip()
                if not class_name or len(class_name) > 80:
                    continue
                lineno = content[:m.start()].count("\n") + 1
                key = f"{path}:{lineno}:{class_name}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category="agent_instance",
                    file_path=path,
                    line_number=lineno,
                    match_text=class_name,
                    capability_tag="multi-agent",
                    confidence=conf,
                ))
                origins.append(("definition", "subclass", m.start()))
        # Evidence must never cost the file its findings: a failure here skips only the sites.
        try:
            if tree is not None:
                self._sites.extend(python_sites.agent_sites(tree, path))
            else:
                is_js = Path(path).suffix.lower() in _JS_EXTENSIONS
                sites = js_sites.agent_sites(content, path) if is_js else []
                spans = js_sites.call_spans(content) if is_js else []
                view = js_sites.code_view(content) if is_js else content
                # A regex finding inside a call that js_sites parsed is that site (it reads only the top-level keys);
                # one inside a JS comment or string is not an agent (the finding stays, only the site is skipped).
                sites += [
                    AgentSite(role=role, kind=kind, name=f.match_text, file_path=path, line=f.line_number)
                    for f, (role, kind, offset) in zip(findings, origins, strict=True)
                    if not any(start <= offset <= end for start, end in spans)
                    and (offset < 0 or view[offset] == content[offset])
                ]
                sites = [clean_site(s) for s in sites]
                self._sites.extend(sites)
        except Exception:
            pass
        return findings

    def _scan_agent_yaml(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse agents.yaml / crew.yaml for named agent definitions."""
        findings = []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        # crew.yaml: top-level keys are agent role names, each has a 'role' or 'name' field
        agents_section = data.get("agents", data)
        if isinstance(agents_section, dict):
            for agent_key, agent_val in agents_section.items():
                if isinstance(agent_val, dict):
                    agent_name = agent_val.get("name") or agent_val.get("role") or str(agent_key)
                else:
                    agent_name = str(agent_key)
                # Every key is a site (code links to it by key); findings stay deduplicated by display name.
                self._add_site(
                    role="definition", kind="config_entry", name=str(agent_name), file_path=path, line=None,
                    instructions=InstructionsRef("config", str(agent_key)),
                    tools=_tools_value(agent_val),
                )
                key = f"{path}::{agent_name}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(ScanFinding(
                    scanner_name=self.name(),
                    category="agent_instance",
                    file_path=path,
                    line_number=0,
                    match_text=str(agent_name),
                    capability_tag="multi-agent",
                    confidence=0.90,
                ))
        elif isinstance(agents_section, list):
            for item in agents_section:
                if isinstance(item, dict):
                    agent_name = item.get("name") or item.get("role", "")
                    if agent_name:
                        key = f"{path}::{agent_name}"
                        if key not in seen:
                            seen.add(key)
                            self._add_site(
                                role="definition", kind="config_entry", name=str(agent_name), file_path=path,
                                line=None, instructions=InstructionsRef("config", str(agent_name)),
                                tools=_tools_value(item),
                            )
                            findings.append(ScanFinding(
                                scanner_name=self.name(),
                                category="agent_instance",
                                file_path=path,
                                line_number=0,
                                match_text=str(agent_name),
                                capability_tag="multi-agent",
                                confidence=0.90,
                            ))
        return findings

    def _scan_adk_root_agent(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse Google ADK's config-based agent file (root_agent.yaml).

        Schema (adk create --type=config): top-level 'name' field for the root
        agent, plus an optional 'sub_agents' list of nested agent definitions.
        """
        findings = []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        def _add(item: dict, confidence: float) -> None:
            agent_name = item.get("name")
            if not agent_name or not isinstance(agent_name, str):
                return
            key = f"{path}::{agent_name}"
            if key in seen:
                return
            seen.add(key)
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="agent_instance",
                file_path=path,
                line_number=0,
                match_text=agent_name,
                capability_tag="multi-agent",
                confidence=confidence,
            ))
            instruction = item.get("instruction")
            model = item.get("model")
            self._add_site(
                role="definition", kind="config_entry", name=agent_name, file_path=path, line=None,
                literal=instruction,
                model_expr=model if isinstance(model, str) else None,
                tools=_tools_value(item),
            )

        _add(data, 0.90)
        sub_agents = data.get("sub_agents", [])
        if isinstance(sub_agents, list):
            for item in sub_agents:
                if isinstance(item, dict):
                    _add(item, 0.88)
        return findings

    @staticmethod
    def _in_agent_dir(path: str) -> bool:
        """Return True if the file is inside an agents/ (or similar) directory."""
        parts = Path(path).parts
        return any(p.lower() in _AGENT_DIR_NAMES for p in parts[:-1])

    def _scan_agent_markdown(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse markdown agent specification files for agent definitions.

        Recognises patterns like:
          # Agent 3: Research Agent
          **Role:** Vendor & Technology Intelligence Researcher
          **Purpose:** Conduct web research ...
        """
        findings = []

        title_m = _MD_AGENT_TITLE_RE.search(content)
        if not title_m:
            return findings

        agent_name = title_m.group(1).strip()
        if not agent_name or len(agent_name) > 120:
            return findings

        key = f"{path}::{agent_name}"
        if key in seen:
            return findings
        seen.add(key)
        self._add_site(
            role="definition", kind="config_entry", name=agent_name, file_path=path, line=None,
            instructions=InstructionsRef("file", path),
        )

        # Build a descriptive match_text with role if available
        role_m = _MD_ROLE_RE.search(content)
        role = role_m.group(1).strip() if role_m else ""
        match_text = f"{agent_name} — {role}" if role else agent_name

        findings.append(ScanFinding(
            scanner_name=self.name(),
            category="agent_instance",
            file_path=path,
            line_number=1,
            match_text=match_text[:200],
            capability_tag="multi-agent",
            confidence=0.92,
        ))
        return findings

    def _scan_flow_dag(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse flow.dag.yaml for agent-type nodes."""
        findings = []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        nodes = data.get("nodes", [])
        if not isinstance(nodes, list):
            return findings

        for node in nodes:
            if not isinstance(node, dict):
                continue
            if node.get("type") in ("agent", "llm"):
                node_name = node.get("name", "")
                if node_name:
                    key = f"{path}::{node_name}"
                    if key not in seen:
                        seen.add(key)
                        self._add_site(
                            role="definition", kind="graph_node", name=str(node_name), file_path=path, line=None,
                        )
                        findings.append(ScanFinding(
                            scanner_name=self.name(),
                            category="agent_instance",
                            file_path=path,
                            line_number=0,
                            match_text=str(node_name),
                            capability_tag="multi-agent",
                            confidence=0.88,
                        ))
        return findings

    def _scan_workflow_graph(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Agent nodes of a workflow graph: ``graph.nodes[]`` items with ``type: agent``, named by their ``id``."""
        findings: list[ScanFinding] = []
        if len(content) > _MAX_WORKFLOW_YAML_BYTES or "nodes" not in content or "agent" not in content:
            return findings
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings
        graph = data.get("graph") if isinstance(data, dict) else None
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        if not isinstance(nodes, list):
            return findings
        for node in nodes:
            if not isinstance(node, dict) or node.get("type") != "agent":
                continue
            node_id = node.get("id") or node.get("name")
            if not node_id:
                continue
            key = f"{path}::{node_id}"
            if key in seen:
                continue
            seen.add(key)
            config = node.get("config") if isinstance(node.get("config"), dict) else {}
            role = config.get("role")
            self._add_site(
                role="definition", kind="graph_node", name=str(node_id), file_path=path, line=None,
                literal=role,
            )
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="agent_instance",
                file_path=path,
                line_number=0,
                match_text=str(node_id),
                capability_tag="multi-agent",
                confidence=0.88,
            ))
        return findings
