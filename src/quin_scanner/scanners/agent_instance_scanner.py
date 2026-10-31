"""AgentInstanceScanner — extracts named agent instantiations from code and config files."""
from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from quin_scanner.models import ScanFinding
from quin_scanner.scanners.base import BaseScanner

if TYPE_CHECKING:
    from quin_scanner.file_index import FileIndex
    from quin_scanner.repo_accessor import RepoAccessor

# Code extensions to scan
_CODE_EXTENSIONS = {".py", ".ts", ".js", ".jsx", ".tsx", ".mjs"}

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


_NAME_KEYWORDS = frozenset({"name", "agent_name"})


def _callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _string_constant(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _python_agent_calls(content: str) -> list[tuple[int, str]] | None:
    """(line, name) of every agent construction in Python source, or None if the source does not parse.

    A name is the literal ``name=`` (or ``agent_name=``) keyword of a call to ``...Agent(...)`` / ``GroupChatManager(...)``, or,
    for a class such as ``AssistantAgent`` that is not the bare ``Agent``, its first positional string.
    Text inside a string argument and the keywords of nested calls are not arguments of the agent.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callee_name(node.func)
        if not callee:
            continue
        lowered = callee.lower()
        if lowered != "groupchatmanager" and not lowered.endswith("agent"):
            continue
        name = next((_string_constant(kw.value) for kw in node.keywords if kw.arg in _NAME_KEYWORDS), None)
        if name is None and callee.endswith("Agent") and callee != "Agent" and node.args:
            positional = _string_constant(node.args[0])
            if positional is not None and 2 <= len(positional) <= 50:
                name = positional
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

        for path in file_index.all_files():
            if _is_test_path(path):
                continue

            p = Path(path)
            fname = p.name.lower()
            suffix = p.suffix.lower()

            try:
                if suffix in _CODE_EXTENSIONS:
                    content = accessor.read_file(path)
                    findings.extend(self._scan_code(content, path, seen))
                elif fname in _AGENT_CONFIG_NAMES:
                    content = accessor.read_file(path)
                    findings.extend(self._scan_agent_yaml(content, path, seen))
                elif fname in _ADK_ROOT_AGENT_NAMES:
                    content = accessor.read_file(path)
                    findings.extend(self._scan_adk_root_agent(content, path, seen))
                elif fname == "flow.dag.yaml":
                    content = accessor.read_file(path)
                    findings.extend(self._scan_flow_dag(content, path, seen))
                elif suffix in _WORKFLOW_YAML_SUFFIXES:
                    content = accessor.read_file(path)
                    findings.extend(self._scan_workflow_graph(content, path, seen))
                elif suffix == ".md" and self._in_agent_dir(path):
                    content = accessor.read_file(path)
                    findings.extend(self._scan_agent_markdown(content, path, seen))
            except Exception:
                continue

        return findings

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings = []

        def add(lineno: int, agent_name: str) -> None:
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

        calls = _python_agent_calls(content) if path.lower().endswith(".py") else None
        if calls is not None:
            for lineno, agent_name in calls:
                add(lineno, agent_name)
        else:
            # Scan full content (not per-line): the patterns are compiled with re.DOTALL specifically to
            # match constructor calls formatted with one kwarg per line (Agent(\n  name="...",\n  ...\n)),
            # the dominant style for well-formatted code. A per-line search would defeat DOTALL entirely.
            for pattern in _AGENT_CODE_PATTERNS:
                for m in pattern.finditer(content):
                    add(content[:m.start()].count("\n") + 1, m.group(1))
        for m in _AGENT_DECORATOR_PATTERN.finditer(content):
            add(content[:m.start()].count("\n") + 1, m.group(1))
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

        def _add(agent_name: object, confidence: float) -> None:
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

        _add(data.get("name"), 0.90)
        sub_agents = data.get("sub_agents", [])
        if isinstance(sub_agents, list):
            for item in sub_agents:
                if isinstance(item, dict):
                    _add(item.get("name"), 0.88)
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
