"""AgentInstanceScanner — extracts named agent instantiations from code and config files."""
from __future__ import annotations

import re
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

# Named agent instantiation patterns
_AGENT_CODE_PATTERNS = [
    # Multi-line aware patterns (re.DOTALL): Agent(... name="..." ...) spanning multiple lines.
    # Cap lookahead to 500 chars to avoid catastrophic backtracking.
    # Generic Agent(name="...", ...) — also matches TS/JS object-literal syntax
    # new Agent({ name: "..." }), e.g. Mastra.
    re.compile(r'Agent\s*\([^)]{0,500}?name\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    # AssistantAgent(name="...", ...)
    re.compile(r'AssistantAgent\s*\([^)]{0,500}?name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    # UserProxyAgent(name="...", ...)
    re.compile(r'UserProxyAgent\s*\([^)]{0,500}?name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    # ConversableAgent(name="...", ...)
    re.compile(r'ConversableAgent\s*\([^)]{0,500}?name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    # GroupChatManager / similar patterns
    re.compile(r'GroupChatManager\s*\([^)]{0,500}?name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
    # @agent decorator followed by def function_name
    re.compile(r'@agent\s*\ndef\s+(\w+)', re.MULTILINE),
    # name="..." as first positional in Agent(...) — simpler fallback
    re.compile(r'(?:Agent|Runner)\s*\(\s*["\']([^"\']{2,50})["\']'),
]

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
                elif suffix == ".md" and self._in_agent_dir(path):
                    content = accessor.read_file(path)
                    findings.extend(self._scan_agent_markdown(content, path, seen))
            except Exception:
                continue

        return findings

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings = []
        # Scan full content (not per-line): _AGENT_CODE_PATTERNS are compiled with
        # re.DOTALL specifically to match constructor calls formatted with one
        # kwarg per line (Agent(\n  name="...",\n  ...\n)), which is the dominant
        # style for well-formatted Python/TS. Per-line search would defeat DOTALL
        # entirely, since a single line never contains the '\n' DOTALL exists for.
        for pattern in _AGENT_CODE_PATTERNS:
            for m in pattern.finditer(content):
                agent_name = m.group(1).strip()
                if not agent_name or len(agent_name) > 80:
                    continue
                lineno = content[:m.start()].count("\n") + 1
                key = f"{path}:{lineno}:{agent_name}"
                if key in seen:
                    continue
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
