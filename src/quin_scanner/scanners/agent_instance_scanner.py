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
    # Generic Agent(name="...", ...)
    re.compile(r'Agent\s*\([^)]{0,500}?name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
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

# Config file names that define agents
_AGENT_CONFIG_NAMES = {"agents.yaml", "agents.yml", "crew.yaml", "crew.yml"}

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
                elif fname == "flow.dag.yaml":
                    content = accessor.read_file(path)
                    findings.extend(self._scan_flow_dag(content, path, seen))
            except Exception:
                continue

        return findings

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings = []
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern in _AGENT_CODE_PATTERNS:
                m = pattern.search(line)
                if m:
                    agent_name = m.group(1).strip()
                    if not agent_name or len(agent_name) > 80:
                        continue
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
