"""ToolDefinitionScanner — extracts named tool definitions from code and config files."""
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

_CODE_EXTENSIONS = {".py", ".ts", ".js", ".jsx", ".tsx", ".mjs"}

# Tool definition patterns
_TOOL_CODE_PATTERNS = [
    # @tool decorator then def function_name (LangChain / CrewAI)
    (re.compile(r'@tool\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@tool"),
    # @function_tool decorator (OpenAI Agents SDK)
    (re.compile(r'@function_tool\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@function_tool"),
    # FunctionTool(name="...", ...)
    (re.compile(r'FunctionTool\s*\(\s*(?:[^)]*?,\s*)?name\s*=\s*["\']([^"\']+)["\']'), "FunctionTool"),
    # Tool(name="...", ...)
    (re.compile(r'\bTool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']'), "Tool"),
    # StructuredTool.from_function(name="...", ...)
    (re.compile(r'StructuredTool\.from_function\s*\([^)]*?name\s*=\s*["\']([^"\']+)["\']'), "StructuredTool"),
    # tools=[tool1, tool2] — capture individual tool variable names
    (re.compile(r'tools\s*=\s*\[([^\]]+)\]'), "tool_list"),
]

# Config file names that define tools
_TOOL_CONFIG_NAMES = {"tools.yaml", "tools.yml"}

_TEST_PATH_RE = re.compile(
    r"(^|[\\/])(test_|tests[\\/]|test[\\/]|__tests__[\\/]|fixtures[\\/]"
    r"|conftest\.py)"
    r"|\.spec\.|_test\.",
    re.IGNORECASE,
)


def _is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path))


class ToolDefinitionScanner(BaseScanner):
    """Scans for named tool definitions in code and config files."""

    def name(self) -> str:
        return "ToolDefinitionScanner"

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
                elif fname in _TOOL_CONFIG_NAMES:
                    content = accessor.read_file(path)
                    findings.extend(self._scan_tools_yaml(content, path, seen))
                elif fname == "flow.dag.yaml":
                    content = accessor.read_file(path)
                    findings.extend(self._scan_flow_dag(content, path, seen))
            except Exception:
                continue

        return findings

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings = []
        for pattern, decorator in _TOOL_CODE_PATTERNS:
            if decorator == "tool_list":
                # Extract individual identifiers from tools=[...] lists
                for m in pattern.finditer(content):
                    list_str = m.group(1)
                    names = [n.strip().strip('"\'') for n in list_str.split(",")]
                    for name in names:
                        if not name or len(name) > 60 or not re.match(r'^[a-zA-Z_]\w*$', name):
                            continue
                        lineno = content[:m.start()].count("\n") + 1
                        key = f"{path}:{lineno}:{name}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(ScanFinding(
                                scanner_name=self.name(),
                                category="tool_definition",
                                file_path=path,
                                line_number=lineno,
                                match_text=name,
                                capability_tag="tool-use",
                                confidence=0.75,
                            ))
            else:
                for m in pattern.finditer(content):
                    tool_name = m.group(1).strip()
                    if not tool_name or len(tool_name) > 80:
                        continue
                    lineno = content[:m.start()].count("\n") + 1
                    key = f"{path}:{lineno}:{tool_name}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(ScanFinding(
                            scanner_name=self.name(),
                            category="tool_definition",
                            file_path=path,
                            line_number=lineno,
                            match_text=f"{tool_name} ({decorator})",
                            capability_tag="tool-use",
                            confidence=0.87,
                        ))
        return findings

    def _scan_tools_yaml(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse tools.yaml for named tool definitions."""
        findings = []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings

        tools = data if isinstance(data, list) else data.get("tools", []) if isinstance(data, dict) else []
        for item in tools:
            if isinstance(item, dict):
                tool_name = item.get("name", "")
            elif isinstance(item, str):
                tool_name = item
            else:
                continue
            if tool_name:
                key = f"{path}::{tool_name}"
                if key not in seen:
                    seen.add(key)
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="tool_definition",
                        file_path=path,
                        line_number=0,
                        match_text=str(tool_name),
                        capability_tag="tool-use",
                        confidence=0.88,
                    ))
        return findings

    def _scan_flow_dag(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Parse flow.dag.yaml for tool/python_func nodes."""
        findings = []
        try:
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        for node in data.get("nodes", []):
            if not isinstance(node, dict):
                continue
            if node.get("type") in ("python_func", "tool", "custom_llm"):
                node_name = node.get("name", "")
                if node_name:
                    key = f"{path}::{node_name}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(ScanFinding(
                            scanner_name=self.name(),
                            category="tool_definition",
                            file_path=path,
                            line_number=0,
                            match_text=str(node_name),
                            capability_tag="tool-use",
                            confidence=0.88,
                        ))
        return findings
