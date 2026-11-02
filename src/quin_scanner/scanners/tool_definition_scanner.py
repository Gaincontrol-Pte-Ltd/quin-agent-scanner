"""ToolDefinitionScanner — extracts named tool definitions from code and config files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from quin_scanner.inventory.evidence import ToolSite, clean_name
from quin_scanner.models import ScanFinding
from quin_scanner.scanners.base import BaseScanner

if TYPE_CHECKING:
    from quin_scanner.file_index import FileIndex
    from quin_scanner.repo_accessor import RepoAccessor

_CODE_EXTENSIONS = {".py", ".ts", ".js", ".jsx", ".tsx", ".mjs"}

# Tool definition patterns
_TOOL_CODE_PATTERNS = [
    # @tool decorator then def function_name (LangChain / CrewAI / Strands / Microsoft
    # Agent Framework). Optional call-style args, e.g. @tool(approval_mode="never_require").
    (re.compile(r'@tool\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@tool"),
    # @function_tool decorator (OpenAI Agents SDK)
    (re.compile(r'@function_tool\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@function_tool"),
    # @register_tool decorator (MetaGPT)
    (re.compile(r'@register_tool\s*(?:\([^)]*\))?\s*\n\s*class\s+(\w+)', re.MULTILINE), "@register_tool"),
    # @kernel_function decorator (Semantic Kernel)
    (re.compile(r'@kernel_function\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@kernel_function"),
    # @register_function decorator (AutoGen)
    (re.compile(r'@register_function\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)', re.MULTILINE), "@register_function"),
    # FunctionTool(name="...", ...)
    (re.compile(r'FunctionTool\s*\(\s*(?:[^)]*?,\s*)?name\s*=\s*["\']([^"\']+)["\']'), "FunctionTool"),
    # Tool(name="...", ...)
    (re.compile(r'\bTool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']'), "Tool"),
    # StructuredTool.from_function(name="...", ...)
    (re.compile(r'StructuredTool\.from_function\s*\([^)]*?name\s*=\s*["\']([^"\']+)["\']'), "StructuredTool"),
    # createTool({ id: "...", ... }) — Mastra
    (re.compile(r'createTool\s*\(\s*\{[^}]{0,300}?id\s*:\s*["\']([^"\']+)["\']'), "createTool"),
    # tools=[tool1, tool2] — capture individual tool variable names
    (re.compile(r'tools\s*=\s*\[([^\]]+)\]'), "tool_list"),
]

# Class inheritance patterns for tool/action definitions
_TOOL_CLASS_PATTERNS = [
    # class Foo(BaseTool) — LangChain, CrewAI, generic
    (re.compile(r'class\s+(\w+)\s*\(\s*BaseTool\s*\)'), "BaseTool", 0.85),
    # class Foo(Tool) — Dify, generic
    (re.compile(r'class\s+(\w+)\s*\(\s*Tool\s*\)'), "Tool subclass", 0.85),
    # class Foo(Action) — MetaGPT (lower confidence: Action is a common class name)
    (re.compile(r'class\s+(\w+)\s*\(\s*Action\s*\)'), "Action subclass", 0.65),
    # class Foo(ToolProviderController) — Dify plugin
    (re.compile(r'class\s+(\w+)\s*\(\s*(?:Tool)?ProviderController\s*\)'), "ToolProvider", 0.85),
]

# Tool registration call patterns
_TOOL_REGISTRATION_PATTERNS = [
    # .register_tool("name") or .register_tool(tool_obj)
    (re.compile(r'\.register_tool\s*\(\s*["\'](\w+)["\']'), "register_tool"),
    # kernel.add_plugin(plugin_obj) — Semantic Kernel (scoped to kernel. prefix)
    (re.compile(r'kernel\.add_plugin\s*\(\s*(?:plugin\s*=\s*)?(\w+)'), "add_plugin"),
    # toolbox.add(tool) / tools.append(tool)
    (re.compile(r'(?:toolbox|tool_registry)\s*\.\s*(?:add|register)\s*\(\s*(\w+)'), "toolbox_add"),
]

_REGISTRATION_LABELS = frozenset(label for _, label in _TOOL_REGISTRATION_PATTERNS)

# Config file names that define tools
_TOOL_CONFIG_NAMES = {"tools.yaml", "tools.yml"}

# Directories that typically hold tool implementation files
_TOOL_DIR_NAMES = {"tools", "tool", "tool_definitions"}

# Pattern: async def func_name(...) or def func_name(...) at top level in a tools/ file
_FUNC_IN_TOOLS_DIR_RE = re.compile(
    r'^(?:async\s+)?def\s+(\w+)\s*\(', re.MULTILINE,
)
# Skip common non-tool function names
_FUNC_SKIP_NAMES = frozenset({
    "__init__", "setup", "teardown", "main", "run", "test",
    "configure", "register", "get", "set", "validate",
})

# Markdown "## Tools Required" section pattern
_MD_TOOLS_SECTION_RE = re.compile(
    r'##\s+Tools\s+Required\s*\n((?:[-*]\s+.+\n?)+)', re.MULTILINE | re.IGNORECASE,
)
_MD_TOOL_ITEM_RE = re.compile(r'[-*]\s+(.+)')

# Directories that hold agent specs (for markdown tool extraction)
_AGENT_DIR_NAMES = {"agents", "agent", "agent_specs", "agent-specs"}

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
        self._sites: list[ToolSite] = []

        for path in file_index.all_files():
            # Test files give the inventory evidence (tagged scope: test) but no findings, as before.
            is_test = _is_test_path(path)
            p = Path(path)
            fname = p.name.lower()
            suffix = p.suffix.lower()
            kind: str | None = None  # None: findings carry a "name (label)" text; else every finding is this kind

            try:
                if suffix in _CODE_EXTENSIONS:
                    content = accessor.read_file(path)
                    found = self._scan_code(content, path, seen)
                    if self._in_tool_dir(path):
                        try:
                            found += self._scan_tool_dir_functions(content, path, seen)
                        except Exception:
                            pass   # the code findings above are kept
                elif fname in _TOOL_CONFIG_NAMES:
                    found = self._scan_tools_yaml(accessor.read_file(path), path, seen)
                    kind = "config"
                elif fname == "flow.dag.yaml":
                    found = self._scan_flow_dag(accessor.read_file(path), path, seen)
                    kind = "graph_node"
                elif suffix == ".md" and self._in_agent_dir(path):
                    found = self._scan_md_tools_required(accessor.read_file(path), path, seen)
                else:
                    continue
            except Exception:
                continue
            if not is_test:
                findings.extend(found)
            try:
                self._sites_from(found, kind)
            except Exception:
                pass  # evidence is best effort: it never costs a file its findings

        return findings

    def _sites_from(self, found: list[ScanFinding], kind: str | None) -> None:
        """Tool definitions among one file's findings; bare names from tools=[...] lists are references, not definitions.

        ``kind`` is set by the caller for tools.yaml / flow.dag.yaml, whose findings are bare names on line 0; the kind
        comes from which parser produced them, never from the text or the line number. Code and agent-spec findings
        end in ``(label)``; a bare name there is a ``tools=[...]`` reference.
        """
        for f in found:
            if kind is not None:
                name, site_kind = f.match_text, kind
            else:
                name, sep, label = f.match_text.rpartition(" (")
                if not sep or not label.endswith(")"):
                    continue                  # a tools=[...] reference
                label = label[:-1]
                if label in _REGISTRATION_LABELS:
                    continue                  # a registration call references a tool; it does not define one
                site_kind = {"tools/": "function", "agent spec": "agent_spec"}.get(label, label)
            # Normalised like agent names (and redacted again: idempotent, keeps that local); empty → no site.
            cleaned = clean_name(name)
            if cleaned:
                self._sites.append(ToolSite(name=cleaned, kind=site_kind, file_path=f.file_path,
                                            line=f.line_number or None))

    def evidence(self) -> list[ToolSite]:
        """Typed tool definition sites from the last scan(), test files included, sorted by location."""
        return sorted(getattr(self, "_sites", []), key=lambda s: (s.file_path, s.line or 0, s.name))

    def _scan_code(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        findings = []
        # Decorator and constructor patterns
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

        # Class inheritance patterns (BaseTool, Action, etc.)
        for pattern, label, conf in _TOOL_CLASS_PATTERNS:
            for m in pattern.finditer(content):
                class_name = m.group(1).strip()
                if not class_name or len(class_name) > 80:
                    continue
                lineno = content[:m.start()].count("\n") + 1
                key = f"{path}:{lineno}:{class_name}"
                if key not in seen:
                    seen.add(key)
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="tool_definition",
                        file_path=path,
                        line_number=lineno,
                        match_text=f"{class_name} ({label})",
                        capability_tag="tool-use",
                        confidence=conf,
                    ))

        # Tool registration calls
        for pattern, label in _TOOL_REGISTRATION_PATTERNS:
            for m in pattern.finditer(content):
                tool_ref = m.group(1).strip()
                if not tool_ref or len(tool_ref) > 80:
                    continue
                # Skip common non-tool variable names
                if tool_ref.startswith("_") or tool_ref in _FUNC_SKIP_NAMES:
                    continue
                lineno = content[:m.start()].count("\n") + 1
                key = f"{path}:{lineno}:{tool_ref}"
                if key not in seen:
                    seen.add(key)
                    findings.append(ScanFinding(
                        scanner_name=self.name(),
                        category="tool_definition",
                        file_path=path,
                        line_number=lineno,
                        match_text=f"{tool_ref} ({label})",
                        capability_tag="tool-use",
                        confidence=0.80,
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

    @staticmethod
    def _in_tool_dir(path: str) -> bool:
        """Return True if the file is inside a tools/ (or similar) directory."""
        parts = Path(path).parts
        return any(p.lower() in _TOOL_DIR_NAMES for p in parts[:-1])

    @staticmethod
    def _in_agent_dir(path: str) -> bool:
        """Return True if the file is inside an agents/ directory."""
        parts = Path(path).parts
        return any(p.lower() in _AGENT_DIR_NAMES for p in parts[:-1])

    def _scan_tool_dir_functions(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Detect public function definitions in files under tools/ directories."""
        findings = []
        for m in _FUNC_IN_TOOLS_DIR_RE.finditer(content):
            func_name = m.group(1)
            if func_name.startswith("_") or func_name in _FUNC_SKIP_NAMES:
                continue
            lineno = content[:m.start()].count("\n") + 1
            key = f"{path}:{lineno}:{func_name}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="tool_definition",
                file_path=path,
                line_number=lineno,
                match_text=f"{func_name} (tools/)",
                capability_tag="tool-use",
                confidence=0.80,
            ))
        return findings

    def _scan_md_tools_required(self, content: str, path: str, seen: set[str]) -> list[ScanFinding]:
        """Extract tool names from '## Tools Required' sections in agent markdown specs."""
        findings = []
        section_m = _MD_TOOLS_SECTION_RE.search(content)
        if not section_m:
            return findings
        for item_m in _MD_TOOL_ITEM_RE.finditer(section_m.group(1)):
            tool_name = item_m.group(1).strip()
            if not tool_name or len(tool_name) > 100:
                continue
            key = f"{path}::md::{tool_name}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="tool_definition",
                file_path=path,
                line_number=0,
                match_text=f"{tool_name} (agent spec)",
                capability_tag="tool-use",
                confidence=0.82,
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
