"""Evidence-based links between Python agent instances and configured tools."""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from quin_scanner.models import AgentToolRelationship, ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.file_index import FileIndex


_AGENT_CONSTRUCTORS = {
    "Agent", "AssistantAgent", "UserProxyAgent", "ConversableAgent",
    "GroupChatManager", "Runner",
}
_JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs")
_JS_AGENT_CALL = re.compile(
    r"\b(?:new\s+)?(?:Agent|AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(\s*\{",
)
_JS_NAME = re.compile(r"\bname\s*:\s*(['\"])(.*?)\1", re.DOTALL)
_JS_TOOLS = re.compile(r"\btools\s*:\s*\[([^\]]*)\]", re.DOTALL)
_JS_TOOL_REF = re.compile(r"^\s*([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*$")


def _matching_brace(content: str, opening: int) -> int | None:
    """Find a closing brace while ignoring braces inside strings and comments."""
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    i = opening
    while i < len(content):
        char = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif char == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _javascript_relationships(
    content: str, path: str, known_agents: set[str]
) -> list[AgentToolRelationship]:
    found: list[AgentToolRelationship] = []
    for call in _JS_AGENT_CALL.finditer(content):
        opening = call.end() - 1
        closing = _matching_brace(content, opening)
        if closing is None:
            continue
        body = content[opening + 1:closing]
        name_match = _JS_NAME.search(body)
        tools_match = _JS_TOOLS.search(body)
        if not name_match or not tools_match:
            continue
        agent_name = name_match.group(2).strip()
        if agent_name.casefold() not in known_agents:
            continue
        line_number = content.count("\n", 0, call.start()) + 1
        for ref in tools_match.group(1).split(","):
            ref_match = _JS_TOOL_REF.match(ref)
            if not ref_match:
                continue
            tool_name = ref_match.group(1).strip("'\"")
            if tool_name:
                found.append(AgentToolRelationship(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    source_file=path,
                    line_number=line_number,
                ))
    return found


def _tool_reference(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                if isinstance(keyword.value.value, str):
                    return keyword.value.value
    return None


def discover_agent_tool_relationships(
    accessor: RepoAccessor,
    file_index: FileIndex,
    findings: list[ScanFinding],
) -> list[AgentToolRelationship]:
    """Link explicit Python ``Agent(..., tools=[...])`` references to agents.

    The relationship is emitted only when Quin independently detected the
    agent instance. A matching tool definition location is attached when one
    was also discovered; the direct reference remains useful without it.
    """
    agents_by_file: dict[str, set[str]] = defaultdict(set)
    tools_by_name: dict[str, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        if finding.scanner_name == "AgentInstanceScanner":
            agents_by_file[finding.file_path].add(finding.match_text.strip().casefold())
        elif finding.scanner_name == "ToolDefinitionScanner":
            name = finding.match_text.split(" (")[0].strip().casefold()
            tools_by_name[name].append(finding)

    relationships: dict[tuple[str, str, str, int], AgentToolRelationship] = {}
    for path in file_index.files_by_extension(".py"):
        if not agents_by_file.get(path):
            continue
        try:
            tree = ast.parse(accessor.read_file(path), filename=path)
        except (OSError, SyntaxError, UnicodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            constructor = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else ""
            )
            if constructor not in _AGENT_CONSTRUCTORS:
                continue
            name_arg = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
            if not isinstance(name_arg, ast.Constant) or not isinstance(name_arg.value, str):
                continue
            agent_name = name_arg.value.strip()
            if agent_name.casefold() not in agents_by_file[path]:
                continue
            tools_arg = next((kw.value for kw in node.keywords if kw.arg == "tools"), None)
            if not isinstance(tools_arg, (ast.List, ast.Tuple, ast.Set)):
                continue

            for item in tools_arg.elts:
                tool_name = _tool_reference(item)
                if not tool_name or not tool_name.strip():
                    continue
                tool_name = tool_name.strip()
                tool_matches = tools_by_name.get(tool_name.casefold(), [])
                tool_finding = max(
                    tool_matches,
                    key=lambda f: (
                        " (" in f.match_text,  # Prefer an actual definition to a tools-list reference.
                        f.confidence,
                        f.file_path == path,
                    ),
                    default=None,
                )
                key = (path, agent_name.casefold(), tool_name.casefold(), node.lineno)
                relationships[key] = AgentToolRelationship(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    source_file=path,
                    line_number=node.lineno,
                    tool_source_file=tool_finding.file_path if tool_finding else "",
                    tool_line_number=tool_finding.line_number if tool_finding else None,
                    evidence="explicit_tools_argument",
                )

    for ext in _JS_EXTENSIONS:
        for path in file_index.files_by_extension(ext):
            known_agents = agents_by_file.get(path)
            if not known_agents:
                continue
            try:
                content = accessor.read_file(path)
            except OSError:
                continue
            for relationship in _javascript_relationships(content, path, known_agents):
                key = (
                    path,
                    relationship.agent_name.casefold(),
                    relationship.tool_name.casefold(),
                    relationship.line_number or 0,
                )
                relationships[key] = relationship

    return sorted(
        relationships.values(),
        key=lambda edge: (edge.source_file, edge.line_number or 0, edge.agent_name, edge.tool_name),
    )
