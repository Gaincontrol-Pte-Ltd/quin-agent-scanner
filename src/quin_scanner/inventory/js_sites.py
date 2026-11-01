"""Agent sites in JavaScript/TypeScript: ``new Agent({...})`` object literals (AgentInstanceScanner's evidence)."""
from __future__ import annotations

import re

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef
from quin_scanner.redaction import redact_secrets

_AGENT_CALL = re.compile(r"\b(?:new\s+)?(?:Agent|AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(\s*\{")
_NAME = re.compile(r"\bname\s*:\s*(['\"])(.*?)\1", re.DOTALL)
_TOOLS_KEY = re.compile(r"\btools\s*:")
_TOOLS = re.compile(r"\btools\s*:\s*\[([^\]]*)\]", re.DOTALL)
_TOOL_REF = re.compile(r"^\s*([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*$")
_STRING_FIELD = r"\b{key}\s*:\s*(['\"`])(.*?)\1"
_EXPR_FIELD = r"\b{key}\s*:\s*([A-Za-z_$][\w$.]*(?:\([^)]*\))?)"


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


def _field(body: str, key: str) -> tuple[str, str] | None:
    """("literal", text) for a quoted value, ("expr", text) for an identifier or call, else None."""
    match = re.search(_STRING_FIELD.format(key=key), body, re.DOTALL)
    if match:
        return "literal", match.group(2)
    match = re.search(_EXPR_FIELD.format(key=key), body)
    if match:
        return "expr", match.group(1)
    return None


def _tool_refs(body: str) -> tuple[str, ...] | None:
    tools = _TOOLS.search(body)
    if tools is None:
        return None if _TOOLS_KEY.search(body) else ()
    refs = []
    for item in tools.group(1).split(","):
        match = _TOOL_REF.match(item)
        if match and match.group(1).strip("'\""):
            refs.append(match.group(1).strip("'\""))
    return tuple(refs)


def agent_sites(content: str, path: str) -> list[AgentSite]:
    sites: list[AgentSite] = []
    for call in _AGENT_CALL.finditer(content):
        opening = call.end() - 1
        closing = _matching_brace(content, opening)
        if closing is None:
            continue
        body = content[opening + 1:closing]
        name_match = _NAME.search(body)
        instructions = NO_INSTRUCTIONS
        found = _field(body, "instructions")
        if found:
            instructions = InstructionsRef.literal(found[1]) if found[0] == "literal" else InstructionsRef("var", found[1])
        model_expr = None
        found = _field(body, "model")
        if found:
            kind, text = found
            model_expr = redact_secrets(text if kind == "literal" or "(" in text else f"var:{text}")
        sites.append(AgentSite(
            role="both", kind="constructor",
            name=name_match.group(2).strip() or None if name_match else None,
            file_path=path, line=content.count("\n", 0, call.start()) + 1,
            instructions=instructions, model_expr=model_expr, tool_refs=_tool_refs(body),
        ))
    return sites
