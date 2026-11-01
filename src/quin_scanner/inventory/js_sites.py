"""Agent sites in JavaScript/TypeScript: ``new Agent({...})`` object literals (AgentInstanceScanner's evidence)."""
from __future__ import annotations

import dataclasses
import re

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef
from quin_scanner.redaction import redact_secrets

_AGENT_CALL = re.compile(r"\b(?:new\s+)?(?:Agent|AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(\s*\{")
# A name, dotted name or quoted string; every item of a tools list must be one for the list to be known.
_TOOL_REF = re.compile(r"^\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|'[^']+'|\"[^\"]+\")\s*$")
_EXPR = re.compile(r"[A-Za-z_$][\w$.]*(?:\([^)]*\))?")
_OPENERS = frozenset("{[(")
# A key starts the object body or follows a top-level comma (so ``x ? name : y`` inside a value is not a key).
_KEY_START = r"(?:^|,)\s*"
_TOOLS_SHORTHAND = re.compile(rf"{_KEY_START}tools\s*(?:,|$)")
_SPREAD = re.compile(rf"{_KEY_START}\.\.\.")
_CLOSERS = frozenset("}])")


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


def _top_level_view(text: str) -> str:
    """``text`` with nested ``{}``/``[]``/``()`` contents, strings and comments blanked (same length, so offsets agree).

    The delimiters of each depth-1 bracket are kept, so a bracketed value's closing position can be found in the view.
    """
    view = list(text)
    depth = 0
    quote = ""
    escaped = False
    line_comment = block_comment = False
    i = 0
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        keep = False
        if line_comment:
            line_comment = char != "\n"
        elif block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                view[i] = view[i + 1] = " "
                i += 2
                continue
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char == "/" and nxt in "/*":
            line_comment, block_comment = nxt == "/", nxt == "*"
            view[i] = view[i + 1] = " "
            i += 2
            continue
        elif char in _OPENERS:
            keep = depth == 0
            depth += 1
        elif char in _CLOSERS:
            depth = max(depth - 1, 0)
            keep = depth == 0
        else:
            keep = depth == 0
        if not keep and char != "\n":
            view[i] = " "
        i += 1
    return "".join(view)


def _string_at(text: str, start: int) -> str | None:
    """The contents of the string literal opening at ``start`` (escapes left as written), or None if it is unterminated."""
    quote = text[start]
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return text[start + 1:i]
        i += 1
    return None


def _value(body: str, view: str, key: str) -> tuple[str, str] | None:
    """The value of a top-level ``key:`` in the object body.

    ("literal", text) for a quoted string, ("template", text) for a backtick string, ("list", items) for ``[...]``,
    ("expr", text) for an identifier or call, ("other", "") for anything else; None when the key is absent.
    """
    match = re.search(rf"{_KEY_START}{key}\s*:", view)
    if match is None:
        return None
    start = match.end()
    while start < len(body) and body[start].isspace():
        start += 1
    if start >= len(body):
        return "other", ""
    char = body[start]
    if char in "'\"`":
        text = _string_at(body, start)
        if text is None:
            return "other", ""
        return ("template" if char == "`" else "literal"), text
    if char == "[":
        closing = view.find("]", start)
        return ("list", body[start + 1:closing]) if closing != -1 else ("other", "")
    expr = _EXPR.match(body, start)
    return ("expr", expr.group(0)) if expr else ("other", "")


def _top_level_items(text: str) -> list[str]:
    """``text`` split at commas that are not inside brackets, strings or comments."""
    view = _top_level_view(text)
    items, start = [], 0
    for i, char in enumerate(view):
        if char == ",":
            items.append(text[start:i])
            start = i + 1
    items.append(text[start:])
    if items and not items[-1].strip():
        items.pop()   # trailing comma, or an empty list
    return items


def _tool_refs(body: str, view: str) -> tuple[str, ...] | None:
    """() when there is no ``tools`` (or it is ``[]``/null/undefined); None for shorthand/spread or unless every item is a plain name."""
    found = _value(body, view, "tools")
    if found is None:
        # ``{ tools }`` shorthand or ``{ ...base }`` may pass tools implicitly.
        return None if _TOOLS_SHORTHAND.search(view) or _SPREAD.search(view) else ()
    kind, text = found
    if kind == "expr" and text in ("null", "undefined"):
        return ()
    if kind != "list":
        return None
    refs = []
    for item in _top_level_items(text):
        match = _TOOL_REF.match(item)
        if match is None:
            return None
        refs.append(match.group(1).strip("'\""))
    return tuple(refs)


def _name(body: str, view: str) -> str | None:
    found = _value(body, view, "name")
    if found is None or found[0] not in ("literal", "template") or (found[0] == "template" and "${" in found[1]):
        return None
    return found[1].strip() or None


def _instructions(body: str, view: str) -> InstructionsRef:
    found = _value(body, view, "instructions")
    if found is None:
        return NO_INSTRUCTIONS
    kind, text = found
    if kind in ("literal", "template"):
        return InstructionsRef.literal(text)
    return InstructionsRef("var", text) if kind == "expr" else NO_INSTRUCTIONS


def _model(body: str, view: str) -> str | None:
    found = _value(body, view, "model")
    if found is None:
        return None
    kind, text = found
    if kind in ("literal", "template"):
        return text
    if kind == "expr":
        return text if "(" in text else f"var:{text}"
    return None


def _redacted(site: AgentSite) -> AgentSite:
    """Credentials removed from every user-content string a site carries (a literal's hash is not user content)."""
    instructions = site.instructions
    if instructions.kind in ("file", "var", "config"):
        instructions = InstructionsRef(instructions.kind, redact_secrets(instructions.value))
    return dataclasses.replace(
        site,
        name=redact_secrets(site.name) if site.name else site.name,
        instructions=instructions,
        model_expr=redact_secrets(site.model_expr) if site.model_expr else site.model_expr,
        tool_refs=None if site.tool_refs is None else tuple(redact_secrets(ref) for ref in site.tool_refs),
    )


def agent_sites(content: str, path: str) -> list[AgentSite]:
    sites: list[AgentSite] = []
    for call in _AGENT_CALL.finditer(content):
        opening = call.end() - 1
        closing = _matching_brace(content, opening)
        if closing is None:
            continue
        body = content[opening + 1:closing]
        view = _top_level_view(body)   # keys are read only at the object's top level, never in nested values
        sites.append(_redacted(AgentSite(
            role="both", kind="constructor", name=_name(body, view),
            file_path=path, line=content.count("\n", 0, call.start()) + 1,
            instructions=_instructions(body, view), model_expr=_model(body, view), tool_refs=_tool_refs(body, view),
        )))
    return sites
