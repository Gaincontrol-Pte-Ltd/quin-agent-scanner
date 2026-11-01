"""Typed evidence that scanners hand to the inventory resolver. Internal: never serialised into a report."""
from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass

from quin_scanner.redaction import redact_secrets


@dataclass(frozen=True)
class InstructionsRef:
    """What an agent's instructions are: part of the agent's identity (with its name)."""
    kind: str = "none"   # "literal" | "file" | "var" | "config" | "none"
    value: str = ""      # literal → sha256 of the whitespace-normalised text; else the path, variable or config key

    @classmethod
    def literal(cls, text: str) -> InstructionsRef:
        normalised = " ".join(text.split())
        return cls("literal", hashlib.sha256(normalised.encode("utf-8", errors="surrogatepass")).hexdigest())

    @property
    def is_known(self) -> bool:
        return self.kind != "none"


NO_INSTRUCTIONS = InstructionsRef()


@dataclass(frozen=True)
class AgentSite:
    """One place in the code or configuration that defines and/or creates an agent."""
    role: str                                  # "definition" | "instance" | "both"
    kind: str                                  # "constructor" | "subclass" | "config_entry" | "decorator" | "graph_node"
    name: str | None                           # literal name only; None when dynamic
    file_path: str
    line: int | None
    instructions: InstructionsRef = NO_INSTRUCTIONS
    model_expr: str | None = None              # redacted literal or reference, e.g. "env:MODEL", "var:settings.llm"
    tool_refs: tuple[str, ...] | None = None   # () = no tools passed; None = not statically known
    tools_given: bool = False                  # a tools keyword/key was present (literal or not)
    in_loop: bool = False                      # inside a for/while/comprehension (Python only)
    framework_hint: str = ""


@dataclass(frozen=True)
class ToolSite:
    """One place that defines a tool (not a reference to one in a tools=[...] list)."""
    name: str
    kind: str                                  # the scanner's label: "@tool", "BaseTool", "config", "function", ...
    file_path: str
    line: int | None


def redacted(site: AgentSite) -> AgentSite:
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
