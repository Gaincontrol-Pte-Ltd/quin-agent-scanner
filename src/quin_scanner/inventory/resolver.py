"""Turn scanner evidence into the inventory of record: agents with instances, tools, links and flags.

Deterministic: no I/O beyond the scope rules and no LLM. The same sites always give the same output,
sorted by ID, whatever their input order.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from typing import Iterable

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.scope import scope_of
from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    AgentToolRelationship,
    EvidenceRef,
    InstanceTool,
    RiskIndicator,
    ToolUsage,
)
from quin_scanner.risk_taxonomy import get_control_label

_SCOPE_RANK = {"production": 0, "test": 1, "example": 2}


@dataclass
class Inventory:
    agents: list[AgentProfile] = field(default_factory=list)
    tools: list[ToolUsage] = field(default_factory=list)
    relationships: list[AgentToolRelationship] = field(default_factory=list)
    # agent id → "literal" | "file:<path>" | "var:<name>" | "config:<key>" | "none", for the LLM digest only
    instructions: dict[str, str] = field(default_factory=dict)


def resolve(
    agent_sites: Iterable[AgentSite],
    tool_sites: Iterable[ToolSite],
    extra_tools: Iterable[ToolUsage] = (),
) -> Inventory:
    tools = _resolve_tools(tool_sites, extra_tools)
    return Inventory(tools=tools)


def _resolve_tools(tool_sites: Iterable[ToolSite], extra_tools: Iterable[ToolUsage]) -> list[ToolUsage]:
    """One tool per (name, file). A name defined in more than one file is a collision: its IDs carry the path."""
    by_name: dict[str, dict[str, list[ToolSite]]] = defaultdict(dict)
    for site in sorted(tool_sites, key=lambda s: (s.name, s.file_path, s.line or 0)):
        by_name[site.name].setdefault(site.file_path, []).append(site)
    tools: list[ToolUsage] = []
    for name, files in by_name.items():
        collision = len(files) > 1
        for path, sites in files.items():
            tools.append(ToolUsage(
                tool_name=name, tool_type="tool_definition", source_file=path, line_number=sites[0].line,
                id=f"tool:{name}@{path}" if collision else f"tool:{name}", scope=scope_of(path),
            ))
    # Skills and external services: first name wins, except that an external service types a same-named definition.
    known = {t.tool_name.casefold(): t for t in tools}
    for extra in extra_tools:
        existing = known.get(extra.tool_name.casefold())
        if existing is None:
            added = replace(extra, id=f"tool:{extra.tool_name}", scope=scope_of(extra.source_file))
            tools.append(added)
            known[extra.tool_name.casefold()] = added
        elif extra.tool_type == "external_service" and existing.tool_type == "tool_definition":
            existing.tool_type = "external_service"
            existing.service_category = extra.service_category
    return sorted(tools, key=lambda t: t.id)


def fallback(agent_sites: Iterable[AgentSite]) -> Inventory:
    """Used only if resolve() raised: one weak agent per site and no tools, so the report is still produced."""
    raise NotImplementedError  # completed in Task 9
