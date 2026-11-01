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


@dataclass
class _Group:
    name: str | None
    instructions: InstructionsRef
    sites: list[AgentSite] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


def _site_key(site: AgentSite) -> tuple:
    return (site.file_path, site.line or 0, site.name or "", site.kind)


def resolve(
    agent_sites: Iterable[AgentSite],
    tool_sites: Iterable[ToolSite],
    extra_tools: Iterable[ToolUsage] = (),
) -> Inventory:
    tools = _resolve_tools(tool_sites, extra_tools)
    tool_index: dict[str, list[ToolUsage]] = defaultdict(list)
    for t in tools:
        tool_index[t.tool_name.casefold()].append(t)
    groups = _group_agents(agent_sites)
    inventory = Inventory(tools=tools)
    for group, agent_id in sorted(zip(groups, _agent_ids(groups)), key=lambda pair: pair[1]):
        agent, relationships = _build_agent(group, agent_id, tool_index)
        inventory.agents.append(agent)
        inventory.relationships.extend(relationships)
        inventory.instructions[agent_id] = _describe(group.instructions)
    inventory.relationships.sort(key=lambda e: (e.source_file, e.line_number or 0, e.agent_name, e.tool_name))
    return inventory


def _group_agents(agent_sites: Iterable[AgentSite]) -> list[_Group]:
    """Same name and same instructions fingerprint → one agent; see spec §6 step 3."""
    sites = sorted(agent_sites, key=_site_key)
    # CrewAI: code that loads agents_config['key'] is an instance of the agents.yaml entry with that key.
    config_names = {
        s.instructions.value: s.name
        for s in sites
        if s.kind == "config_entry" and s.instructions.kind == "config" and s.name
    }
    named: list[AgentSite] = []
    unnamed: list[AgentSite] = []
    for site in sites:
        if site.kind != "config_entry" and site.instructions.kind == "config" and site.instructions.value in config_names:
            site = replace(site, name=config_names[site.instructions.value])
        (named if site.name else unnamed).append(site)

    groups: dict[tuple[str, InstructionsRef], _Group] = {}
    pending: list[AgentSite] = []
    for site in named:
        if site.instructions.is_known:
            key = (site.name, site.instructions)
            groups.setdefault(key, _Group(site.name, site.instructions)).sites.append(site)
        else:
            pending.append(site)
    known_by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups.values():
        known_by_name[group.name].append(group)
    for site in pending:
        candidates = known_by_name.get(site.name, [])
        if len(candidates) == 1:
            candidates[0].sites.append(site)
            continue
        group = groups.setdefault((site.name, NO_INSTRUCTIONS), _Group(site.name, NO_INSTRUCTIONS))
        group.sites.append(site)
        if candidates:
            group.flags.add("ambiguous_instance")

    by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups.values():
        by_name[group.name].append(group)
    for same_name in by_name.values():
        if len(same_name) > 1:
            for group in same_name:
                group.flags.add("name_collision")

    weak = [_Group(None, site.instructions, [site]) for site in unnamed]
    return list(groups.values()) + weak


def _definition(group: _Group) -> AgentSite:
    return next((s for s in group.sites if s.role in ("definition", "both")), group.sites[0])


def _agent_ids(groups: list[_Group]) -> list[str]:
    ids: list[str] = []
    weak_per_file: dict[str, int] = defaultdict(int)
    for group in groups:
        if group.name is None:
            path = group.sites[0].file_path
            weak_per_file[path] += 1
            ids.append(f"agent:@{path}#{weak_per_file[path]}")
        elif "name_collision" in group.flags:
            ids.append(f"agent:{group.name}@{_definition(group).file_path}")
        else:
            ids.append(f"agent:{group.name}")
    seen: dict[str, int] = defaultdict(int)
    unique: list[str] = []
    for agent_id in ids:
        seen[agent_id] += 1
        unique.append(agent_id if seen[agent_id] == 1 else f"{agent_id}#{seen[agent_id]}")
    return unique


def _describe(instructions: InstructionsRef) -> str:
    if instructions.kind in ("literal", "none"):
        return instructions.kind
    return f"{instructions.kind}:{instructions.value}"


def _build_agent(
    group: _Group, agent_id: str, tool_index: dict[str, list[ToolUsage]],
) -> tuple[AgentProfile, list[AgentToolRelationship]]:
    instance_sites = [s for s in group.sites if s.role in ("instance", "both")] or list(group.sites)
    per_file: dict[str, int] = defaultdict(int)
    instances: list[AgentInstance] = []
    for site in instance_sites:
        per_file[site.file_path] += 1
        instances.append(AgentInstance(
            id=f"{agent_id}/{site.file_path}#{per_file[site.file_path]}",
            file=site.file_path,
            line=site.line,
            scope=scope_of(site.file_path),
            multiplicity="many" if site.in_loop else "one",
            model=site.model_expr,
        ))
    scopes = {scope_of(s.file_path) for s in group.sites}
    agent = AgentProfile(
        name=group.name or "",
        agent_type="unknown",
        goal="",
        source_file=_definition(group).file_path,
        id=agent_id,
        identity="strong" if group.name else "weak",
        scope=min(scopes, key=_SCOPE_RANK.__getitem__),
        flags=sorted(group.flags),
        provenance={"name": "static", "tools": "static"},
        instances=instances,
    )
    return agent, []


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
