"""Turn scanner evidence into the inventory of record: agents with instances, tools, links and flags.

Deterministic: no I/O beyond the scope rules and no LLM. The same sites always give the same output,
sorted by ID, whatever their input order.

Known limitation: IDs are not escaped. An agent name containing ``/`` can make an instance ID
(``agent:<name>/<path>#<n>``) equal to another agent's, e.g. agent ``a`` in ``b/src/x.py`` and agent ``a/b``
in ``src/x.py``. Agent IDs stay unique; only instance IDs can clash. Accepted: such names are rare.
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


# (name, instructions, anchor): the anchor is the agents.yaml a config identity belongs to, the file of a
# definition that links to nothing, or "" for code identities.
_GroupKey = tuple[str, InstructionsRef, str]
# A site after config linking: the site (renamed to its config entry's name), its anchor, and whether its
# config key was ambiguous (several entries equally near).
_Placed = tuple[AgentSite, str, bool]
_ToolRefs = tuple[str, ...] | None


def _site_key(site: AgentSite) -> tuple:
    """Total order on sites, so grouping and numbering never depend on input order."""
    return (
        site.file_path, site.line or 0, site.line is None, site.name or "", site.kind, site.role,
        site.instructions.kind, site.instructions.value,
        site.tool_refs is None, site.tool_refs or (),
        site.model_expr or "", site.model_expr is None, site.in_loop, site.framework_hint,
    )


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
    """Same name and same instructions fingerprint → one agent; see spec §6 step 3 and plan clarifications 11–12."""
    placed = _link_config_sites(sorted(agent_sites, key=_site_key))
    groups: dict[_GroupKey, _Group] = {}
    unknown_instances: list[AgentSite] = []
    unknown_definitions: list[AgentSite] = []
    unnamed: list[AgentSite] = []
    for site, anchor, ambiguous in placed:
        if not site.name:
            unnamed.append(site)
        elif site.instructions.is_known:
            group = _add(groups, (site.name, site.instructions, anchor), site)
            if ambiguous:
                group.flags.add("ambiguous_instance")
        elif site.role == "definition":
            unknown_definitions.append(site)
        else:
            unknown_instances.append(site)
    _join_unknown_instances(groups, unknown_instances)
    _join_unknown_definitions(groups, unknown_definitions)
    _flag_name_collisions(groups.values())
    for group in groups.values():
        group.sites.sort(key=_site_key)
    weak = [_Group(None, site.instructions, [site]) for site in unnamed]
    return list(groups.values()) + weak


def _add(groups: dict[_GroupKey, _Group], key: _GroupKey, site: AgentSite) -> _Group:
    group = groups.setdefault(key, _Group(key[0], key[1]))
    group.sites.append(site)
    return group


def _link_config_sites(sites: list[AgentSite]) -> list[_Placed]:
    """CrewAI: code that loads ``agents_config['key']`` is an instance of the nearest agents.yaml entry with that key.

    Nearest = the entry whose directory shares the most leading path components with the code's file. A tie leaves
    the code site unlinked (its own name and instructions) and marks it ambiguous.
    """
    entries: dict[str, list[AgentSite]] = defaultdict(list)
    for site in sites:
        if site.kind == "config_entry" and site.instructions.kind == "config" and site.name:
            entries[site.instructions.value].append(site)
    placed: list[_Placed] = []
    for site in sites:
        if site.kind == "config_entry":
            placed.append((site, site.file_path, False))
            continue
        candidates = entries.get(site.instructions.value, []) if site.instructions.kind == "config" else []
        if not candidates:
            placed.append((site, "", False))
            continue
        nearest = _nearest(candidates, site.file_path)
        if nearest is None:
            placed.append((site, "", True))
        else:
            placed.append((replace(site, name=nearest.name), nearest.file_path, False))
    return placed


def _directory_parts(path: str) -> list[str]:
    return path.replace("\\", "/").split("/")[:-1]


def _nearest(candidates: list[AgentSite], path: str) -> AgentSite | None:
    here = _directory_parts(path)

    def shared(entry: AgentSite) -> int:
        depth = 0
        for a, b in zip(_directory_parts(entry.file_path), here):
            if a != b:
                break
            depth += 1
        return depth

    best = max(shared(entry) for entry in candidates)
    winners = [entry for entry in candidates if shared(entry) == best]
    return winners[0] if len(winners) == 1 else None


def _join_unknown_instances(groups: dict[_GroupKey, _Group], sites: list[AgentSite]) -> None:
    """An instance without known instructions joins the single same-named agent, in any file; else its own."""
    known_by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups.values():
        known_by_name[group.name].append(group)
    for site in sites:
        candidates = known_by_name.get(site.name, [])
        if len(candidates) == 1:
            candidates[0].sites.append(site)
            continue
        group = _add(groups, (site.name, NO_INSTRUCTIONS, ""), site)
        if candidates:
            group.flags.add("ambiguous_instance")


def _join_unknown_definitions(groups: dict[_GroupKey, _Group], sites: list[AgentSite]) -> None:
    """A definition without known instructions (subclass, decorator) links in its own file only (spec D9).

    It joins the single same-named agent that has a site in its file; otherwise it is an agent of its own, one per file.
    """
    for site in sites:
        same_file = [
            group for group in groups.values()
            if group.name == site.name and any(s.file_path == site.file_path for s in group.sites)
        ]
        if len(same_file) == 1:
            same_file[0].sites.append(site)
            continue
        group = _add(groups, (site.name, NO_INSTRUCTIONS, site.file_path), site)
        if len(same_file) > 1:
            group.flags.add("ambiguous_instance")


def _flag_name_collisions(groups: Iterable[_Group]) -> None:
    by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups:
        by_name[group.name].append(group)
    for same_name in by_name.values():
        if len(same_name) > 1:
            for group in same_name:
                group.flags.add("name_collision")


def _definition(group: _Group) -> AgentSite:
    sites = group.sites
    return next((s for s in sites if s.role == "definition"), None) or next((s for s in sites if s.role == "both"), sites[0])


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


def _link_tool(ref: str, path: str, tool_index: dict[str, list[ToolUsage]]) -> ToolUsage | None:
    """A tool defined in the same file, else a repo-unique name, else None (unresolved).

    The exact-case name is tried first (same file, then repo-unique), then the case-insensitive one.
    """
    candidates = tool_index.get(ref.casefold(), [])
    exact = [t for t in candidates if t.tool_name == ref]
    for pool in (exact, candidates):
        same_file = [t for t in pool if t.source_file == path]
        if same_file:
            return same_file[0]
        if len(pool) == 1:
            return pool[0]
    return None


def _build_agent(
    group: _Group, agent_id: str, tool_index: dict[str, list[ToolUsage]],
) -> tuple[AgentProfile, list[AgentToolRelationship]]:
    definition = _definition(group)
    # A CrewAI instance that passes no tools= gets the tools its agents.yaml entry lists (plan clarification 13).
    inherited = definition.tool_refs if definition.kind == "config_entry" else None
    instance_sites = [s for s in group.sites if s.role in ("instance", "both")] or list(group.sites)
    per_file: dict[str, int] = defaultdict(int)
    built: list[tuple[AgentInstance, AgentSite, _ToolRefs]] = []
    relationships: list[AgentToolRelationship] = []
    for site in instance_sites:
        per_file[site.file_path] += 1
        instance_id = f"{agent_id}/{site.file_path}#{per_file[site.file_path]}"
        refs = site.tool_refs if site.tool_refs is not None else inherited
        tools: list[InstanceTool] = []
        for ref in refs or ():
            linked = _link_tool(ref, site.file_path, tool_index)
            tools.append(InstanceTool(name=ref, tool_id=linked.id if linked else None, resolved=linked is not None))
            relationships.append(AgentToolRelationship(
                agent_name=group.name or "",
                tool_name=ref,
                source_file=site.file_path,
                line_number=site.line,
                tool_source_file=linked.source_file if linked else "",
                tool_line_number=linked.line_number if linked else None,
                agent_id=agent_id,
                instance_id=instance_id,
                tool_id=linked.id if linked else None,
            ))
        instance = AgentInstance(
            id=instance_id,
            file=site.file_path,
            line=site.line,
            scope=scope_of(site.file_path),
            multiplicity="many" if site.in_loop else "one",
            model=site.model_expr,
            tools=tools,
        )
        built.append((instance, site, refs))
    risk_signals, divergence_flags = _divergence(group.name or agent_id, built)
    instances = [instance for instance, _, _ in built]
    agent = AgentProfile(
        name=group.name or "",
        agent_type="unknown",
        goal="",
        risk_signals=risk_signals,
        tools=sorted({t.name for instance in instances for t in instance.tools}),
        source_file=definition.file_path,
        id=agent_id,
        identity="strong" if group.name else "weak",
        # Spec D5: production if any instance is, else test, else example.
        scope=min((instance.scope for instance in instances), key=_SCOPE_RANK.__getitem__),
        flags=sorted(group.flags | divergence_flags),
        provenance={"name": "static", "tools": "static"},
        instances=instances,
    )
    return agent, relationships


def _divergence(
    label: str, built: list[tuple[AgentInstance, AgentSite, _ToolRefs]],
) -> tuple[list[RiskIndicator], set[str]]:
    """Flags for instances that differ; a T006 signal when production instances are given different tools."""
    flags: set[str] = set()
    known = [(instance, frozenset(refs)) for instance, _, refs in built if refs is not None]
    if len({tools for _, tools in known}) > 1:
        flags.add("tool_divergence")
    if len({site.model_expr for _, site, _ in built if site.model_expr}) > 1:
        flags.add("model_divergence")
    production = [(instance, tools) for instance, tools in known if instance.scope == "production"]
    tool_sets = {tools for _, tools in production}
    if len(tool_sets) < 2:
        return [], flags
    differing = sorted(frozenset.union(*tool_sets) - frozenset.intersection(*tool_sets))
    signal = RiskIndicator(
        signal=f"Instances of agent '{label}' are given different tools: {', '.join(differing)}",
        recommended_controls=[get_control_label("C003")],
        threat_id="T006",
        severity="medium",
        evidence_refs=[
            EvidenceRef(file_path=instance.file, line_number=instance.line, scanner="AgentInstanceScanner")
            for instance, _ in production
        ],
    )
    return [signal], flags


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
    # Skills and external services, in a fixed order: the first of a name (case-insensitive) wins, except that an
    # external service types every same-named definition.
    known: dict[str, list[ToolUsage]] = defaultdict(list)
    for t in tools:
        known[t.tool_name.casefold()].append(t)
    ordered = sorted(extra_tools, key=lambda t: (
        t.tool_name.casefold(), t.tool_type, t.source_file, t.tool_name, t.service_category, t.line_number or 0,
    ))
    for extra in ordered:
        existing = known[extra.tool_name.casefold()]
        if not existing:
            existing.append(replace(extra, id=f"tool:{extra.tool_name}", scope=scope_of(extra.source_file)))
            tools.append(existing[0])
        elif extra.tool_type == "external_service":
            for definition in existing:
                if definition.tool_type == "tool_definition":
                    definition.tool_type = "external_service"
                    definition.service_category = extra.service_category
    return sorted(tools, key=lambda t: t.id)


def fallback(agent_sites: Iterable[AgentSite]) -> Inventory:
    """Used only if resolve() raised: one weak agent per site and no tools, so the report is still produced."""
    inventory = Inventory()
    per_file: dict[str, int] = defaultdict(int)
    for site in sorted(agent_sites, key=_site_key):
        per_file[site.file_path] += 1
        inventory.agents.append(AgentProfile(
            name=site.name or "", agent_type="unknown", goal="", source_file=site.file_path,
            id=f"agent:@{site.file_path}#{per_file[site.file_path]}", identity="weak",
            scope=scope_of(site.file_path), provenance={"name": "static"},
        ))
    return inventory
