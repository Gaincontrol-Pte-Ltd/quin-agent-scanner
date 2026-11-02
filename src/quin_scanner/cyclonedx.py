"""Serializes a ScanReport's AI inventory to a CycloneDX 1.6 BOM (AI components only).

Only static inventory is exported: nothing the LLM can write, so the same commit gives the same BOM
apart from serialNumber and metadata.timestamp. Spec: docs/superpowers/specs/2026-11-02-cyclonedx-ai-bom-design.md
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    EndpointUsage,
    ModelUsage,
    ScanReport,
    ToolUsage,
    Vulnerability,
)
from quin_scanner.vuln_checker import FrameworkRef, parse_framework_ref

SPEC_VERSION = "1.6"
ROOT_REF = "repo"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5, "unknown": 6}


_TEMPLATE = re.compile(r'[{}$<>"|\\^`\s]')


class _Refs:
    """Hands out bom-refs, unique across the BOM: a value already taken gets #2, #3, ..."""

    def __init__(self) -> None:
        self._taken: set[str] = {ROOT_REF}

    def take(self, ref: str) -> str:
        candidate, n = ref, 1
        while candidate in self._taken:
            n += 1
            candidate = f"{ref}#{n}"
        self._taken.add(candidate)
        return candidate


def _repo_name(repo_path: str) -> str:
    """owner/repo for GitHub targets, the directory name for local paths."""
    clean = re.sub(r"[\\/]+$", "", repo_path).removesuffix(".git")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", clean):
        return clean
    return re.split(r"[\\/]", clean)[-1] or "repository"


def _iso_utc(value: str | None) -> str | None:
    """An ISO 8601 date or date-time as a UTC date-time (YYYY-MM-DDTHH:MM:SSZ), or None when unparsable."""
    if not value:
        return None
    text = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


def _purl(ref: FrameworkRef) -> str | None:
    """Package URL of the framework package, or None for an ecosystem without a mapping."""
    version = quote(ref.version, safe="")
    ecosystem = ref.ecosystem.lower()
    if ecosystem == "pypi":
        return f"pkg:pypi/{re.sub(r'[-_.]+', '-', ref.package).lower()}@{version}"
    if ecosystem == "npm":
        namespace, _, name = ref.package.rpartition("/")
        path = f"{quote(namespace, safe='')}/{quote(name, safe='')}" if namespace else quote(name, safe="")
        return f"pkg:npm/{path}@{version}"
    return None


def _framework(report: ScanReport, refs: _Refs, graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    """The framework component (0 or 1 item), wired to the root in *graph*."""
    ref = parse_framework_ref(report.framework)
    purl = _purl(ref) if ref else None
    if ref is None or purl is None:
        return []
    bom_ref = refs.take(purl)
    graph[ROOT_REF].add(bom_ref)
    graph[bom_ref] = set()
    return [{"type": "framework", "bom-ref": bom_ref, "name": ref.package, "version": ref.version, "purl": purl}]


def _vulnerability(v: Vulnerability, bom_ref: str, framework_ref: str) -> dict[str, Any]:
    severity = v.severity if v.severity in _SEVERITY_ORDER else "unknown"
    rating: dict[str, Any] = {}
    if v.cvss_score is not None:
        rating["score"] = v.cvss_score
    rating["severity"] = severity
    source: dict[str, Any] = {"name": "OSV"}
    if v.source_url:
        source["url"] = v.source_url
    out: dict[str, Any] = {"bom-ref": bom_ref, "id": v.cve_id, "source": source, "ratings": [rating]}
    if v.summary:
        out["description"] = v.summary
    published = _iso_utc(v.published)
    if published:
        out["published"] = published
    out["affects"] = [{"ref": framework_ref}]
    return out


def _vuln_rank(v: Vulnerability) -> tuple:
    return (_SEVERITY_ORDER.get(v.severity, _SEVERITY_ORDER["unknown"]), -(v.cvss_score or 0), v.summary, v.source_url or "")


def _vulnerabilities(report: ScanReport, refs: _Refs, framework_ref: str | None) -> list[dict[str, Any]]:
    """OSV entries with an ID only: web-search results can differ between runs (spec D2).

    When an ID repeats, the entry that ranks first (severity, then higher score, summary, URL) wins,
    whatever the input order. Refs are taken in sorted order, so collision suffixes follow sorted order.
    """
    if framework_ref is None:
        return []
    picked: dict[str, Vulnerability] = {}
    for v in report.vulnerabilities:
        if v.source == "osv" and v.cve_id and (v.cve_id not in picked or _vuln_rank(v) < _vuln_rank(picked[v.cve_id])):
            picked[v.cve_id] = v
    ordered = sorted(picked.values(), key=lambda v: (_vuln_rank(v)[0], v.cve_id))
    return [_vulnerability(v, refs.take(f"vuln:{v.cve_id}"), framework_ref) for v in ordered]


def omitted_vulnerability_count(report: ScanReport) -> int:
    """Number of web-search (non-OSV) vulnerabilities the BOM leaves out; counts those only."""
    return sum(1 for v in report.vulnerabilities if v.source != "osv")


def _occurrence(location: str, line: int | None, *, ref: str | None = None, context: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if ref:
        out["bom-ref"] = ref
    out["location"] = location
    if line is not None:
        out["line"] = line
    if context:
        out["additionalContext"] = context
    return out


def _models(report: ScanReport, refs: _Refs, graph: dict[str, set[str]]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Model components, and their bom-refs by case-folded model name (for agent dependencies)."""
    groups: dict[tuple[str, str], list[ModelUsage]] = {}
    for usage in report.model_usages:
        if usage.model_name.strip():
            groups.setdefault((usage.provider or "unknown", usage.model_name), []).append(usage)
    components: list[dict[str, Any]] = []
    by_name: dict[str, list[str]] = {}
    for (provider, name), usages in sorted(groups.items()):
        ref = refs.take(f"model:{provider}/{name}")
        graph[ref] = set()
        component: dict[str, Any] = {"type": "machine-learning-model", "bom-ref": ref, "name": name, "publisher": provider}
        places = sorted({(u.file_path, u.line_number) for u in usages if u.file_path}, key=lambda p: (p[0], p[1] is None, p[1] or 0))
        if places:
            component["evidence"] = {"occurrences": [_occurrence(file, line) for file, line in places]}
        components.append(component)
        by_name.setdefault(name.casefold(), []).append(ref)
    return sorted(components, key=lambda c: c["bom-ref"]), by_name


def _properties(**values: str) -> list[dict[str, str]]:
    """quin:<name> properties sorted by name; keyword underscores become hyphens."""
    props = [{"name": f"quin:{key.replace('_', '-')}", "value": value} for key, value in values.items()]
    return sorted(props, key=lambda p: p["name"])


def _is_literal_model(model: str | None) -> bool:
    return bool(model) and not model.startswith(("env:", "var:")) and "(" not in model


def _instance_context(instance: AgentInstance) -> str:
    parts = [f"scope={instance.scope}"]
    if instance.model:
        parts.append(f"model={instance.model}")
    parts.append("tools=unknown" if not instance.tools_known else "tools=" + ",".join(t.name for t in instance.tools))
    if instance.multiplicity == "many":
        parts.append("multiplicity=many")
    return "; ".join(parts)


def _instance_key(i: AgentInstance) -> tuple:
    return (i.file, i.line is None, i.line or 0, i.id, i.model or "", i.multiplicity, i.tools_known, tuple(t.name for t in i.tools))


def _agent(agent: AgentProfile, ref: str) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": ref,
        "name": agent.name or ref,
        "scope": "required" if agent.scope == "production" else "excluded",
        "properties": _properties(kind="agent", identity=agent.identity),
    }
    # Occurrence bom-refs hold the raw instance id here; _claim_occurrence_refs allocates them once every
    # component and service has its ref, so a component always keeps a bare id.
    instances = sorted(agent.instances, key=_instance_key)
    occurrences = [_occurrence(i.file, i.line, ref=i.id or None, context=_instance_context(i)) for i in instances if i.file]
    if occurrences:
        component["evidence"] = {"occurrences": occurrences}
    return component


def _tool(tool: ToolUsage, ref: str) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": ref,
        "name": tool.tool_name or ref,
        "properties": _properties(kind="tool", tool_type=tool.tool_type),
    }
    if tool.source_file:
        component["evidence"] = {"occurrences": [_occurrence(tool.source_file, tool.line_number)]}
    return component


def _tools(report: ScanReport, refs: _Refs, graph: dict[str, set[str]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Tool components, and a map from tool ID to the bom-ref allocated for it (the first in sorted order when an ID repeats)."""
    tool_refs: dict[str, str] = {}
    components: list[dict[str, Any]] = []
    for tool in sorted(report.tool_usages, key=lambda t: (
        t.id or f"tool:{t.tool_name}", t.source_file, t.line_number is None, t.line_number or 0, t.tool_name, t.tool_type,
    )):
        ref = refs.take(tool.id or f"tool:{tool.tool_name}")
        if tool.id:
            tool_refs.setdefault(tool.id, ref)
        graph[ref] = set()
        components.append(_tool(tool, ref))
    return sorted(components, key=lambda c: c["bom-ref"]), tool_refs


def _agents(
    report: ScanReport,
    refs: _Refs,
    graph: dict[str, set[str]],
    tool_refs: dict[str, str],
    models_by_name: dict[str, list[str]],
) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    ordered = sorted(report.agents, key=lambda a: (
        a.id or f"agent:{a.name}", a.scope, a.name, a.identity, sorted(_instance_key(i) for i in a.instances),
    ))
    agent_refs = [refs.take(a.id or f"agent:{a.name}") for a in ordered]
    for agent, ref in zip(ordered, agent_refs):
        components.append(_agent(agent, ref))
        graph[ROOT_REF].add(ref)
        depends = graph[ref] = set()
        for instance in agent.instances:
            depends.update(tool_refs[t.tool_id] for t in instance.tools if t.tool_id in tool_refs)
            # An instance model carries no provider, so the agent depends on every model component of that name.
            if _is_literal_model(instance.model):
                depends.update(models_by_name.get(instance.model.casefold(), []))
    return sorted(components, key=lambda c: c["bom-ref"])


def _services(report: ScanReport, refs: _Refs, graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for server in sorted(report.mcp_servers, key=lambda s: (s.name, s.transport, s.source_file)):
        values = {"transport": server.transport}
        if server.source_file:
            values["source_file"] = server.source_file
        ref = refs.take(f"service:mcp:{server.name}")
        services.append({"bom-ref": ref, "name": server.name or ref,
                         "properties": _properties(**values)})

    hosts: dict[str, list[EndpointUsage]] = {}
    for endpoint in report.llm_endpoints:
        if endpoint.kind != "unresolved" and endpoint.host and not _TEMPLATE.search(endpoint.host + endpoint.url):
            hosts.setdefault(endpoint.host, []).append(endpoint)
    for host, endpoints in sorted(hosts.items()):
        services.append({
            "bom-ref": refs.take(f"service:endpoint:{host}"),
            "name": host,
            "endpoints": sorted({e.url for e in endpoints}),
            "properties": _properties(endpoint_kind=",".join(sorted({e.kind for e in endpoints}))),
        })
    for service in services:
        graph[ROOT_REF].add(service["bom-ref"])
        graph[service["bom-ref"]] = set()
    return sorted(services, key=lambda s: s["bom-ref"])


def _claim_occurrence_refs(components: list[dict[str, Any]], refs: _Refs) -> None:
    """Second pass: occurrences take their bom-refs after every component and service has its own."""
    for component in components:
        for occurrence in component.get("evidence", {}).get("occurrences", []):
            if "bom-ref" in occurrence:
                occurrence["bom-ref"] = refs.take(occurrence["bom-ref"])


def _metadata(report: ScanReport) -> dict[str, Any]:
    from quin_scanner import __version__

    timestamp = _iso_utc(report.scan_timestamp) or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "timestamp": timestamp,
        "tools": {"components": [{"type": "application", "name": "quin-scanner", "version": __version__}]},
        "component": {"type": "application", "bom-ref": ROOT_REF, "name": _repo_name(report.repo_path)},
    }


def _dependencies(graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    out = []
    for ref in sorted(graph):
        entry: dict[str, Any] = {"ref": ref}
        if graph[ref]:
            entry["dependsOn"] = sorted(graph[ref])
        out.append(entry)
    return out


def build_bom(report: ScanReport) -> dict[str, Any]:
    """The CycloneDX 1.6 BOM for *report* as a plain dict.

    Each group builder takes (report, refs, graph), takes its bom-refs from *refs* itself on items already
    sorted (so collision suffixes follow sorted order), registers its nodes and edges in *graph* and
    returns its list. build_bom calls them in spec order.
    """
    refs = _Refs()
    graph: dict[str, set[str]] = {ROOT_REF: set()}
    framework = _framework(report, refs, graph)
    framework_ref = framework[0]["bom-ref"] if framework else None
    models, models_by_name = _models(report, refs, graph)
    tools, tool_refs = _tools(report, refs, graph)
    agents = _agents(report, refs, graph, tool_refs, models_by_name)
    components = framework + models + agents + tools
    services = _services(report, refs, graph)
    _claim_occurrence_refs(components, refs)
    vulnerabilities = _vulnerabilities(report, refs, framework_ref)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _metadata(report),
    }
    if components:
        bom["components"] = components
    if services:
        bom["services"] = services
    bom["dependencies"] = _dependencies(graph)
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def to_cyclonedx(report: ScanReport) -> str:
    return json.dumps(build_bom(report), indent=2, ensure_ascii=False)
