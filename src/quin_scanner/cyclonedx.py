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

from quin_scanner.models import ScanReport, Vulnerability
from quin_scanner.vuln_checker import FrameworkRef, parse_framework_ref

SPEC_VERSION = "1.6"
ROOT_REF = "repo"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5, "unknown": 6}


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
    components = _framework(report, refs, graph)
    framework_ref = components[0]["bom-ref"] if components else None
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
    bom["dependencies"] = _dependencies(graph)
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def to_cyclonedx(report: ScanReport) -> str:
    return json.dumps(build_bom(report), indent=2, ensure_ascii=False)
