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

from quin_scanner.models import ScanReport

SPEC_VERSION = "1.6"
ROOT_REF = "repo"


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
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    """The CycloneDX 1.6 BOM for *report* as a plain dict."""
    graph: dict[str, set[str]] = {ROOT_REF: set()}
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _metadata(report),
    }
    bom["dependencies"] = _dependencies(graph)
    return bom


def to_cyclonedx(report: ScanReport) -> str:
    return json.dumps(build_bom(report), indent=2, ensure_ascii=False)
