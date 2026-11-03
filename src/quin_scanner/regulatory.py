"""Informative crosswalk from Quin's controls (C001-C014) to the EU AI Act, ISO/IEC 42001 and the NIST AI RMF.

Data: rules/regulatory_mapping.yaml, validated on load. Nothing here comes from the LLM.
Spec: docs/superpowers/specs/2026-11-03-regulatory-mapping-design.md
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_MAPPING_PATH = Path(__file__).parent / "rules" / "regulatory_mapping.yaml"
_CONTROL_ID = re.compile(r"^\s*(C\d{3})\b", re.IGNORECASE)
_URL_UNSAFE = re.compile(r'[\s()<>"]')
_FRAMEWORK_FIELDS = ("id", "name", "version", "url", "clauses")


@dataclass(frozen=True)
class Clause:
    id: str
    title: str
    url: str


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    version: str
    url: str
    clauses: tuple[Clause, ...]


@dataclass(frozen=True)
class RegulatoryRef:
    framework: str
    framework_name: str
    id: str
    title: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {"framework": self.framework, "id": self.id, "title": self.title, "url": self.url}


@dataclass(frozen=True)
class Mapping:
    disclaimer: str
    frameworks: tuple[Framework, ...]
    controls: dict[str, dict[str, tuple[str, ...]]]


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _markup_problem(value: str, *, is_id: bool = False) -> bool:
    """True when *value* would break a Markdown table or link, or HTML."""
    return "|" in value or "\n" in value or "\r" in value or (is_id and ("[" in value or "]" in value))


def problems(data: Any, control_ids: Iterable[str]) -> list[str]:
    """Everything wrong with a parsed mapping file, as readable messages; empty when valid."""
    if not isinstance(data, dict):
        return ["the mapping file must be a mapping"]
    out: list[str] = []
    if not _nonempty_str(data.get("disclaimer")):
        out.append("missing disclaimer")
    raw_frameworks = data.get("frameworks")
    if not isinstance(raw_frameworks, list) or not raw_frameworks:
        return out + ["frameworks must be a non-empty list"]

    catalogue: dict[str, set[str]] = {}
    for index, fw in enumerate(raw_frameworks):
        if not isinstance(fw, dict):
            out.append(f"frameworks[{index}] must be a mapping")
            continue
        name = fw.get("id") or f"frameworks[{index}]"
        missing = [key for key in _FRAMEWORK_FIELDS if not fw.get(key)]
        if missing:
            out.append(f"framework {name}: missing {', '.join(missing)}")
            continue
        fid = fw["id"]
        if not isinstance(fid, str):
            out.append(f"framework id {fid!r} must be a string (quote it)")
            continue
        if fid in catalogue:
            out.append(f"duplicate framework id: {fid}")
        if _markup_problem(fid, is_id=True):
            out.append(f"framework {fid}: id must not contain | [ ] or newlines")
        for key in ("name", "version", "url"):
            if not _nonempty_str(fw[key]):
                out.append(f"framework {fid}: {key} must be a non-empty string")
            elif key == "url" and not fw[key].startswith("https://"):
                out.append(f"framework {fid}: url must start with https://")
            elif key == "url" and _URL_UNSAFE.search(fw[key]):
                out.append(f'framework {fid}: url must not contain spaces or ()<>"')
            elif key != "url" and _markup_problem(fw[key]):
                out.append(f"framework {fid}: {key} must not contain | or newlines")
        ids: set[str] = set()
        if not isinstance(fw["clauses"], list):
            out.append(f"framework {fid}: clauses must be a list")
            catalogue[fid] = ids
            continue
        for clause in fw["clauses"]:
            if not isinstance(clause, dict) or not clause.get("id") or not clause.get("title"):
                out.append(f"framework {fid}: every clause needs an id and a title")
                continue
            clause_id = clause["id"]
            if not isinstance(clause_id, str):
                out.append(f"framework {fid}: clause id {clause_id!r} must be a string (quote it)")
                continue
            if clause_id in ids:
                out.append(f"framework {fid}: duplicate clause {clause_id}")
            ids.add(clause_id)
            if not _nonempty_str(clause_id) or _markup_problem(clause_id, is_id=True):
                out.append(f"framework {fid}: clause {clause_id!r}: id must be non-empty and not contain | [ ] or newlines")
            title = clause["title"]
            if not _nonempty_str(title) or _markup_problem(title):
                out.append(f"framework {fid}: clause {clause_id}: title must be a non-empty string without | or newlines")
            if "url" in clause and (not isinstance(clause["url"], str) or not clause["url"].startswith("https://")):
                out.append(f"framework {fid}: clause {clause_id}: url must start with https://")
            elif "url" in clause and _URL_UNSAFE.search(clause["url"]):
                out.append(f'framework {fid}: clause {clause_id}: url must not contain spaces or ()<>"')
        catalogue[fid] = ids

    controls = data.get("controls")
    if not isinstance(controls, dict):
        return out + ["controls must be a mapping"]
    keys = []
    for key in controls:
        if isinstance(key, str):
            keys.append(key)
        else:
            out.append(f"control key {key!r} must be a string")
    expected = set(control_ids)
    out.extend(f"control {cid} has no mapping entry" for cid in sorted(expected - set(keys)))
    out.extend(f"mapping entry {cid} is not a control in the taxonomy" for cid in sorted(set(keys) - expected))

    used: dict[str, set[str]] = {fid: set() for fid in catalogue}
    for cid in sorted(keys):
        entry = controls[cid]
        if not isinstance(entry, dict):
            out.append(f"control {cid}: entry must be a mapping")
            continue
        out.extend(f"control {cid}: missing key {fid}" for fid in catalogue if fid not in entry)
        for fid, clause_ids in entry.items():
            if fid not in catalogue:
                out.append(f"control {cid}: unknown framework {fid}")
                continue
            if clause_ids is None:
                clause_ids = []
            if not isinstance(clause_ids, list):
                out.append(f"control {cid}: {fid} must be a list of clause IDs")
                continue
            seen: set[str] = set()
            for clause_id in clause_ids:
                if not isinstance(clause_id, str):
                    out.append(f"control {cid}: {fid} clause {clause_id!r} must be a string (quote it)")
                    continue
                if clause_id in seen:
                    out.append(f"control {cid}: duplicate {fid} clause {clause_id}")
                seen.add(clause_id)
                if clause_id not in catalogue[fid]:
                    out.append(f"control {cid}: unknown {fid} clause {clause_id}")
                used[fid].add(clause_id)
    for fid, ids in catalogue.items():
        out.extend(f"{fid} clause {clause_id} is not used by any control" for clause_id in sorted(ids - used[fid]))
    return out


def _parse(data: dict[str, Any]) -> Mapping:
    frameworks = tuple(
        Framework(
            id=fw["id"], name=fw["name"], version=fw["version"], url=fw["url"],
            clauses=tuple(
                Clause(id=c["id"], title=c["title"], url=c.get("url") or fw["url"]) for c in fw["clauses"]
            ),
        )
        for fw in data["frameworks"]
    )
    controls = {
        cid: {fid: tuple(ids or ()) for fid, ids in entry.items()}
        for cid, entry in data["controls"].items()
    }
    return Mapping(disclaimer=" ".join(str(data["disclaimer"]).split()), frameworks=frameworks, controls=controls)


@lru_cache(maxsize=1)
def load_mapping(path: Path | None = None) -> Mapping:
    """Load and validate the mapping (cached). Raises ValueError listing every problem."""
    from quin_scanner.risk_taxonomy import load_taxonomy

    source = path or _MAPPING_PATH
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    found = problems(data, (c.id for c in load_taxonomy().controls))
    if found:
        raise ValueError(f"invalid regulatory mapping in {source}: " + "; ".join(found))
    return _parse(data)


def frameworks() -> tuple[Framework, ...]:
    return load_mapping().frameworks


def disclaimer() -> str:
    return load_mapping().disclaimer


def control_id_of(label: str) -> str | None:
    """The control ID at the start of a label such as "C003: Access Control & Least Privilege"."""
    match = _CONTROL_ID.match(label or "")
    return match.group(1).upper() if match else None


def refs_for_control(control_id: str) -> list[RegulatoryRef]:
    """References for a control: frameworks in file order, clauses in the control's order."""
    mapping = load_mapping()
    entry = mapping.controls.get((control_id or "").upper())
    if not entry:
        return []
    out: list[RegulatoryRef] = []
    for fw in mapping.frameworks:
        by_id = {c.id: c for c in fw.clauses}
        for clause_id in entry.get(fw.id, ()):
            clause = by_id[clause_id]
            out.append(RegulatoryRef(fw.id, fw.name, clause.id, clause.title, clause.url))
    return out


def refs_for_label(label: str) -> list[RegulatoryRef]:
    control_id = control_id_of(label)
    return refs_for_control(control_id) if control_id else []


def sarif_tag(ref: RegulatoryRef) -> str:
    """framework/slug, e.g. eu-ai-act/art-14, iso-42001/a.9.2, nist-ai-rmf/manage-2.4."""
    text = re.sub(r"\.(?=\s|$)", "", ref.id).lower()  # "Art. 14" -> "art 14"; dots inside IDs stay
    return f"{ref.framework}/{re.sub(r'[^a-z0-9.]+', '-', text).strip('-')}"


def controls_catalog(labels: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Report `controls` field: every taxonomy control named by *labels*, sorted by ID."""
    from quin_scanner.risk_taxonomy import load_taxonomy

    names = {c.id: c.name for c in load_taxonomy().controls}
    found: dict[str, dict[str, Any]] = {}
    for label in labels:
        control_id = control_id_of(label)
        if control_id in names and control_id not in found:
            found[control_id] = {
                "name": names[control_id],
                "regulatory_refs": [ref.to_dict() for ref in refs_for_control(control_id)],
            }
    return {cid: found[cid] for cid in sorted(found)}
