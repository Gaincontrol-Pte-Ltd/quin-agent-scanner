"""Loads and queries the risk taxonomy from rules/risk_taxonomy.yaml."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml


@dataclass
class Threat:
    """A threat entry from the risk taxonomy."""
    id: str
    name: str
    category: str
    applies_to: list[str]
    key_risk_indicators: list[str]
    recommended_controls: list[str]


@dataclass
class Control:
    """A control entry from the risk taxonomy."""
    id: str
    name: str


@dataclass
class Taxonomy:
    """Complete parsed taxonomy."""
    threats: list[Threat] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)


_TAXONOMY_PATH = Path(__file__).parent / "rules" / "risk_taxonomy.yaml"


@lru_cache(maxsize=1)
def load_taxonomy(path: Path | None = None) -> Taxonomy:
    """Load and cache the risk taxonomy from YAML."""
    p = path or _TAXONOMY_PATH
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    threats = [
        Threat(
            id=t["id"],
            name=t["name"],
            category=t["category"],
            applies_to=t.get("applies_to", []),
            key_risk_indicators=t.get("key_risk_indicators", []),
            recommended_controls=t.get("recommended_controls", []),
        )
        for t in data.get("threats", [])
    ]
    controls = [
        Control(id=c["id"], name=c["name"])
        for c in data.get("controls", [])
    ]
    return Taxonomy(threats=threats, controls=controls)


def filter_threats(
    system_types: list[str],
    threat_ids: list[str] | None = None,
    taxonomy: Taxonomy | None = None,
) -> list[Threat]:
    """Return threats whose applies_to overlaps with system_types.

    If threat_ids is provided, further filter to only those IDs.
    """
    tax = taxonomy or load_taxonomy()
    system_set = set(system_types)
    result = [t for t in tax.threats if system_set & set(t.applies_to)]
    if threat_ids is not None:
        id_set = set(threat_ids)
        result = [t for t in result if t.id in id_set]
    return result


def get_control_label(control_id: str, taxonomy: Taxonomy | None = None) -> str:
    """Return 'C003: Access Control & Least Privilege' for a given control ID."""
    tax = taxonomy or load_taxonomy()
    for c in tax.controls:
        if c.id == control_id:
            return f"{c.id}: {c.name}"
    return control_id


def build_threat_reference(threats: list[Threat], taxonomy: Taxonomy | None = None) -> str:
    """Build a compact THREAT REFERENCE block for injection into the LLM prompt."""
    tax = taxonomy or load_taxonomy()
    lines: list[str] = ["--- THREAT REFERENCE (evaluate these KRIs against the evidence) ---"]
    for t in threats:
        control_labels = [get_control_label(cid, tax) for cid in t.recommended_controls]
        controls_str = "; ".join(control_labels)
        lines.append(f"\n{t.id} {t.name} [{controls_str}]:")
        for kri in t.key_risk_indicators:
            lines.append(f"  - {kri}")
    return "\n".join(lines)


def build_threat_summary() -> str:
    """Build a compact threat summary for the classification prompt (IDs + names + applicability)."""
    tax = load_taxonomy()
    lines: list[str] = ["Threat reference:"]
    for t in tax.threats:
        tags = ", ".join(t.applies_to)
        lines.append(f"  {t.id}: {t.name} [{tags}]")
    return "\n".join(lines)
