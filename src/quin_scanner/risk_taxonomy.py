"""Loads and queries the risk taxonomy from rules/risk_taxonomy.yaml."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from quin_scanner.rules.kri_predicates import EvidenceFacts, evaluate as eval_predicate


@dataclass
class ExternalRef:
    """An external reference (authoritative URL + optional local doc)."""
    title: str
    url: str
    local: str | None = None


@dataclass(frozen=True)
class KRI:
    """A Key Risk Indicator with optional precondition predicates.

    `requires` lists predicate names from kri_predicates._REGISTRY. All
    listed predicates must hold (AND semantics) for the KRI to be a
    candidate. An empty `requires` means the KRI is always a candidate,
    matching the legacy bare-string YAML form.
    """
    text: str
    requires: tuple[str, ...] = ()

    def __str__(self) -> str:
        # Doc generator and existing call sites stringify KRIs directly;
        # preserving __str__ == text keeps rendered output byte-identical.
        return self.text


@dataclass
class Threat:
    """A threat entry from the risk taxonomy."""
    id: str
    name: str
    category: str
    applies_to: list[str]
    key_risk_indicators: list[KRI]
    recommended_controls: list[str]
    description: str = ""
    why_it_matters: str = ""
    attack_patterns: list[str] = field(default_factory=list)
    external_refs: list[ExternalRef] = field(default_factory=list)


@dataclass
class Control:
    """A control entry from the risk taxonomy."""
    id: str
    name: str
    description: str = ""
    why_it_matters: str = ""
    how_to_implement: list[str] = field(default_factory=list)
    common_pitfalls: list[str] = field(default_factory=list)
    external_refs: list[ExternalRef] = field(default_factory=list)


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

    def _parse_refs(raw: list | None) -> list[ExternalRef]:
        if not raw:
            return []
        out: list[ExternalRef] = []
        for r in raw:
            if isinstance(r, dict) and r.get("title") and r.get("url"):
                out.append(ExternalRef(title=r["title"], url=r["url"], local=r.get("local")))
        return out

    def _parse_kri(raw) -> KRI:
        # Accept legacy bare-string KRIs and structured dict form.
        if isinstance(raw, str):
            return KRI(text=raw)
        if isinstance(raw, dict):
            text = raw.get("text", "")
            requires = tuple(raw.get("requires", []) or [])
            return KRI(text=text, requires=requires)
        return KRI(text=str(raw))

    threats = [
        Threat(
            id=t["id"],
            name=t["name"],
            category=t["category"],
            applies_to=t.get("applies_to", []),
            key_risk_indicators=[_parse_kri(k) for k in t.get("key_risk_indicators", [])],
            recommended_controls=t.get("recommended_controls", []),
            description=t.get("description", ""),
            why_it_matters=t.get("why_it_matters", ""),
            attack_patterns=t.get("attack_patterns", []),
            external_refs=_parse_refs(t.get("external_refs")),
        )
        for t in data.get("threats", [])
    ]
    controls = [
        Control(
            id=c["id"],
            name=c["name"],
            description=c.get("description", ""),
            why_it_matters=c.get("why_it_matters", ""),
            how_to_implement=c.get("how_to_implement", []),
            common_pitfalls=c.get("common_pitfalls", []),
            external_refs=_parse_refs(c.get("external_refs")),
        )
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


def build_threat_reference(
    threats: list[Threat],
    taxonomy: Taxonomy | None = None,
    facts: EvidenceFacts | None = None,
) -> str:
    """Build a compact THREAT REFERENCE block for injection into the LLM prompt.

    When `facts` is provided, KRIs are filtered by their `requires` preconditions:
    a KRI is included only if every listed predicate holds. Threats whose KRIs
    are all filtered out are dropped from the reference entirely.

    When `facts` is None, all KRIs are included (backward-compatible behavior).
    """
    tax = taxonomy or load_taxonomy()
    lines: list[str] = ["--- THREAT REFERENCE (evaluate these KRIs against the evidence) ---"]
    for t in threats:
        if facts is not None:
            kept = [k for k in t.key_risk_indicators
                    if all(eval_predicate(req, facts) for req in k.requires)]
        else:
            kept = list(t.key_risk_indicators)
        if not kept:
            continue
        control_labels = [get_control_label(cid, tax) for cid in t.recommended_controls]
        controls_str = "; ".join(control_labels)
        lines.append(f"\n{t.id} {t.name} [{controls_str}]:")
        for kri in kept:
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
