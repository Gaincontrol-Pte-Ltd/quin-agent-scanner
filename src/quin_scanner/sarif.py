"""Serializes ScanReport risk_signals to SARIF 2.1.0 for GitHub code scanning."""
from __future__ import annotations

import re

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def _slugify(text: str, max_words: int = 6) -> str:
    words = re.findall(r"[A-Za-z0-9]+", text)[:max_words]
    slug = "-".join(w.lower() for w in words)
    return slug or "risk-signal"


from typing import Any

from quin_scanner.models import EvidenceRef, RiskIndicator


def _rule_id(indicator: RiskIndicator) -> str:
    if indicator.threat_id:
        return indicator.threat_id
    return _slugify(indicator.signal)


def _location_from_evidence(ref: EvidenceRef) -> dict[str, Any] | None:
    if not ref.file_path:
        return None
    physical_location: dict[str, Any] = {"artifactLocation": {"uri": ref.file_path}}
    if ref.line_number is not None:
        physical_location["region"] = {"startLine": ref.line_number}
    return {"physicalLocation": physical_location}


def _message_text(indicator: RiskIndicator, agent_name: str | None = None) -> str:
    text = indicator.signal
    if agent_name:
        text = f"[agent: {agent_name}] {text}"
    if indicator.recommended_controls:
        text += f"\n\nRecommended: {'; '.join(indicator.recommended_controls)}"
    return text
