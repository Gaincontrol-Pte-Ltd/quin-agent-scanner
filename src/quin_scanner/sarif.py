"""Serializes ScanReport risk_signals to SARIF 2.1.0 for GitHub code scanning."""
from __future__ import annotations

import json
import re
from typing import Any

from quin_scanner.models import EvidenceRef, RiskIndicator, ScanReport, Vulnerability
from quin_scanner.risk_taxonomy import Threat
from quin_scanner.vuln_checker import parse_framework_ref

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


def _vulnerability_location(report: ScanReport) -> dict[str, Any] | None:
    ref = parse_framework_ref(report.framework)
    if ref is None:
        return None
    pattern = re.compile(rf"\b{re.escape(ref.package.lower())}\b")
    for finding in report.artifacts:
        if finding.category == "dependency" and pattern.search(finding.match_text.lower()):
            return _location_from_evidence(
                EvidenceRef(file_path=finding.file_path, line_number=finding.line_number)
            )
    return None


def _message_text(indicator: RiskIndicator, agent_name: str | None = None) -> str:
    text = indicator.signal
    if agent_name:
        text = f"[agent: {agent_name}] {text}"
    if indicator.recommended_controls:
        text += f"\n\nRecommended: {'; '.join(indicator.recommended_controls)}"
    return text


def _result_from_indicator(indicator: RiskIndicator, agent_name: str | None = None) -> dict[str, Any]:
    locations = [
        loc
        for loc in (_location_from_evidence(ref) for ref in indicator.evidence_refs)
        if loc is not None
    ]
    return {
        "ruleId": _rule_id(indicator),
        "level": _severity_to_level(indicator.severity),
        "message": {"text": _message_text(indicator, agent_name)},
        "locations": locations,
    }


def _rule_from_indicator(indicator: RiskIndicator, threats_by_id: dict[str, Threat]) -> dict[str, Any]:
    rule_id = _rule_id(indicator)
    level = _severity_to_level(indicator.severity)
    threat = threats_by_id.get(indicator.threat_id) if indicator.threat_id else None

    if threat is not None:
        full_desc_parts = [p for p in (threat.description, threat.why_it_matters) if p]
        rule: dict[str, Any] = {
            "id": rule_id,
            "shortDescription": {"text": threat.name},
            "fullDescription": {"text": "\n\n".join(full_desc_parts) or threat.name},
            "defaultConfiguration": {"level": level},
        }
        if threat.external_refs:
            rule["helpUri"] = threat.external_refs[0].url
        return rule

    return {
        "id": rule_id,
        "shortDescription": {"text": indicator.signal},
        "fullDescription": {"text": indicator.signal},
        "defaultConfiguration": {"level": level},
    }


def _vuln_rule_id(vuln: Vulnerability) -> str:
    if vuln.cve_id:
        return vuln.cve_id
    return _slugify(vuln.summary)


def _result_from_vulnerability(
    vuln: Vulnerability, location: dict[str, Any] | None, framework: str
) -> dict[str, Any]:
    text = f"{vuln.severity.upper()} vulnerability in {framework}: {vuln.summary}"
    if vuln.affected_versions:
        text += f"\n\nAffected versions: {vuln.affected_versions}"
    return {
        "ruleId": _vuln_rule_id(vuln),
        "level": _severity_to_level(vuln.severity),
        "message": {"text": text},
        "locations": [location] if location is not None else [],
    }


def _rule_from_vulnerability(vuln: Vulnerability) -> dict[str, Any]:
    rule_id = _vuln_rule_id(vuln)
    short_desc = vuln.cve_id or rule_id
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": vuln.summary},
        "defaultConfiguration": {"level": _severity_to_level(vuln.severity)},
    }
    if vuln.source_url:
        rule["helpUri"] = vuln.source_url
    return rule


def to_sarif(report: ScanReport) -> str:
    from quin_scanner import __version__
    from quin_scanner.risk_taxonomy import load_taxonomy

    threats_by_id = {t.id: t for t in load_taxonomy().threats}

    indicators: list[tuple[RiskIndicator, str | None]] = [
        (indicator, None)
        for indicator in report.risk_signals
        if not any(ref.scanner == "VulnChecker" for ref in indicator.evidence_refs)
    ]
    for agent in report.agents:
        indicators.extend(
            (indicator, agent.name)
            for indicator in agent.risk_signals
            if not any(ref.scanner == "VulnChecker" for ref in indicator.evidence_refs)
        )

    results = [_result_from_indicator(indicator, agent_name) for indicator, agent_name in indicators]

    rules_by_id: dict[str, dict[str, Any]] = {}
    for indicator, _ in indicators:
        rule_id = _rule_id(indicator)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _rule_from_indicator(indicator, threats_by_id)

    vuln_location = _vulnerability_location(report)
    for vuln in report.vulnerabilities:
        results.append(_result_from_vulnerability(vuln, vuln_location, report.framework))
        vuln_rule_id = _vuln_rule_id(vuln)
        if vuln_rule_id not in rules_by_id:
            rules_by_id[vuln_rule_id] = _rule_from_vulnerability(vuln)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "quin-scanner",
                        "informationUri": "https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner",
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, default=str)
