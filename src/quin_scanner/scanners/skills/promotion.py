from __future__ import annotations

from quin_scanner.models import EvidenceRef, RiskIndicator, SkillAssessment
from quin_scanner.risk_taxonomy import get_control_label
from quin_scanner.scanners.skills.scoring import is_protected

_CONTROL_BY_CATEGORY = {
    "prompt_injection": "C001",
    "hidden_content": "C001",
    "mcp_poisoning": "C001",
    "dangerous_code": "C002",
    "permissions": "C003",
    "persistence": "C003",
    "supply_chain": "C004",
    "credential_access": "C005",
    "exfiltration": "C005",
    "prompt_leakage": "C005",
    "safety_bypass": "C006",
}
_DEFAULT_CONTROL = "C008"
_PROMOTE = {"critical", "high"}


def promote_skill_findings(assessments: list[SkillAssessment]) -> list[RiskIndicator]:
    """Turn high/critical, non-disputed skill findings (LLM disputes never remove critical, AST or taint findings) into repo-level risk signals."""
    signals: list[RiskIndicator] = []
    for a in assessments:
        for f in a.findings:
            if f.severity not in _PROMOTE or (f.llm_verdict == "disputed" and not is_protected(f)):
                continue
            control = _CONTROL_BY_CATEGORY.get(f.category, _DEFAULT_CONTROL)
            signals.append(RiskIndicator(
                signal=f"[skill: {a.record.name}] {f.title} ({f.rule_id})",
                recommended_controls=[get_control_label(control)],
                threat_id=f.threat_id,
                severity=f.severity,
                evidence_refs=[EvidenceRef(
                    file_path=f.file_path, line_number=f.line_number, scanner="SkillScanner",
                )],
            ))
    return signals
