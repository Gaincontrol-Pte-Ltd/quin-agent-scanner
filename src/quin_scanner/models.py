from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanFinding:
    scanner_name: str
    category: str
    file_path: str
    line_number: int | None
    match_text: str
    capability_tag: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "match_text": self.match_text,
            "capability_tag": self.capability_tag,
            "confidence": self.confidence,
        }


@dataclass
class EvidenceRef:
    """Pointer back to the scanner finding (or external source) that triggered a risk signal.

    For LLM-emitted KRIs: file_path / line_number / scanner come from a ScanFinding.
    For CVE-promoted entries: file_path is empty, source_url carries the advisory URL.
    """
    file_path: str = ""
    line_number: int | None = None
    scanner: str = ""
    source_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "scanner": self.scanner,
            "source_url": self.source_url,
        }


@dataclass
class RiskIndicator:
    """A single risk indicator grounded in the threat taxonomy."""
    signal: str                          # KRI text from taxonomy
    recommended_controls: list[str] = field(default_factory=list)  # e.g. ["C003: Access Control & Least Privilege"]
    threat_id: str | None = None         # e.g. "T001" — the originating threat in the taxonomy
    severity: str = "medium"             # "critical" | "high" | "medium" | "low" | "info"
    evidence_refs: list[EvidenceRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "recommended_controls": self.recommended_controls,
            "threat_id": self.threat_id,
            "severity": self.severity,
            "evidence_refs": [e.to_dict() for e in self.evidence_refs],
        }


@dataclass
class ClassificationResult:
    """Result from the classification pass (Pass 1)."""
    system_types: list[str] = field(default_factory=list)       # e.g. ["agentic_ai", "mcp_enabled"]
    relevant_threats: list[str] = field(default_factory=list)    # e.g. ["T001", "T005", "T006"]


@dataclass
class AgentProfile:
    name: str
    agent_type: str                      # "supervisor" | "utility" | "worker" | "unknown"
    goal: str
    capabilities: list[str] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "agent_type": self.agent_type,
            "goal": self.goal,
            "capabilities": self.capabilities,
            "risk_signals": [r.to_dict() if isinstance(r, RiskIndicator) else r for r in self.risk_signals],
            "skills": self.skills,
            "tools": self.tools,
            "source_file": self.source_file,
        }


@dataclass
class MCPServer:
    name: str
    transport: str = "unknown"           # "stdio" | "http" | "sse" | "unknown"
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "source_file": self.source_file,
        }


@dataclass
class InfraProfile:
    platform: str                        # "kubernetes" | "terraform" | "docker-compose" | ...
    details: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "details": self.details,
            "source_files": self.source_files,
        }


@dataclass
class ToolUsage:
    tool_name: str
    tool_type: str = "tool_definition"   # "tool_definition" | "external_service" | "skill" | "mcp_tool"
    service_category: str = ""           # only for external_service: "web_search", "web_browsing", etc.
    source_file: str = ""
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_type": self.tool_type,
            "service_category": self.service_category,
            "source_file": self.source_file,
            "line_number": self.line_number,
        }


@dataclass
class SynthesisResult:
    """Internal result from SynthesisAgent — not serialised directly."""
    is_ai_application: bool
    framework: str
    summary: str
    agents: list[AgentProfile] = field(default_factory=list)
    tool_usages: list[ToolUsage] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)  # repo-level risks
    confidence_adjustment: float = 0.0   # -0.1 to +0.1, applied to static confidence


# Kept for backward compatibility — replaced by AgentProfile in new reports.
@dataclass
class AgentIntentSummary:
    prompt_location: str
    agent_name: str
    goal: str
    capabilities: list[str] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_location": self.prompt_location,
            "agent_name": self.agent_name,
            "goal": self.goal,
            "capabilities": self.capabilities,
            "risk_signals": self.risk_signals,
        }


def _make_agent_id(prompt_location: str) -> str:
    return hashlib.sha256(prompt_location.encode()).hexdigest()[:16]


@dataclass
class ModelUsage:
    provider: str          # e.g., "openai", "anthropic", "google"
    model_name: str        # e.g., "gpt-4o", "claude-sonnet-4-20250514"
    source: str            # "code", "config", "env_var", "routing"
    file_path: str
    line_number: int
    role: str = "unknown"  # "primary", "fallback", "embedding", "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "source": self.source,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "role": self.role,
        }


@dataclass
class Vulnerability:
    """A known vulnerability affecting the detected framework+version."""
    cve_id: str | None                       # "CVE-2024-1234" or GHSA-... or None
    severity: str                            # "critical" | "high" | "medium" | "low" | "unknown"
    cvss_score: float | None                 # 0.0–10.0
    published: str | None                    # ISO date string
    summary: str                             # short human description
    source: str                              # "osv" | "web:perplexity" | "web:gemini" | ...
    source_url: str | None                   # canonical advisory URL
    affected_versions: str | None = None     # e.g. ">=0.80.0,<0.90.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published": self.published,
            "summary": self.summary,
            "source": self.source,
            "source_url": self.source_url,
            "affected_versions": self.affected_versions,
        }


@dataclass
class ScanReport:
    repo_path: str
    scan_timestamp: str
    is_ai_application: bool
    confidence: float
    capability_tags: list[str] = field(default_factory=list)
    artifacts: list[ScanFinding] = field(default_factory=list)
    # New synthesis fields
    framework: str = "unknown"
    summary: str = ""
    agents: list[AgentProfile] = field(default_factory=list)
    tool_usages: list[ToolUsage] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)  # repo-level risks
    mcp_servers: list[MCPServer] = field(default_factory=list)
    infra: InfraProfile | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # Existing fields
    model_usages: list[ModelUsage] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "scan_timestamp": self.scan_timestamp,
            "is_ai_application": self.is_ai_application,
            "confidence": self.confidence,
            "capability_tags": self.capability_tags,
            "framework": self.framework,
            "summary": self.summary,
            "agents": [a.to_dict() for a in self.agents],
            "tool_usages": [t.to_dict() for t in self.tool_usages],
            "risk_signals": [r.to_dict() for r in self.risk_signals],
            "mcp_servers": [m.to_dict() for m in self.mcp_servers],
            "infra": self.infra.to_dict() if self.infra else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "artifacts": [f.to_dict() for f in self.artifacts],
            "model_usages": [m.to_dict() for m in self.model_usages],
            "metadata": self.metadata,
        }
