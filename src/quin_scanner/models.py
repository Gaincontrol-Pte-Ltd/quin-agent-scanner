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
class AgentProfile:
    name: str
    agent_type: str                      # "supervisor" | "utility" | "worker" | "unknown"
    goal: str
    capabilities: list[str] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "agent_type": self.agent_type,
            "goal": self.goal,
            "capabilities": self.capabilities,
            "risk_signals": self.risk_signals,
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
    source_file: str = ""
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
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
class ScanReport:
    repo_path: str
    scan_timestamp: str
    is_ai_application: bool
    confidence: float
    capability_tags: list[str] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    # New synthesis fields
    framework: str = "unknown"
    summary: str = ""
    agents: list[AgentProfile] = field(default_factory=list)
    tool_usages: list[ToolUsage] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    infra: InfraProfile | None = None
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
            "mcp_servers": [m.to_dict() for m in self.mcp_servers],
            "infra": self.infra.to_dict() if self.infra else None,
            "findings": [f.to_dict() for f in self.findings],
            "model_usages": [m.to_dict() for m in self.model_usages],
            "metadata": self.metadata,
        }
