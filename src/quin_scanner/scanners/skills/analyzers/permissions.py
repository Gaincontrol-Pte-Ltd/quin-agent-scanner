from __future__ import annotations

import re

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import line_of, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle
from quin_scanner.scanners.skills.discovery import is_pseudo_record

_UNRESTRICTED_WRITE_TOOLS = {"write", "edit", "multiedit", "webfetch", "notebookedit"}
_NETWORK = re.compile(
    r"\b(requests|httpx|urllib|aiohttp|http\.client|axios|XMLHttpRequest)\b|\bcurl\b|\bwget\b|\bfetch\("
)
_CREDENTIALS = re.compile(
    r"(?i)(\.ssh/|\.aws/|\.gnupg/|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\.git-credentials)"
)
_NETWORK_WORDS = (
    "fetch", "download", "http", "api", "web", "url", "search", "upload", "request",
    "network", "online", "internet", "scrap", "crawl", "brows", "email", "slack",
    "webhook", "notif", "sync", "deploy", "publish",
)
_CREDENTIAL_WORDS = (
    "credential", "secret", "token", "ssh", "aws", "auth", "authenticat", "authoriz", "login", "password",
    "keychain", "vault", "key",
)


def _word_pattern(words: tuple[str, ...]) -> re.Pattern[str]:
    """Match each word at a word start, allowing a short inflection (keys, fetching, browser)."""
    return re.compile(r"\b(?:" + "|".join(map(re.escape, words)) + r")\w{0,3}\b")


_NETWORK_RE = _word_pattern(_NETWORK_WORDS)
_CREDENTIAL_RE = _word_pattern(_CREDENTIAL_WORDS)


_DANGEROUS_BASH_GRANTS = {f"{c}:*" for c in ("curl", "wget", "rm", "sudo", "sh", "bash", "eval")}


def _unrestricted_bash(tool: str) -> bool:
    t = tool.strip()
    if t.lower() == "bash":
        return True
    m = re.fullmatch(r"(?i)bash\((.*)\)", t)
    if not m:
        return False
    inner = m.group(1).strip()
    return inner in {"*", ":*"} or inner.lower() in _DANGEROUS_BASH_GRANTS


def _is_wildcard(tool: str) -> bool:
    t = tool.strip()
    return t == "*" or (t.lower().startswith("mcp__") and t.endswith("*"))


def _tools_line(bundle: SkillBundle) -> tuple[str, int | None]:
    md = bundle.get("SKILL.md")
    if md is None:
        return bundle.record.skill_md_path, None
    idx = md.text.lower().find("allowed-tools")
    return md.path, (line_of(md.text, idx) if idx >= 0 else None)


def analyze_permissions(bundle: SkillBundle) -> list[SkillFinding]:
    rec = bundle.record
    if is_pseudo_record(rec):
        return []
    findings: list[SkillFinding] = []

    if not rec.frontmatter_valid and rec.skill_md_path:
        findings.append(make_finding(
            bundle, rule_id="SK-META-001", severity="low", category="metadata",
            title="SKILL.md frontmatter is missing or invalid",
            file_path=rec.skill_md_path, line_number=1, evidence_text="frontmatter not parseable",
            threat_id="T011", confidence=0.9,
        ))

    path, line = _tools_line(bundle)
    for tool in rec.allowed_tools:
        if _is_wildcard(tool):
            findings.append(make_finding(
                bundle, rule_id="SK-PERM-002", severity="high", category="permissions",
                title="Wildcard tool grant in allowed-tools", file_path=path, line_number=line,
                evidence_text=tool, threat_id="T006", confidence=0.8,
            ))
        elif _unrestricted_bash(tool):
            findings.append(make_finding(
                bundle, rule_id="SK-PERM-001", severity="high", category="permissions",
                title="Unrestricted shell access in allowed-tools", file_path=path,
                line_number=line, evidence_text=tool, threat_id="T006", confidence=0.8,
            ))
        elif tool.strip().lower() in _UNRESTRICTED_WRITE_TOOLS:
            findings.append(make_finding(
                bundle, rule_id="SK-PERM-003", severity="low", category="permissions",
                title="Unrestricted write or network tool in allowed-tools", file_path=path,
                line_number=line, evidence_text=tool, threat_id="T006", confidence=0.6,
            ))

    declared = f"{rec.name} {rec.description}".lower()
    network_declared = bool(_NETWORK_RE.search(declared))
    credential_declared = bool(_CREDENTIAL_RE.search(declared))
    network_hit = credential_hit = None
    for f in bundle.of_kind("code", "shell"):
        if network_hit is None and (m := _NETWORK.search(f.text)):
            network_hit = (f, m)
        if credential_hit is None and (m := _CREDENTIALS.search(f.text)):
            credential_hit = (f, m)

    if network_hit and not network_declared:
        f, m = network_hit
        findings.append(make_finding(
            bundle, rule_id="SK-PERM-004", severity="medium", category="permissions",
            title="Code makes network calls not mentioned in the skill description",
            file_path=f.path, line_number=line_of(f.text, m.start()),
            evidence_text=m.group(0), threat_id="T011", confidence=0.5,
        ))
    if credential_hit and not credential_declared:
        f, m = credential_hit
        findings.append(make_finding(
            bundle, rule_id="SK-PERM-005", severity="high", category="permissions",
            title="Code touches credential files not mentioned in the skill description",
            file_path=f.path, line_number=line_of(f.text, m.start()),
            evidence_text=m.group(0), threat_id="T011", confidence=0.6,
        ))
    return findings
