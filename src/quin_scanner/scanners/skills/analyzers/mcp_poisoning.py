from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import dotted, line_of, make_finding
from quin_scanner.scanners.skills.analyzers.text_rules import is_negated, load_rules
from quin_scanner.scanners.skills.bundle import SkillBundle, SkillFile

_MCP_INJECTION = re.compile(
    r"(?i)<\s*important\s*>"
    r"|\bbefore (?:using|calling|invoking) this tool\b[^.\n]{0,80}\b(?:read|send|include|pass|attach)\b"
    r"|\bdo not (?:mention|tell|reveal|disclose)\b"
    r"|\botherwise the tool (?:will )?(?:not work|fail|break)"
)
_CREDENTIAL = re.compile(
    r"(?i)(\.ssh/|\.aws/|\.gnupg/|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\.git-credentials|credentials?\b)"
)
_TOOL_DECORATORS = {"tool", "resource", "prompt"}
_TOOL_CALLS = {"Tool", "tool", "add_tool", "registerTool", "register_tool", "Field"}
_JS_DESCRIPTION = re.compile(
    r"description\s*:\s*([\"'`])(?P<d>(?:(?!\1)[\s\S]){10,2000})\1"
)
_BROAD_ARGS = {"/", "~", "$HOME", "${HOME}", "C:\\", "C:/"}
_INJECTION_CATEGORIES = {"prompt_injection", "hidden_content"}


def _python_descriptions(f: SkillFile) -> Iterator[tuple[str, int]]:
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if (dotted(target) or "").rsplit(".", 1)[-1] in _TOOL_DECORATORS:
                    doc = ast.get_docstring(node)
                    if doc:
                        yield doc, node.lineno
                    break
        elif isinstance(node, ast.Call):
            last = (dotted(node.func) or "").rsplit(".", 1)[-1]
            if last in _TOOL_CALLS:
                for kw in node.keywords:
                    if (
                        kw.arg == "description"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        yield kw.value.value, kw.value.lineno


def _js_descriptions(f: SkillFile) -> Iterator[tuple[str, int]]:
    for m in _JS_DESCRIPTION.finditer(f.text):
        yield m.group("d"), line_of(f.text, m.start())


def _json_descriptions(obj: object, in_tool: bool = False) -> Iterator[str]:
    if isinstance(obj, dict):
        is_tool = in_tool or (
            "name" in obj and any(k in obj for k in ("inputSchema", "input_schema", "parameters"))
        )
        for key, value in obj.items():
            if key == "description" and isinstance(value, str) and is_tool:
                yield value
            else:
                yield from _json_descriptions(value, is_tool)
    elif isinstance(obj, list):
        for item in obj:
            yield from _json_descriptions(item, in_tool)


def _descriptions(f: SkillFile) -> Iterator[tuple[str, int]]:
    suffix = PurePosixPath(f.path).suffix.lower()
    if suffix == ".py":
        yield from _python_descriptions(f)
    elif suffix in {".js", ".mjs", ".cjs", ".ts"}:
        yield from _js_descriptions(f)
    elif suffix == ".json":
        try:
            data = json.loads(f.text)
        except ValueError:
            return
        for desc in _json_descriptions(data):
            idx = f.text.find(desc[:40])
            yield desc, (line_of(f.text, idx) if idx >= 0 else 1)


def _injection_match(description: str) -> str | None:
    for rule in load_rules():
        if rule.category not in _INJECTION_CATEGORIES or rule.id == "SK-PI-007":
            continue
        m = rule.pattern.search(description)
        if m and not (rule.negatable and is_negated(description, m.start())):
            return m.group(0)
    m = _MCP_INJECTION.search(description)
    return m.group(0) if m else None


def _scan_descriptions(bundle: SkillBundle, f: SkillFile) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for desc, line in _descriptions(f):
        hit = _injection_match(desc)
        if hit:
            findings.append(make_finding(
                bundle, rule_id="SK-MCP-001", severity="high", category="mcp_poisoning",
                title="Injection or hidden instruction in MCP tool description",
                file_path=f.path, line_number=line, evidence_text=hit,
                threat_id="T001", confidence=0.8,
            ))
        cred = _CREDENTIAL.search(desc)
        if cred:
            findings.append(make_finding(
                bundle, rule_id="SK-MCP-002", severity="high", category="mcp_poisoning",
                title="MCP tool description references credentials or sensitive files",
                file_path=f.path, line_number=line, evidence_text=cred.group(0),
                threat_id="T002", confidence=0.7,
            ))
    return findings


def _scan_server_scope(bundle: SkillBundle, f: SkillFile) -> list[SkillFinding]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return []
    servers = data.get("mcpServers") or data.get("servers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    findings: list[SkillFinding] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        args = [str(a) for a in (cfg.get("args") or [])]
        blob = f"{name} {cfg.get('command', '')} {' '.join(args)}".lower()
        if "filesystem" not in blob:
            continue
        for a in args:
            if a in _BROAD_ARGS:
                findings.append(make_finding(
                    bundle, rule_id="SK-MCP-004", severity="high", category="permissions",
                    title="MCP filesystem server granted overly broad scope",
                    file_path=f.path, line_number=1 + f.text[: max(f.text.find(a), 0)].count("\n"),
                    evidence_text=f"{name}: {a}", threat_id="T006", confidence=0.8,
                ))
                break
    return findings


def analyze_mcp(bundle: SkillBundle) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.files:
        name = PurePosixPath(f.path).name.lower()
        if name in {".mcp.json", "mcp.json"}:
            findings.extend(_scan_server_scope(bundle, f))
        findings.extend(_scan_descriptions(bundle, f))
    return findings
