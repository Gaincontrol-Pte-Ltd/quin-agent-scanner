from __future__ import annotations

import ast
import re

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import dotted, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle

_SENSITIVE = re.compile(
    r"(\.ssh|\.aws|\.gnupg|\.kube|\.netrc|id_rsa|id_ed25519|\.git-credentials|\.npmrc|\.pypirc)"
)
_PATH_FUNCS = {"open", "os.path.expanduser", "os.path.join", "Path", "pathlib.Path"}
_NET_PREFIXES = ("requests.", "httpx.", "aiohttp.", "urllib3.", "urllib.request.", "http.client.")
_NET_METHODS = {
    "get", "post", "put", "patch", "delete", "request", "urlopen", "urlretrieve", "Request",
}
_MAX_PASSES = 3


def _source_kind(node: ast.AST) -> str | None:
    """'file' for sensitive-file reads, 'env' for environment access, else None."""
    kind: str | None = None
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute):
            d = dotted(n)
            if d and d.startswith("os.environ"):
                kind = kind or "env"
        elif isinstance(n, ast.Call):
            d = dotted(n.func) or ""
            if d in {"os.getenv", "os.environ.get"}:
                kind = kind or "env"
            elif d in _PATH_FUNCS or d.endswith((".read_text", ".expanduser")):
                if any(
                    isinstance(c, ast.Constant)
                    and isinstance(c.value, str)
                    and _SENSITIVE.search(c.value)
                    for c in ast.walk(n)
                ):
                    return "file"
    return kind


def _uses(node: ast.AST, tainted: dict[str, str]) -> str | None:
    kind: str | None = None
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted:
            if tainted[n.id] == "file":
                return "file"
            kind = "env"
    return kind


def _expr_kind(node: ast.AST, tainted: dict[str, str]) -> str | None:
    a, b = _source_kind(node), _uses(node, tainted)
    if "file" in (a, b):
        return "file"
    return a or b


def _is_sink(call: ast.Call) -> bool:
    name = dotted(call.func) or ""
    last = call.func.attr if isinstance(call.func, ast.Attribute) else name
    if last in {"sendall", "sendto"}:
        return True
    if name == "urlopen":
        return True
    return name.startswith(_NET_PREFIXES) and last in _NET_METHODS


def _names(target: ast.AST) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def analyze_taint(bundle: SkillBundle) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.of_kind("code"):
        if not f.path.endswith(".py"):
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError):
            continue

        tainted: dict[str, str] = {}
        assigns = sorted(
            (n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.With))),
            key=lambda n: n.lineno,
        )
        for _ in range(_MAX_PASSES):
            for node in assigns:
                if isinstance(node, ast.With):
                    for item in node.items:
                        kind = _expr_kind(item.context_expr, tainted)
                        if kind and item.optional_vars is not None:
                            for name in _names(item.optional_vars):
                                if tainted.get(name) != "file":
                                    tainted[name] = kind
                    continue
                if node.value is None:
                    continue
                kind = _expr_kind(node.value, tainted)
                if not kind:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for name in _names(target):
                        if tainted.get(name) != "file":
                            tainted[name] = kind

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_sink(node)):
                continue
            values = list(node.args) + [kw.value for kw in node.keywords]
            kinds = [k for k in (_expr_kind(v, tainted) for v in values) if k]
            if not kinds:
                continue
            segment = (ast.get_source_segment(f.text, node) or "network call").splitlines()[0]
            if "file" in kinds:
                findings.append(make_finding(
                    bundle, rule_id="SK-TAINT-001", severity="high", category="exfiltration",
                    title="Sensitive file contents flow into a network call",
                    file_path=f.path, line_number=node.lineno, evidence_text=segment,
                    threat_id="T002", confidence=0.75,
                ))
            else:
                findings.append(make_finding(
                    bundle, rule_id="SK-TAINT-002", severity="medium", category="exfiltration",
                    title="Environment value flows into a network call",
                    file_path=f.path, line_number=node.lineno, evidence_text=segment,
                    threat_id="T002", confidence=0.45,
                ))
    return findings
