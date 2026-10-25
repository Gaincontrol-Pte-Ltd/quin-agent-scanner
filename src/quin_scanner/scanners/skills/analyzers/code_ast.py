from __future__ import annotations

import ast

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import call_last_name, dotted, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle, SkillFile

_DECODERS = {
    "b64decode", "urlsafe_b64decode", "b85decode", "a85decode",
    "decompress", "fromhex", "unhexlify",
}
_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}
_UNSAFE_LOADERS = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
    "marshal.load", "marshal.loads", "dill.load", "dill.loads",
}


def _has_decoder(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and call_last_name(n) in _DECODERS for n in ast.walk(node)
    )


def _emit(
    bundle: SkillBundle,
    f: SkillFile,
    node: ast.Call,
    rule_id: str,
    severity: str,
    title: str,
    confidence: float,
) -> SkillFinding:
    segment = ast.get_source_segment(f.text, node) or title
    return make_finding(
        bundle,
        rule_id=rule_id,
        severity=severity,
        category="dangerous_code",
        title=title,
        file_path=f.path,
        line_number=node.lineno,
        evidence_text=segment.splitlines()[0],
        threat_id="T005",
        confidence=confidence,
    )


def _check_call(bundle: SkillBundle, f: SkillFile, node: ast.Call) -> list[SkillFinding]:
    name = dotted(node.func) or ""
    arg0 = node.args[0] if node.args else None
    nonconst = arg0 is not None and not isinstance(arg0, ast.Constant)
    out: list[SkillFinding] = []

    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        if arg0 is not None and _has_decoder(arg0):
            out.append(_emit(bundle, f, node, "SK-CODE-005", "critical",
                             "Decoded payload passed to eval/exec", 0.9))
        elif nonconst:
            out.append(_emit(bundle, f, node, "SK-CODE-001", "high",
                             "eval/exec of dynamic input", 0.8))
        else:
            out.append(_emit(bundle, f, node, "SK-CODE-001", "medium",
                             "eval/exec call", 0.5))
    elif name in {"os.system", "os.popen"}:
        out.append(_emit(bundle, f, node, "SK-CODE-002",
                         "high" if nonconst else "medium",
                         "Shell command execution", 0.75 if nonconst else 0.5))
    elif name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in _SUBPROCESS_FUNCS:
        shell = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if shell:
            out.append(_emit(bundle, f, node, "SK-CODE-002",
                             "high" if nonconst else "medium",
                             "subprocess with shell=True", 0.75 if nonconst else 0.5))
    elif name in _UNSAFE_LOADERS:
        out.append(_emit(bundle, f, node, "SK-CODE-003", "medium",
                         "Unsafe deserialization", 0.6))
    elif name == "yaml.load":
        loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
        if loader is None or "Safe" not in (dotted(loader) or ""):
            out.append(_emit(bundle, f, node, "SK-CODE-003", "high",
                             "yaml.load without a safe loader", 0.7))
    elif name in {"__import__", "importlib.import_module"} and nonconst:
        out.append(_emit(bundle, f, node, "SK-CODE-004", "medium",
                         "Dynamic import of a computed module name", 0.5))
    return out


def analyze_python(bundle: SkillBundle) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.of_kind("code"):
        if not f.path.endswith(".py"):
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError):
            continue  # regex rules still cover this file
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(_check_call(bundle, f, node))
    return findings
