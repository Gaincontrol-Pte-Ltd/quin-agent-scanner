from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import PurePosixPath

from quin_scanner.models import SkillFinding, Vulnerability
from quin_scanner.scanners.skills.analyzers.common import line_of, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle, SkillFile, file_kind

OsvLookup = Callable[[str, str], list[Vulnerability]]

_POPULAR_PYPI = frozenset({
    "requests", "numpy", "pandas", "urllib3", "boto3", "setuptools", "django", "flask",
    "pyyaml", "cryptography", "pillow", "scipy", "matplotlib", "beautifulsoup4",
    "sqlalchemy", "pytest", "openai", "anthropic", "langchain", "httpx", "aiohttp",
    "pydantic", "fastapi", "tensorflow", "torch", "transformers", "click", "rich",
})
_POPULAR_NPM = frozenset({
    "express", "lodash", "react", "axios", "chalk", "commander", "moment", "request",
    "debug", "openai", "typescript", "vue", "webpack", "eslint", "jest", "dotenv",
})
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:(===|==|~=|!=|>=|<=|>|<)\s*([^\s;#,]+))?")
_PIP = re.compile(r"\bpip3?\s+install\b(?P<args>[^\n`|;&]*)")
_NPX = re.compile(r"\bnpx\s+(?:(?:-y|--yes)\s+)?(?P<pkg>@?[A-Za-z0-9][\w./-]*(?:@[\w.^~-]+)?)")
_PIP_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target",
}
_OSV_VERSION = re.compile(r"^\d+(?:\.\d+)*$")
_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


def edit_distance_one(a: str, b: str) -> bool:
    """True when *a* and *b* differ by exactly one edit (or one adjacent transposition)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        )
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def _typosquat_of(name: str, popular: frozenset[str]) -> str | None:
    norm = _normalise(name)
    if len(norm) < 4 or norm in popular:
        return None
    return next((p for p in popular if edit_distance_one(norm, p)), None)


def _sc(bundle: SkillBundle, f: SkillFile, rule_id: str, severity: str, title: str,
        line: int | None, ev: str, confidence: float) -> SkillFinding:
    return make_finding(
        bundle, rule_id=rule_id, severity=severity, category="supply_chain", title=title,
        file_path=f.path, line_number=line, evidence_text=ev, threat_id="T003",
        confidence=confidence,
    )


def _scan_requirements(
    bundle: SkillBundle, f: SkillFile, osv_lookup: OsvLookup | None
) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for n, line in enumerate(f.text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        if "://" in stripped or stripped.startswith("git+"):
            findings.append(_sc(bundle, f, "SK-SC-003", "medium",
                                "Dependency installed from a URL or VCS", n, stripped, 0.7))
            continue
        m = _REQ_NAME.match(stripped)
        if not m:
            continue
        name, _, op, version = m.groups()
        squat = _typosquat_of(name, _POPULAR_PYPI)
        if squat:
            findings.append(_sc(bundle, f, "SK-SC-002", "medium",
                                f"Possible typosquat of '{squat}'", n, stripped, 0.6))
        if op != "==":
            findings.append(_sc(bundle, f, "SK-SC-001", "low",
                                "Unpinned dependency", n, stripped, 0.6))
        elif osv_lookup and version and _OSV_VERSION.match(version):
            for v in osv_lookup(_normalise(name), version):
                sev = v.severity if v.severity in {"critical", "high", "medium", "low"} else "medium"
                findings.append(_sc(
                    bundle, f, "SK-SC-006", sev,
                    f"Known vulnerability in {name}=={version}", n,
                    f"{name}=={version}: {v.cve_id or 'advisory'} {(v.summary or '')[:200]}", 0.9,
                ))
    return findings


def _line_containing(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    return line_of(text, idx) if idx >= 0 else None


def _scan_package_json(bundle: SkillBundle, f: SkillFile) -> list[SkillFinding]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[SkillFinding] = []
    for section in _NPM_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            line = _line_containing(f.text, f'"{name}"')
            ev = f'"{name}": "{spec}"'
            spec_s = str(spec)
            squat = _typosquat_of(name, _POPULAR_NPM)
            if squat:
                findings.append(_sc(bundle, f, "SK-SC-002", "medium",
                                    f"Possible typosquat of '{squat}'", line, ev, 0.6))
            if spec_s.startswith(("git", "http", "github:", "file:")):
                findings.append(_sc(bundle, f, "SK-SC-003", "medium",
                                    "Dependency installed from a URL or VCS", line, ev, 0.7))
            elif spec_s in {"*", "latest", ""}:
                findings.append(_sc(bundle, f, "SK-SC-001", "low",
                                    "Unpinned dependency", line, ev, 0.6))
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in _INSTALL_SCRIPTS:
            if key in scripts:
                findings.append(_sc(
                    bundle, f, "SK-SC-004", "medium", "Install-time script",
                    _line_containing(f.text, f'"{key}"'), f"{key}: {scripts[key]}", 0.6,
                ))
    return findings


def _scan_install_commands(bundle: SkillBundle, f: SkillFile) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for n, line in enumerate(f.text.splitlines(), start=1):
        for m in _PIP.finditer(line):
            tokens = m.group("args").split()
            skip_next = False
            for tok in tokens:
                if skip_next:
                    skip_next = False
                    continue
                if tok.startswith("-"):
                    skip_next = tok in _PIP_VALUE_FLAGS
                    continue
                if "==" in tok or "/" in tok or tok.startswith(".") or "://" in tok:
                    continue
                findings.append(_sc(bundle, f, "SK-SC-005", "low",
                                    "Unpinned pip install", n, f"pip install {tok}", 0.5))
        for m in _NPX.finditer(line):
            pkg = m.group("pkg")
            rest = pkg[1:] if pkg.startswith("@") else pkg
            if "@" not in rest:
                findings.append(_sc(bundle, f, "SK-SC-005", "low",
                                    "Unpinned npx package", n, f"npx {pkg}", 0.5))
    return findings


def analyze_supply_chain(
    bundle: SkillBundle, osv_lookup: OsvLookup | None = None
) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.files:
        name = PurePosixPath(f.path).name.lower()
        kind = file_kind(f.path)
        if re.fullmatch(r"requirements[\w.-]*\.txt", name):
            findings.extend(_scan_requirements(bundle, f, osv_lookup))
        elif name == "package.json":
            findings.extend(_scan_package_json(bundle, f))
        if kind in {"markdown", "shell"}:
            findings.extend(_scan_install_commands(bundle, f))
    return findings
