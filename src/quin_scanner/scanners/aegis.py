from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from quin_scanner.file_index import FileIndex
from quin_scanner.models import GovernanceInfo, ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.base import BaseScanner
from quin_scanner.scanners.dependency import DependencyScanner

_LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
}

_PYTHON_MANIFEST_GLOBS = ("**/requirements*.txt", "**/pyproject.toml")


def _norm(pkg: str) -> str:
    return pkg.strip().lower().replace("_", "-")


class AegisScanner(BaseScanner):
    """Detects use of the Aegis SDK (identity/policy enforcement for agents).

    Not part of the default scanner set — enabled with ``--detect-aegis``.
    Findings use category ``governance`` and tag ``aegis-governed``.
    """

    TAG = "aegis-governed"

    def __init__(self) -> None:
        rules = load_rules("aegis.yaml")
        deps = rules.get("dependencies", {})
        self._deps: dict[str, list[str]] = {eco: [_norm(p) for p in pkgs] for eco, pkgs in deps.items()}
        self._integrations: dict[str, str] = rules.get("integrations", {})
        self._patterns = [
            {**p, "_re": re.compile(p["pattern"])} for p in rules.get("code_patterns", [])
        ]
        self._file_markers: list[dict[str, Any]] = rules.get("file_markers", [])
        self._config: dict[str, Any] = rules.get("config", {})

    def name(self) -> str:
        return "AegisScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._scan_dependencies(accessor, file_index))
        findings.extend(self._scan_code(accessor, file_index))
        findings.extend(self._scan_file_markers(accessor, file_index))
        findings.extend(self._scan_config(accessor, file_index))
        return findings

    # --- helpers ---

    def _is_aegis_dep(self, ecosystem: str, pkg: str) -> bool:
        pkg = _norm(pkg)
        for rule in self._deps.get(ecosystem, []):
            if rule.endswith("*"):
                if pkg.startswith(rule[:-1]):
                    return True
            elif pkg == rule:
                return True
        return False

    def _finding(self, kind: str, path: str, lineno: int | None, text: str, confidence: float) -> ScanFinding:
        return ScanFinding(
            scanner_name=self.name(),
            category="governance",
            file_path=path,
            line_number=lineno,
            match_text=text,
            capability_tag=f"{self.TAG}:{kind}",
            confidence=confidence,
        )

    # --- dependencies ---

    def _scan_dependencies(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for glob in _PYTHON_MANIFEST_GLOBS:
            for path in file_index.files_matching(glob):
                try:
                    content = accessor.read_file(path)
                except Exception:
                    continue
                for lineno, line in enumerate(content.splitlines(), start=1):
                    if path.endswith(".toml"):
                        m = re.search(r'"([A-Za-z0-9_.\-]+)', line)
                        pkg = m.group(1) if m else None
                    else:
                        pkg = DependencyScanner._extract_python_pkg(line)
                    if not pkg:
                        continue
                    if self._is_aegis_dep("python", pkg):
                        findings.append(self._finding("dependency", path, lineno, line.strip().strip('",'), 0.9))
        for path in file_index.files_matching("**/package.json"):
            try:
                content = accessor.read_file(path)
                data = json.loads(content)
            except Exception:
                continue
            all_deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            lines = content.splitlines()
            for pkg, version in all_deps.items():
                if self._is_aegis_dep("nodejs", pkg):
                    lineno = next((i + 1 for i, ln in enumerate(lines) if pkg in ln), None)
                    findings.append(self._finding("dependency", path, lineno, f"{pkg}@{version}", 0.9))
        return findings

    # --- source code ---

    def _scan_code(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for path in file_index.all_files():
            ext = Path(path).suffix
            lang = next((lg for lg, exts in _LANGUAGE_EXTENSIONS.items() if ext in exts), None)
            if lang is None:
                continue
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            if "aegis" not in content.lower() and "load_mcp_tools" not in content:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                if line.lstrip().startswith(("#", "//", "*", "/*")):
                    continue  # comments are not evidence of integration
                for rule in self._patterns:
                    if rule["language"] == lang and rule["_re"].search(line):
                        conf = 0.95 if rule["kind"] == "integration" else 0.85
                        findings.append(self._finding(rule["kind"], path, lineno, line.strip(), conf))
                        break
        return findings

    # --- hook / plugin markers ---

    def _scan_file_markers(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for path in file_index.all_files():
            parts = path.replace("\\", "/").split("/")
            for marker in self._file_markers:
                if marker["file"] not in parts:
                    continue
                content_re = marker.get("content")
                if content_re:
                    try:
                        if not re.search(content_re, accessor.read_file(path)):
                            continue
                    except Exception:
                        continue
                findings.append(self._finding("plugin", path, None, marker["name"], 0.9))
        return findings

    # --- config ---

    def _scan_config(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        if not self._config:
            return []
        key_re = re.compile(self._config["pattern"], re.MULTILINE)
        req = [re.compile(r) for r in self._config.get("requires_any_of", [])]
        findings: list[ScanFinding] = []
        seen: set[str] = set()
        for glob in self._config.get("files", []):
            for path in file_index.files_matching(glob):
                if path in seen:
                    continue
                seen.add(path)
                try:
                    content = accessor.read_file(path)
                except Exception:
                    continue
                m = key_re.search(content)
                if not m:
                    continue
                block = content[m.start():]
                if req and not any(r.search(block) for r in req):
                    continue
                lineno = content.count("\n", 0, m.start()) + 1
                findings.append(self._finding("config", path, lineno, "aegis: (engine config)", 0.8))
        return findings


# Evidence kinds that prove the SDK is actually wired in, versus merely declared.
_ACTIVE_KINDS = {"import", "integration", "plugin", "config"}


def classify_governance(is_ai_application: bool, findings: list[ScanFinding]) -> GovernanceInfo:
    """Map Aegis evidence to a governance classification.

    governed       - SDK imported/initialised, or a hook/plugin/config is present
    declared_only  - Aegis is listed as a dependency but no usage was found
    ungoverned     - AI application with no Aegis evidence
    not_applicable - no AI application and no Aegis evidence
    """
    kinds = {f.capability_tag.split(":", 1)[-1] for f in findings}
    if kinds & _ACTIVE_KINDS:
        status = "governed"
    elif "dependency" in kinds:
        status = "declared_only"
    elif is_ai_application:
        status = "ungoverned"
    else:
        status = "not_applicable"

    packages = sorted({
        _norm(re.split(r"[>=<!~;\[\s@]", f.match_text)[0])
        for f in findings
        if f.capability_tag.endswith(":dependency")
    })
    return GovernanceInfo(
        aegis_detected=bool(findings),
        status=status,
        evidence_kinds=sorted(kinds),
        packages=packages,
        evidence=findings,
    )
