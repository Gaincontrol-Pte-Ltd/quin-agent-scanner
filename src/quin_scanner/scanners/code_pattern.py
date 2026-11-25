from __future__ import annotations

import re
from pathlib import Path

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.regex_prefilter import TextProbe, required_literals
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.base import BaseScanner

_LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
}

_ANY_EXT = {ext for exts in _LANGUAGE_EXTENSIONS.values() for ext in exts}


def _lang_for_ext(ext: str) -> str | None:
    for lang, exts in _LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return None


class CodePatternScanner(BaseScanner):
    """Regex-matches AI import statements and function calls in source files."""

    def __init__(self) -> None:
        rules = load_rules("code_patterns.yaml")
        self._patterns: list[dict] = rules.get("patterns", [])
        # Precompile regexes, and derive for each the text any match must contain (None when that
        # cannot be derived safely: the rule then always runs).
        for p in self._patterns:
            p["_re"] = re.compile(p["pattern"])
            p["_required"] = required_literals(p["pattern"])
        # Rules that apply to each language, in rule order (the first matching rule wins a line).
        self._rules_by_lang: dict[str, list[dict]] = {
            lang: [p for p in self._patterns if p.get("language", "any") in ("any", lang)]
            for lang in _LANGUAGE_EXTENSIONS
        }

    def name(self) -> str:
        return "CodePatternScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for path in file_index.all_files():
            ext = Path(path).suffix
            if ext not in _ANY_EXT:
                continue
            file_lang = _lang_for_ext(ext)
            if file_lang is None:
                continue
            try:
                content = accessor.read_file(path)
            except Exception:
                continue
            # A rule whose required text is absent from the file cannot match any of its lines,
            # so dropping it leaves the findings unchanged (#88). Rule order is kept.
            probe = TextProbe(content)
            rules = [r for r in self._rules_by_lang[file_lang] if probe.may_match(r["_required"])]
            if not rules:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                for rule in rules:
                    if rule["_re"].search(line):
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="code_pattern",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=rule["capability_tag"],
                                confidence=0.85,
                            )
                        )
                        break  # one finding per line
        return findings
