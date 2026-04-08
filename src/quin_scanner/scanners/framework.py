from __future__ import annotations

from pathlib import Path

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.base import BaseScanner


def _first_tag(tags: list[str] | str) -> str:
    if isinstance(tags, list):
        return tags[0] if tags else "orchestration"
    return tags


class FrameworkMarkerScanner(BaseScanner):
    """Detects framework-specific config files (langgraph.json, crew.yaml, etc.)."""

    def __init__(self) -> None:
        rules = load_rules("frameworks.yaml")
        self._frameworks: list[dict] = rules.get("frameworks", [])

    def name(self) -> str:
        return "FrameworkMarkerScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        all_files = file_index.all_files()
        all_names = {Path(f).name: f for f in all_files}

        for fw_rule in self._frameworks:
            filename = fw_rule["file"]
            tags = fw_rule.get("capability_tags", fw_rule.get("capability_tag", "orchestration"))
            confidence = fw_rule.get("confidence", 0.85)

            if filename in all_names:
                path = all_names[filename]
                findings.append(
                    ScanFinding(
                        scanner_name=self.name(),
                        category="framework_marker",
                        file_path=path,
                        line_number=None,
                        match_text=filename,
                        capability_tag=_first_tag(tags),
                        confidence=confidence,
                    )
                )

        return findings
