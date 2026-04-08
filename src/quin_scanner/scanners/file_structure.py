from __future__ import annotations

from pathlib import Path

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.base import BaseScanner


def _first_tag(tags: list[str] | str) -> str:
    if isinstance(tags, list):
        return tags[0] if tags else "llm-api"
    return tags


class FileStructureScanner(BaseScanner):
    """Detects AI-related directories and file extensions."""

    def __init__(self) -> None:
        rules = load_rules("file_markers.yaml")
        self._directories: list[dict] = rules.get("directories", [])
        self._extensions: list[dict] = rules.get("extensions", [])
        self._file_names: list[dict] = rules.get("file_names", [])

    def name(self) -> str:
        return "FileStructureScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        all_files = file_index.all_files()

        # Collect all directory names present in the repo
        dirs_seen: set[str] = set()
        for f in all_files:
            parts = Path(f).parts
            for part in parts[:-1]:  # exclude filename itself
                dirs_seen.add(part)

        # Check directory markers
        for dir_rule in self._directories:
            dir_name = dir_rule["name"]
            tags = dir_rule.get("capability_tags", dir_rule.get("capability_tag", "llm-api"))
            if dir_name in dirs_seen:
                # Find a representative file inside this directory
                sample_files = file_index.files_in_dir(dir_name)
                rep_path = sample_files[0] if sample_files else dir_name + "/"
                findings.append(
                    ScanFinding(
                        scanner_name=self.name(),
                        category="file_marker",
                        file_path=rep_path,
                        line_number=None,
                        match_text=f"{dir_name}/",
                        capability_tag=_first_tag(tags),
                        confidence=0.75,
                    )
                )

        # Check file extension markers
        for ext_rule in self._extensions:
            ext = ext_rule["ext"]
            tag = ext_rule["capability_tag"]
            matches = file_index.files_by_extension(ext)
            for path in matches:
                findings.append(
                    ScanFinding(
                        scanner_name=self.name(),
                        category="file_marker",
                        file_path=path,
                        line_number=None,
                        match_text=path,
                        capability_tag=tag,
                        confidence=0.8,
                    )
                )

        # Check known filenames
        for name_rule in self._file_names:
            name = name_rule["name"]
            tag = name_rule["capability_tag"]
            for f in all_files:
                if Path(f).name == name:
                    findings.append(
                        ScanFinding(
                            scanner_name=self.name(),
                            category="file_marker",
                            file_path=f,
                            line_number=None,
                            match_text=name,
                            capability_tag=tag,
                            confidence=0.8,
                        )
                    )

        return findings
