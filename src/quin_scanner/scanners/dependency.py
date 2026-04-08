from __future__ import annotations

import re

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.base import BaseScanner


def _first_tag(tags: list[str] | str) -> str:
    if isinstance(tags, list):
        return tags[0] if tags else "llm-api"
    return tags


class DependencyScanner(BaseScanner):
    """Detects AI packages in dependency manifest files."""

    def __init__(self) -> None:
        rules = load_rules("dependencies.yaml")
        # Build lookup: ecosystem -> {normalized_pkg_name -> capability_tags}
        self._rules: dict[str, dict[str, list[str]]] = {}
        for ecosystem, packages in rules.items():
            self._rules[ecosystem] = {}
            for entry in packages:
                pkg = entry["package"].lower()
                tags = entry["capability_tags"]
                if isinstance(tags, str):
                    tags = [tags]
                self._rules[ecosystem][pkg] = tags

    def name(self) -> str:
        return "DependencyScanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        findings.extend(self._scan_python_requirements(accessor, file_index))
        findings.extend(self._scan_pyproject_toml(accessor, file_index))
        findings.extend(self._scan_package_json(accessor, file_index))
        findings.extend(self._scan_go_mod(accessor, file_index))
        findings.extend(self._scan_cargo_toml(accessor, file_index))
        findings.extend(self._scan_pom_xml(accessor, file_index))
        findings.extend(self._scan_build_gradle(accessor, file_index))
        return findings

    # --- Python ---

    def _scan_python_requirements(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/requirements*.txt"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                pkg = self._extract_python_pkg(line)
                if pkg and pkg in self._rules.get("python", {}):
                    tags = self._rules["python"][pkg]
                    findings.append(
                        ScanFinding(
                            scanner_name=self.name(),
                            category="dependency",
                            file_path=path,
                            line_number=lineno,
                            match_text=line.strip(),
                            capability_tag=_first_tag(tags),
                            confidence=0.95,
                        )
                    )
        return findings

    def _scan_pyproject_toml(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/pyproject.toml"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                # Match quoted package names in toml dependency lists
                m = re.search(r'"([a-zA-Z0-9_\-]+)', line)
                if m:
                    pkg = m.group(1).lower().replace("_", "-")
                    if pkg in self._rules.get("python", {}):
                        tags = self._rules["python"][pkg]
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="dependency",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=_first_tag(tags),
                                confidence=0.9,
                            )
                        )
        return findings

    # --- Node.js ---

    def _scan_package_json(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        import json

        findings = []
        for path in file_index.files_matching("**/package.json"):
            # Skip node_modules
            if "node_modules" in path:
                continue
            try:
                data = json.loads(accessor.read_file(path))
            except (json.JSONDecodeError, Exception):
                continue
            all_deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            content_lines = accessor.read_file(path).splitlines()
            for pkg_name, version in all_deps.items():
                normalized = pkg_name.lower()
                if normalized in self._rules.get("nodejs", {}):
                    tags = self._rules["nodejs"][normalized]
                    # Find approx line number
                    lineno = next(
                        (i + 1 for i, line in enumerate(content_lines) if pkg_name in line),
                        None,
                    )
                    findings.append(
                        ScanFinding(
                            scanner_name=self.name(),
                            category="dependency",
                            file_path=path,
                            line_number=lineno,
                            match_text=f'"{pkg_name}": "{version}"',
                            capability_tag=_first_tag(tags),
                            confidence=0.95,
                        )
                    )
        return findings

    # --- Go ---

    def _scan_go_mod(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/go.mod"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                line_stripped = line.strip()
                if not line_stripped.startswith("require") and not re.match(
                    r"\s+github\.com/", line
                ):
                    # Try bare module line inside require block
                    pass
                for pkg in self._rules.get("go", {}):
                    if pkg in line_stripped:
                        tags = self._rules["go"][pkg]
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="dependency",
                                file_path=path,
                                line_number=lineno,
                                match_text=line_stripped,
                                capability_tag=_first_tag(tags),
                                confidence=0.9,
                            )
                        )
        return findings

    # --- Rust ---

    def _scan_cargo_toml(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/Cargo.toml"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=', line.strip())
                if m:
                    pkg = m.group(1).lower().replace("_", "-")
                    if pkg in self._rules.get("rust", {}):
                        tags = self._rules["rust"][pkg]
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="dependency",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=_first_tag(tags),
                                confidence=0.9,
                            )
                        )
        return findings

    # --- Java ---

    def _scan_pom_xml(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/pom.xml"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                for pkg in self._rules.get("java", {}):
                    if pkg in line:
                        tags = self._rules["java"][pkg]
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="dependency",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=_first_tag(tags),
                                confidence=0.9,
                            )
                        )
        return findings

    def _scan_build_gradle(
        self, accessor: RepoAccessor, file_index: FileIndex
    ) -> list[ScanFinding]:
        findings = []
        for path in file_index.files_matching("**/*.gradle"):
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                for pkg in self._rules.get("java", {}):
                    if pkg in line:
                        tags = self._rules["java"][pkg]
                        findings.append(
                            ScanFinding(
                                scanner_name=self.name(),
                                category="dependency",
                                file_path=path,
                                line_number=lineno,
                                match_text=line.strip(),
                                capability_tag=_first_tag(tags),
                                confidence=0.9,
                            )
                        )
        return findings

    @staticmethod
    def _extract_python_pkg(line: str) -> str | None:
        """Extract the normalized package name from a requirements.txt line."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        # Remove extras, version specifiers, environment markers
        pkg = re.split(r"[>=<!;\[\s]", line)[0].strip().lower().replace("_", "-")
        return pkg if pkg else None
