"""Tests for DependencyScanner, particularly pyproject.toml and package.json parsing."""
from __future__ import annotations

import json

from quin_scanner.file_index import FileIndex
from quin_scanner.orchestrator import _detect_framework, _extract_framework_version
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.dependency import DependencyScanner


def _build(tmp_path, pyproject_body: str):
    (tmp_path / "pyproject.toml").write_text(pyproject_body)
    accessor = LocalRepoAccessor(tmp_path)
    file_index = FileIndex(accessor)
    file_index.build()
    return accessor, file_index


def _build_package_json(tmp_path, deps: dict):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": deps}))
    accessor = LocalRepoAccessor(tmp_path)
    file_index = FileIndex(accessor)
    file_index.build()
    return accessor, file_index


class TestScanPyprojectToml:
    def test_match_text_is_unquoted_with_version_spec(self, tmp_path):
        """match_text must have the same unquoted shape as a requirements.txt line
        (e.g. 'langchain>=1.0.2', not '"langchain>=1.0.2",') so downstream
        framework/version matching (which does prefix checks like
        text.startswith(pkg + ">")) actually works."""
        accessor, file_index = _build(
            tmp_path,
            'dependencies = [\n    "langchain>=1.0.2",\n]\n',
        )
        findings = DependencyScanner().scan(accessor, file_index)
        assert len(findings) == 1
        assert findings[0].match_text == "langchain>=1.0.2"

    def test_bare_quoted_package_no_version(self, tmp_path):
        accessor, file_index = _build(tmp_path, 'dependencies = [\n    "crewai",\n]\n')
        findings = DependencyScanner().scan(accessor, file_index)
        assert len(findings) == 1
        assert findings[0].match_text == "crewai"

    def test_detect_framework_resolves_from_pyproject(self, tmp_path):
        """End-to-end: a framework declared only in pyproject.toml (no
        requirements.txt) must still resolve via _detect_framework."""
        accessor, file_index = _build(
            tmp_path,
            'dependencies = [\n    "crewai>=0.80.0",\n    "requests>=2.0",\n]\n',
        )
        findings = DependencyScanner().scan(accessor, file_index)
        assert _detect_framework(findings) == "CrewAI"


class TestScanPackageJson:
    def test_match_text_is_unquoted_npm_install_shape(self, tmp_path):
        """match_text must be an unquoted 'pkg@version' shape (not the raw
        '"pkg": "version"' JSON shape) so downstream framework/version
        matching (prefix checks like text.startswith(pkg + "@")) works."""
        accessor, file_index = _build_package_json(tmp_path, {"@mastra/core": "^1.0.0"})
        findings = DependencyScanner().scan(accessor, file_index)
        assert len(findings) == 1
        assert findings[0].match_text == "@mastra/core@^1.0.0"

    def test_detect_framework_resolves_from_package_json(self, tmp_path):
        """End-to-end: a framework declared only in package.json (npm) must
        still resolve via _detect_framework, including the caret (^) range
        operator that is npm's default version prefix."""
        accessor, file_index = _build_package_json(
            tmp_path, {"@mastra/core": "^1.0.0", "left-pad": "1.0.0"}
        )
        findings = DependencyScanner().scan(accessor, file_index)
        assert _detect_framework(findings) == "Mastra"

    def test_extract_framework_version_from_package_json(self, tmp_path):
        accessor, file_index = _build_package_json(tmp_path, {"@mastra/core": "^1.2.3"})
        findings = DependencyScanner().scan(accessor, file_index)
        assert _extract_framework_version("Mastra", findings) == "1.2.3"
