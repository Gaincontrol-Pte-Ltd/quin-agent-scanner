"""A repository that publishes a framework's own package is labelled with that framework (#84).

An umbrella repository can import a sibling product somewhere (langchain imports `deepagents` in a test helper,
semantic-kernel imports `agent_framework` in an interop shim). The first self-import used to decide the label.
"""
from __future__ import annotations

import json

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.orchestrator import _declared_package_names, _detect_framework
from quin_scanner.repo_accessor import LocalRepoAccessor


def _finding(scanner: str, text: str, path: str = "x.py") -> ScanFinding:
    return ScanFinding(scanner_name=scanner, category="c", file_path=path, line_number=1,
                       match_text=text, capability_tag="t", confidence=1.0)


def _declared(tmp_path) -> set[str]:
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return _declared_package_names(accessor, index)


def _write(tmp_path, rel: str, text: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


SIBLING_IMPORT = [_finding("CodePatternScanner", "from deepagents.graph import create_deep_agent")]


def test_a_sibling_import_alone_still_labels_the_repository():
    assert _detect_framework(SIBLING_IMPORT) == "LangChain Deep Agents"


def test_the_published_package_outranks_a_sibling_import():
    assert _detect_framework(SIBLING_IMPORT, declared_packages={"langchain"}) == "LangChain"


def test_semantic_kernel_outranks_its_agent_framework_shim():
    findings = [_finding("CodePatternScanner", "from agent_framework import AIFunction")]
    assert _detect_framework(findings, declared_packages={"semantic-kernel"}) == "Semantic Kernel"


def test_declared_names_follow_the_lookup_priority():
    assert _detect_framework([], declared_packages={"langchain", "langgraph"}) == "LangGraph"


def test_an_unknown_declared_name_changes_nothing():
    assert _detect_framework(SIBLING_IMPORT, declared_packages={"my-app"}) == "LangChain Deep Agents"


def test_declared_names_are_read_from_pyproject_and_package_json(tmp_path):
    _write(tmp_path, "libs/core/pyproject.toml", '[project]\nname = "Langchain_Core"\nversion = "1"\n')
    _write(tmp_path, "python/pyproject.toml", '[tool.poetry]\nname = "semantic_kernel"\nversion = "1"\n')
    _write(tmp_path, "js/package.json", json.dumps({"name": "@mastra/core", "version": "1.0.0"}))
    assert {"langchain-core", "semantic-kernel", "@mastra/core"} <= _declared(tmp_path)


def test_manifests_in_examples_tests_and_docs_are_ignored(tmp_path):
    _write(tmp_path, "examples/demo/pyproject.toml", '[project]\nname = "crewai"\n')
    _write(tmp_path, "tests/fixture/package.json", json.dumps({"name": "ai"}))
    _write(tmp_path, "docs/pyproject.toml", '[project]\nname = "langchain"\n')
    assert _declared(tmp_path) == set()


def test_broken_manifests_are_skipped(tmp_path):
    _write(tmp_path, "pyproject.toml", "[project\nname = ")
    _write(tmp_path, "package.json", "{not json")
    _write(tmp_path, "a/package.json", json.dumps(["a", "list"]))
    _write(tmp_path, "b/pyproject.toml", '[project]\nname = 3\n')
    assert _declared(tmp_path) == set()
