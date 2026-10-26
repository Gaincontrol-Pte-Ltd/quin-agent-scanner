"""Dependency policy (docs/stability.md): real floors, ceilings on the LLM SDKs, a locked set inside the ranges."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
LOCK = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
STABILITY = ROOT / "docs" / "stability.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"
SDKS = ("openai", "anthropic", "google-genai")


def _requirements() -> dict[str, Requirement]:
    return {Requirement(text).name: Requirement(text) for text in PYPROJECT["project"]["dependencies"]}


def _locked() -> dict[str, Version]:
    return {package["name"]: Version(package["version"]) for package in LOCK["package"]}


def _operators(requirement: Requirement) -> set[str]:
    return {spec.operator for spec in requirement.specifier}


def test_every_runtime_dependency_has_a_floor():
    for name, requirement in _requirements().items():
        assert _operators(requirement) & {">=", "==", "~=", ">"}, f"{name} has no lower bound"


def test_the_llm_sdks_have_a_ceiling():
    requirements = _requirements()
    for name in SDKS:
        assert "<" in _operators(requirements[name]), (
            f"{name} needs an upper bound (the next major version after the one Quin is tested with); see docs/stability.md"
        )


def test_locked_versions_satisfy_the_declared_ranges():
    locked = _locked()
    for name, requirement in _requirements().items():
        assert locked[name] in requirement.specifier, f"locked {name} {locked[name]} is outside {requirement.specifier}"


def test_documented_sdk_ranges_match_pyproject():
    block = re.search(r"<!-- sdk-ranges:start -->(.*?)<!-- sdk-ranges:end -->", STABILITY.read_text(encoding="utf-8"), re.S)
    assert block, "missing <!-- sdk-ranges:start/end --> markers in docs/stability.md"
    documented = {name: SpecifierSet(spec) for name, spec in re.findall(r"^\| `([a-z-]+)` \| `([^`]+)` \|", block.group(1), re.M)}
    requirements = _requirements()
    assert set(documented) == set(SDKS)
    for name in SDKS:
        assert documented[name] == requirements[name].specifier, f"{name}: docs say {documented[name]}, pyproject says {requirements[name].specifier}"


def test_ci_runs_the_suite_on_the_oldest_allowed_dependencies():
    # Removing that job would turn every floor back into an untested claim.
    assert "--resolution lowest-direct" in CI.read_text(encoding="utf-8")
