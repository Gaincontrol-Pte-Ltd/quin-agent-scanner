"""Keep docs/stability.md and docs/schema/README.md honest: they must match the code."""
from __future__ import annotations

import re
from pathlib import Path

import click

from quin_scanner.cli import cli
from quin_scanner.models import ScanReport

ROOT = Path(__file__).resolve().parent.parent
STABILITY = ROOT / "docs" / "stability.md"
SCHEMA = ROOT / "docs" / "schema" / "README.md"

DOCS = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "CHANGELOG.md",
    ROOT / "ui" / "README.md",
    *sorted((ROOT / "docs").rglob("*.md")),
]


def _between(text: str, name: str) -> str:
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.S)
    assert match, f"missing <!-- {name}:start --> / <!-- {name}:end --> markers"
    return match.group(1)


def _cli_commands() -> set[str]:
    names: set[str] = set()
    for name, command in cli.commands.items():
        if isinstance(command, click.Group):
            names |= {f"{name} {sub}" for sub in command.commands}
        else:
            names.add(name)
    return names


def test_documented_commands_match_the_cli():
    block = _between(STABILITY.read_text(encoding="utf-8"), "cli-commands")
    documented = set(re.findall(r"`quin-scanner ((?:skills )?[a-z-]+)`", block))
    documented.discard("skills")  # the group itself is not a command
    assert documented == _cli_commands()


def test_documented_report_fields_match_the_report():
    block = _between(SCHEMA.read_text(encoding="utf-8"), "report-fields")
    rows = re.findall(r"^\| `([a-z_]+)` \| (always|optional) \|", block, re.M)
    always = {field for field, presence in rows if presence == "always"}
    optional = {field for field, presence in rows if presence == "optional"}
    actual = set(
        ScanReport(
            repo_path="r", scan_timestamp="t", is_ai_application=False, confidence=0.0
        ).to_dict()
    )
    assert always == actual
    assert optional == {"governance"}  # only present with --detect-aegis


def test_typed_classifier_requires_a_py_typed_marker():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    has_marker = (ROOT / "src" / "quin_scanner" / "py.typed").exists()
    assert has_marker or "Typing :: Typed" not in pyproject


def test_relative_links_resolve():
    broken = []
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        for match in re.finditer(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            target = match.group(1)
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (doc.parent / target).resolve().exists():
                broken.append(f"{doc.relative_to(ROOT)} -> {target}")
    assert not broken, broken
