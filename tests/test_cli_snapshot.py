"""The CLI is a contract (docs/stability.md): this pins every command, option, default and type.

A change to `tests/cli_snapshot.json` shows up in review. If a change is intentional and not
breaking, regenerate it with:  UPDATE_CLI_SNAPSHOT=1 python3 -m pytest tests/test_cli_snapshot.py
"""
from __future__ import annotations

import difflib
import json
import os
from pathlib import Path

import click
import pytest

from quin_scanner.cli import cli

TESTS = Path(__file__).resolve().parent
SNAPSHOT = TESTS / "cli_snapshot.json"
BASELINE = TESTS / "cli_baseline_1.0.json"


def _type_name(param_type: click.ParamType):
    if isinstance(param_type, click.Choice):
        return {"choice": list(param_type.choices)}
    return param_type.name


def _plain(value):
    return value if isinstance(value, (str, int, float, bool, type(None))) else str(value)


def _default(param: click.Parameter):
    """The declared default, independent of click's internals.

    Newer click versions report "no default" as an internal sentinel object (older ones use None or
    False for flags), which would make the snapshot depend on the click version.
    """
    value = param.default
    if not isinstance(value, (str, int, float, bool, type(None))):
        value = None
    if value is None and getattr(param, "is_flag", False):
        value = False
    return value


def _param(param: click.Parameter) -> dict:
    return {
        "name": param.name,
        "kind": "argument" if isinstance(param, click.Argument) else "option",
        "opts": list(param.opts) + list(getattr(param, "secondary_opts", [])),
        "type": _type_name(param.type),
        "required": param.required,
        "default": _default(param),
        "is_flag": bool(getattr(param, "is_flag", False)),
        "multiple": param.multiple,
        "envvar": _plain(param.envvar),
    }


def _walk(command: click.Command, path: str, out: dict) -> None:
    out[path] = {"params": sorted((_param(p) for p in command.params), key=lambda p: p["name"] or "")}
    if isinstance(command, click.Group):
        for name, sub in sorted(command.commands.items()):
            if not sub.hidden:
                _walk(sub, f"{path} {name}".strip(), out)


def cli_shape() -> dict:
    shape: dict = {}
    _walk(cli, "", shape)
    return {("quin-scanner" if key == "" else key): value for key, value in shape.items()}


def breaking_cli_changes(old: dict, new: dict) -> list[str]:
    """Changes that would break an existing invocation written against *old*."""
    problems = []
    for command, old_command in old.items():
        if command not in new:
            problems.append(f"removed command: {command}")
            continue
        new_params = {p["name"]: p for p in new[command]["params"]}
        for old_param in old_command["params"]:
            name = old_param["name"]
            if name not in new_params:
                problems.append(f"{command}: removed {old_param['kind']} {name}")
                continue
            new_param = new_params[name]
            for field in ("kind", "opts", "type", "required", "default", "is_flag", "multiple", "envvar"):
                if old_param[field] != new_param[field]:
                    problems.append(f"{command}: {name}.{field} changed {old_param[field]!r} -> {new_param[field]!r}")
        old_names = {p["name"] for p in old_command["params"]}
        for new_param in new[command]["params"]:
            if new_param["name"] not in old_names and new_param["required"]:
                problems.append(f"{command}: new required {new_param['kind']} {new_param['name']}")
    return problems


def _dump(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def test_cli_matches_the_committed_snapshot():
    current = _dump(cli_shape())
    if os.environ.get("UPDATE_CLI_SNAPSHOT") == "1":
        SNAPSHOT.write_text(current, encoding="utf-8")
    recorded = SNAPSHOT.read_text(encoding="utf-8")
    diff = "".join(
        difflib.unified_diff(recorded.splitlines(True), current.splitlines(True), "tests/cli_snapshot.json", "current CLI")
    )
    assert not diff, (
        "The CLI changed. If this is intentional and not a breaking change (docs/stability.md), regenerate with\n"
        "  UPDATE_CLI_SNAPSHOT=1 python3 -m pytest tests/test_cli_snapshot.py\n" + diff
    )


def test_cli_is_compatible_with_the_frozen_1_0_baseline():
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert breaking_cli_changes(baseline, cli_shape()) == []


def test_snapshot_lists_every_command():
    assert set(cli_shape()) == {
        "quin-scanner", "scan", "scan-batch", "scan-org", "skills", "skills scan", "skills baseline",
    }


def test_breaking_change_detector():
    base = {"scan": {"params": [
        {"name": "output", "kind": "option", "opts": ["-o", "--output"], "type": "text", "required": False,
         "default": "html", "is_flag": False, "multiple": False, "envvar": None},
    ]}}
    assert breaking_cli_changes(base, base) == []

    def with_param(**changes):
        param = {**base["scan"]["params"][0], **changes}
        return {"scan": {"params": [param]}}

    assert breaking_cli_changes(base, with_param(default="json")) == [
        "scan: output.default changed 'html' -> 'json'"
    ]
    assert breaking_cli_changes(base, with_param(opts=["--format"])) == [
        "scan: output.opts changed ['-o', '--output'] -> ['--format']"
    ]
    assert breaking_cli_changes(base, {"scan": {"params": []}}) == ["scan: removed option output"]
    assert breaking_cli_changes(base, {}) == ["removed command: scan"]

    added_optional = {"scan": {"params": base["scan"]["params"] + [
        {"name": "fast", "kind": "option", "opts": ["--fast"], "type": "bool", "required": False,
         "default": False, "is_flag": True, "multiple": False, "envvar": None}]}}
    assert breaking_cli_changes(base, added_optional) == []
    added_required = {"scan": {"params": base["scan"]["params"] + [
        {"name": "token", "kind": "option", "opts": ["--token"], "type": "text", "required": True,
         "default": None, "is_flag": False, "multiple": False, "envvar": None}]}}
    assert breaking_cli_changes(base, added_required) == ["scan: new required option token"]
