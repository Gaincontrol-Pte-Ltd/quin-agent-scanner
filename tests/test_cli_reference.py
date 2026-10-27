"""docs/cli.md is generated from the click commands; the README must only mention real flags."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import click

from quin_scanner.cli import cli

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("gen_cli_reference", ROOT / "scripts" / "gen_cli_reference.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)  # type: ignore[union-attr]


def _all_commands(command: click.Command = cli, path: str = "quin-scanner") -> dict[str, click.Command]:
    found = {path: command}
    if isinstance(command, click.Group):
        for name, sub in command.commands.items():
            if not sub.hidden:
                found.update(_all_commands(sub, f"{path} {name}"))
    return found


def test_committed_cli_reference_is_current():
    committed = (ROOT / "docs" / "cli.md").read_text(encoding="utf-8")
    assert committed == gen.render(), "docs/cli.md is stale: run `python3 scripts/gen_cli_reference.py` and commit the result"


def test_every_command_and_option_is_documented():
    text = gen.render()
    snapshot = json.loads((ROOT / "tests" / "cli_snapshot.json").read_text(encoding="utf-8"))
    for command, shape in snapshot.items():
        heading = command if command == "quin-scanner" else f"quin-scanner {command}"
        assert f"## `{heading}`" in text, f"missing section for {command}"
        for param in shape["params"]:
            if param["kind"] == "argument":
                assert f"`{param['name'].upper()}`" in text, f"{command}: argument {param['name']} is not documented"
                continue
            for opt in param["opts"]:
                assert f"`{opt}`" in text, f"{command}: {opt} is not documented"


def test_reference_does_not_depend_on_the_machine_or_release():
    text = gen.render()
    assert str(ROOT) not in text
    assert not re.search(r"\b\d+\.\d+\.\d+(?:[ab]|rc)\d+\b", text)
    assert "Sentinel" not in text


def test_reference_embeds_the_exit_code_table_from_the_stability_policy():
    stability = (ROOT / "docs" / "stability.md").read_text(encoding="utf-8")
    table_row = next(line for line in stability.splitlines() if line.startswith("| `skills scan` |"))
    assert table_row in gen.render()


def test_readme_only_mentions_flags_and_commands_that_exist():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    commands = _all_commands()
    real_flags = {opt for c in commands.values() for p in c.params for opt in [*p.opts, *getattr(p, "secondary_opts", [])]}
    # Flags of other tools quoted in the README (git, uv, pip, curl) are not ours.
    foreign = {"--help", "--all-extras"}
    mentioned = set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", readme))
    unknown = sorted(f for f in mentioned if f not in real_flags and f not in foreign)
    assert not unknown, f"README mentions flags that no command has: {unknown}"

    names = {path.removeprefix("quin-scanner ") for path in commands if path != "quin-scanner"}
    in_code, unknown = False, []
    for line in readme.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        match = in_code and re.match(r"\s*(?:\$ )?(?:uv run )?quin-scanner\s+((?:skills\s+)?[a-z][a-z-]*)", line)
        if match and match.group(1).strip() not in names:
            unknown.append(match.group(1))
    assert not unknown, f"README code blocks use unknown commands: {unknown}"
