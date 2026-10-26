"""The GitHub Action is part of the contract (docs/stability.md): inputs and outputs are frozen."""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION_FILE = ROOT / "action.yml"
ACTION = yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))
BASELINE = json.loads((Path(__file__).resolve().parent / "action_baseline_1.0.json").read_text(encoding="utf-8"))
STABILITY = ROOT / "docs" / "stability.md"
README = ROOT / "README.md"


def _between(text: str, name: str) -> str:
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.S)
    assert match, f"missing <!-- {name}:start --> / <!-- {name}:end --> markers"
    return match.group(1)


def _row_names(block: str) -> set[str]:
    return set(re.findall(r"^\| `([a-z-]+)` \|", block, re.M))


def test_every_frozen_input_is_unchanged():
    inputs = ACTION["inputs"]
    for name, spec in BASELINE["inputs"].items():
        assert name in inputs, f"input {name} was removed"
        assert inputs[name].get("default") == spec["default"], f"default of {name} changed"
        assert bool(inputs[name].get("required", False)) == spec["required"], f"requiredness of {name} changed"


def test_new_inputs_are_optional_and_have_a_default():
    for name, spec in ACTION["inputs"].items():
        if name not in BASELINE["inputs"]:
            assert not spec.get("required", False), f"new input {name} must not be required"
            assert "default" in spec, f"new input {name} needs a default"


def test_every_frozen_output_still_exists():
    for name in BASELINE["outputs"]:
        assert name in ACTION.get("outputs", {}), f"output {name} was removed"


def test_documented_inputs_and_outputs_match_action_yml():
    text = STABILITY.read_text(encoding="utf-8")
    assert _row_names(_between(text, "action-inputs")) == set(ACTION["inputs"])
    assert _row_names(_between(text, "action-outputs")) == set(ACTION["outputs"])


def test_readme_mentions_every_input_and_output():
    readme = README.read_text(encoding="utf-8")
    for name in [*ACTION["inputs"], *ACTION["outputs"]]:
        assert f"`{name}`" in readme, f"README does not document `{name}`"


def test_the_action_installs_the_scanner_from_its_own_checkout_by_default():
    # So the tag you pin selects the scanner version (it used to install the latest PyPI release).
    assert "github.action_path" in ACTION_FILE.read_text(encoding="utf-8")


def _run_steps() -> list[dict]:
    return [step for step in ACTION["runs"]["steps"] if "run" in step]


def test_inputs_never_reach_a_shell_by_string_interpolation():
    for step in _run_steps():
        assert "${{" not in step["run"], f"step {step.get('name') or step.get('id')!r} interpolates an expression into its script; use env:"


def test_every_run_step_fails_fast():
    for step in _run_steps():
        assert "set -euo pipefail" in step["run"]
        assert step.get("shell") == "bash"
