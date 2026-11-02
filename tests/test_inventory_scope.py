"""Scope rules (rules/scope.yaml) and the instructions fingerprint used for agent identity."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef
from quin_scanner.inventory.scope import scope_of


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("src/agents/researcher.py", "production"),
        ("tests/test_agents.py", "test"),
        ("pkg/test/helpers.py", "test"),
        ("src/__tests__/agent.spec.ts", "test"),
        ("src/agent_test.py", "test"),
        ("src/agent.test.ts", "test"),
        ("conftest.py", "test"),
        ("fixtures/agent.py", "test"),
        ("examples/crew/main.py", "example"),
        ("python/samples/getting_started/agent.py", "example"),
        ("cookbook/agent.ipynb", "example"),
        ("notebooks/demo.py", "example"),
        ("docs/quickstart.py", "example"),
        ("demo/app.py", "example"),
        ("tutorials/01.py", "example"),
        ("examples/tests/test_x.py", "test"),  # test rules are checked first
        ("src/latest/agent.py", "production"),  # "test" inside a word is not a test directory
        ("src/contest_entry.py", "production"),
    ],
)
def test_scope_of(path, scope):
    assert scope_of(path) == scope


def test_backslash_paths_are_normalised():
    assert scope_of("tests\\test_a.py") == "test"


def test_literal_instructions_hash_ignores_whitespace():
    a = InstructionsRef.literal("You are  a\nresearcher.")
    b = InstructionsRef.literal("You are a researcher.")
    assert a == b
    assert a.kind == "literal" and len(a.value) == 64


def test_no_instructions_is_unknown():
    assert not NO_INSTRUCTIONS.is_known
    assert InstructionsRef("var", "PROMPT").is_known


def test_literal_instructions_never_raise_on_lone_surrogates():
    assert InstructionsRef.literal("\ud800 hi").kind == "literal"
    assert InstructionsRef.literal("\ud800 hi") != InstructionsRef.literal("\ud801 hi")
