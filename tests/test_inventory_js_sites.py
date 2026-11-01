"""Agent sites from new Agent({...}) object literals in JavaScript and TypeScript."""
from __future__ import annotations

from quin_scanner.inventory.evidence import InstructionsRef
from quin_scanner.inventory.js_sites import agent_sites


def test_agent_object_literal():
    source = (
        "const r = new Agent({\n"
        '  name: "researcher",\n'
        '  instructions: "Find facts.",\n'
        '  model: openai("gpt-4o"),\n'
        '  tools: [lookup, "fetch"],\n'
        "});\n"
    )
    (site,) = agent_sites(source, "a.ts")
    assert (site.role, site.name, site.line, site.tool_refs) == ("both", "researcher", 1, ("lookup", "fetch"))
    assert site.instructions == InstructionsRef.literal("Find facts.")
    assert site.model_expr == 'openai("gpt-4o")'


def test_tools_missing_or_not_a_literal_list():
    a, b = agent_sites('new Agent({ name: "a" });\nnew Agent({ name: "b", tools: myTools });\n', "a.ts")
    assert a.tool_refs == ()
    assert b.tool_refs is None


def test_instructions_and_model_by_reference():
    (site,) = agent_sites('new Agent({ name: "a", instructions: PROMPT, model: cfg.model });\n', "a.js")
    assert site.instructions == InstructionsRef("var", "PROMPT")
    assert site.model_expr == "var:cfg.model"


def test_braces_inside_strings_do_not_end_the_object():
    (site,) = agent_sites('new Agent({ instructions: "use {braces}", name: "b", tools: [x] });\n', "a.ts")
    assert (site.name, site.tool_refs) == ("b", ("x",))


def test_agent_without_a_name_is_a_weak_site():
    (site,) = agent_sites('new Agent({ instructions: "x" });\n', "a.ts")
    assert site.name is None
