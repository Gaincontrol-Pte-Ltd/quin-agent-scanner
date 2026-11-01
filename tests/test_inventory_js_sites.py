"""Agent sites from new Agent({...}) object literals in JavaScript and TypeScript."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef
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


# ── Review fixes ─────────────────────────────────────────────────────────────


def test_keys_of_nested_objects_do_not_describe_the_agent():
    (site,) = agent_sites(
        'new Agent({ tools: [createTool({ name: "search", instructions: "tool-level" })], name: "outer" });\n', "a.ts"
    )
    assert (site.name, site.instructions, site.tool_refs) == ("outer", NO_INSTRUCTIONS, None)


def test_a_nested_constructor_argument_does_not_name_the_agent():
    (site,) = agent_sites('new Agent({ memory: new Memory({ name: "mem" }), name: "outer" });\n', "a.ts")
    assert site.name == "outer"


def test_keys_in_comments_and_strings_are_ignored():
    a, b = agent_sites(
        'new Agent({\n  // name: "commented",\n  /* model: "x" */\n  name: "real",\n});\n'
        "new Agent({ description: \"set instructions: 'foo' later\" });\n",
        "a.ts",
    )
    assert (a.name, a.model_expr) == ("real", None)
    assert (b.name, b.instructions) == (None, NO_INSTRUCTIONS)


def test_tools_of_a_nested_object_are_not_the_agents_tools():
    (site,) = agent_sites('new Agent({ name: "a", workflow: { tools: [x] } });\n', "a.ts")
    assert site.tool_refs == ()


@pytest.mark.parametrize(
    ("tools", "expected"),
    [
        ("[...base, x]", None),
        ("[x, makeTool()]", None),
        ("[toolA, [toolB]]", None),
        ("[x, { name: 'y' }]", None),
        ("[]", ()),
        ("[a, 'b', search.run]", ("a", "b", "search.run")),
        ('["a,b", c]', ("a,b", "c")),
    ],
)
def test_tool_lists_are_known_only_when_every_item_is_a_name(tools, expected):
    (site,) = agent_sites(f'new Agent({{ name: "n", tools: {tools} }});\n', "a.ts")
    assert site.tool_refs == expected


def test_template_literal_name_without_interpolation_is_a_literal_name():
    a, b = agent_sites("new Agent({ name: `researcher` });\nnew Agent({ name: `r-${id}` });\n", "a.ts")
    assert (a.name, b.name) == ("researcher", None)


def test_user_content_in_sites_is_redacted():
    key = "sk-abcdefghijklmnopqrstuvwxyz123456"
    (site,) = agent_sites(f'new Agent({{ name: "{key}", tools: ["{key}", x], model: "{key}" }});\n', "a.ts")
    assert (site.name, site.tool_refs, site.model_expr) == ("[REDACTED]", ("[REDACTED]", "x"), "[REDACTED]")


def test_shorthand_tools_or_an_object_spread_means_tools_are_unknown():
    a, b, c = agent_sites(
        'new Agent({ name: "a", tools });\nnew Agent({ ...base, name: "b" });\nnew Agent({\n  name: "c",\n  tools\n});\n',
        "a.ts",
    )
    assert (a.tool_refs, b.tool_refs, c.tool_refs) == (None, None, None)
    assert b.name == "b"


def test_key_like_text_inside_an_expression_is_not_a_key():
    (site,) = agent_sites('new Agent({ description: x ? name : "y", name: "real" });\n', "a.ts")
    assert site.name == "real"


def test_null_or_undefined_tools_means_no_tools():
    a, b = agent_sites('new Agent({ name: "a", tools: null });\nnew Agent({ name: "b", tools: undefined });\n', "a.ts")
    assert (a.tool_refs, b.tool_refs) == ((), ())


def test_instructions_variable_is_redacted():
    (site,) = agent_sites('new Agent({ name: "a", instructions: AKIAABCDEFGHIJKLMNOP });\n', "a.ts")
    assert site.instructions == InstructionsRef("var", "[REDACTED]")


def test_comments_are_fully_blanked_in_the_top_level_view():
    from quin_scanner.inventory.js_sites import _top_level_view

    text = 'a, // x\n/* y */ b'
    view = _top_level_view(text)
    assert len(view) == len(text)
    assert view.split() == ["a,", "b"]
