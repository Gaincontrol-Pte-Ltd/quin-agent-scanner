"""The inventory resolver: one test per rule in spec §6."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.resolver import fallback, resolve
from quin_scanner.models import ToolUsage

PROMPT = InstructionsRef.literal("Find facts.")
OTHER = InstructionsRef.literal("Write prose.")


def agent(name, path="src/app.py", line=1, *, role="both", kind="constructor",
          instructions=NO_INSTRUCTIONS, tools=(), model=None, in_loop=False):
    return AgentSite(role=role, kind=kind, name=name, file_path=path, line=line, instructions=instructions,
                     model_expr=model, tool_refs=tools, in_loop=in_loop)


def tool(name, path="src/tools.py", line=1, kind="@tool"):
    return ToolSite(name=name, kind=kind, file_path=path, line=line)


# --- tools ------------------------------------------------------------------------------------


def test_unique_tool_names_get_plain_ids():
    inv = resolve([], [tool("search"), tool("calc", "src/calc.py")])
    assert [(t.id, t.tool_name, t.source_file, t.scope) for t in inv.tools] == [
        ("tool:calc", "calc", "src/calc.py", "production"),
        ("tool:search", "search", "src/tools.py", "production"),
    ]


def test_same_name_in_two_files_is_a_collision():
    inv = resolve([], [tool("search", "src/a.py"), tool("search", "tests/test_b.py")])
    assert [(t.id, t.scope) for t in inv.tools] == [
        ("tool:search@src/a.py", "production"),
        ("tool:search@tests/test_b.py", "test"),
    ]


def test_same_name_twice_in_one_file_is_one_tool():
    inv = resolve([], [tool("search", line=9), tool("search", line=3)])
    assert [(t.id, t.line_number) for t in inv.tools] == [("tool:search", 3)]


def test_extra_tools_are_merged_by_name():
    extras = [
        ToolUsage(tool_name="search", tool_type="external_service", service_category="web_search",
                  source_file="requirements.txt"),
        ToolUsage(tool_name="pdf", tool_type="skill", source_file="skills/pdf/SKILL.md"),
        ToolUsage(tool_name="SEARCH", tool_type="skill", source_file="skills/s/SKILL.md"),
    ]
    inv = resolve([], [tool("search")], extras)
    assert [(t.id, t.tool_type, t.service_category) for t in inv.tools] == [
        ("tool:pdf", "skill", ""),
        ("tool:search", "external_service", "web_search"),
    ]
