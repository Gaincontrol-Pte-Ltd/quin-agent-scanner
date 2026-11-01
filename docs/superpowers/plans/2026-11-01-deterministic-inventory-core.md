# Deterministic Inventory Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make static evidence the inventory of record: agents with instances, stable IDs, scope tags and tool-divergence flags. The LLM only enriches verified items by ID.

**Architecture:** `AgentInstanceScanner` and `ToolDefinitionScanner` keep emitting their `ScanFinding`s unchanged and additionally expose typed evidence (`AgentSite`, `ToolSite`) through `evidence()`. A new deterministic package, `quin_scanner/inventory/`, resolves that evidence into `AgentProfile`s (with `instances`), `ToolUsage`s and `AgentToolRelationship`s. The orchestrator uses it in place of the LLM-or-fallback agent and tool lists. The synthesis prompt receives the inventory by ID and returns enrichment and suggestions, which go to `llm_inferred_agents` / `llm_inferred_tools`. The report schema goes to 1.1; every change is additive.

**Tech Stack:** Python 3.11+, `ast`, `re`, PyYAML, pytest, jsonschema (existing). No new dependencies.

**Spec:** [docs/superpowers/specs/2026-11-01-deterministic-inventory-core-design.md](../specs/2026-11-01-deterministic-inventory-core-design.md)

---

## Before you start

- Create the branch from `main` **after 1.0.0 is released** (spec §11): `git checkout main && git pull && git checkout -b feat/inventory-core`.
- Run the suite once so you know it is green: `python3 -m pytest tests/ -q`. Lint with `ruff check src/ --select F,E4,E7,E9` (CONTRIBUTING.md).
- Commit messages follow `type(scope): message`, for example `feat(inventory): ...`. End each commit with the repo's co-author line if your tooling requires one.
- Paths in this plan are relative to the repo root (`quin-agent-scanner/`).

### Spec clarifications decided while planning

These fill gaps in the spec. They are binding for this plan.

1. **`tool_refs` semantics.** `()` means the call passed no tools: no `tools=` argument on an agent constructor, or an empty literal list. `None` means the tools are not statically known: a non-literal `tools=` (for example a variable), a subclass instantiation without `tools=`, or a definition-only site. Divergence compares only instances whose `tool_refs` is not `None`.
2. **CrewAI config linking is repo-wide by config key.** `agents_config['key']` in code links to the `agents.yaml` entry with that key in any file. This is an explicit key, not call-graph analysis. All other definition-to-instance links are same-file.
3. **Duplicate collision IDs get a counter.** Two colliding agents defined in the same file would both get `agent:<name>@<path>`. The second becomes `agent:<name>@<path>#2`, the third `#3`, and so on.
4. **`tool_usages` lists tool definitions only.** `tools=[a, b]` list items are references, not definitions: they still appear as artifacts and as instance tools (resolved or not), but they no longer appear in `tool_usages` on their own. ToolUsage gets no `flags` field; a tool collision is visible in its ID.
5. **Tool resolution order** is: a tool defined in the same file; otherwise a repo-unique tool name; otherwise unresolved. An imported name that collides across files stays unresolved.
6. **The orchestrator's `_is_test_path`** (used for model usages and endpoints) is **not** changed. `rules/scope.yaml` is new and used only by the inventory, so model and endpoint filtering does not change in this release.
7. **The LLM may also enrich tools** with `service_category`, by tool ID (`tool_enrichment`). Before this change the LLM supplied that category; without it the Tools tab would lose categories when an LLM is used.
8. **Test files are now read by the agent and tool scanners** to produce evidence, but still produce no findings. Read-coverage counters in `coverage` go up accordingly.
9. **Unnamed agent constructor calls** become weak agents only for `Agent`, `AssistantAgent`, `UserProxyAgent`, `ConversableAgent` and `GroupChatManager`, for calls carrying a CrewAI config key, and for constructors inside an `@agent` function. Other `...agent(...)` calls without a literal name (`create_react_agent(model, tools)`, `evaluate_agent(...)`) are ignored, as today.
10. **JavaScript/TypeScript sites never set `in_loop`.** Loop detection is Python-only.

---

## File structure

| File | Status | Responsibility |
|---|---|---|
| `src/quin_scanner/rules/scope.yaml` | create | Path rules for `production` / `test` / `example`. |
| `src/quin_scanner/inventory/__init__.py` | create | Public names of the package. |
| `src/quin_scanner/inventory/evidence.py` | create | `InstructionsRef`, `AgentSite`, `ToolSite` (internal, never serialised). |
| `src/quin_scanner/inventory/scope.py` | create | `scope_of(path)`. |
| `src/quin_scanner/inventory/python_sites.py` | create | One `ast` pass over a Python file → `AgentSite`s. |
| `src/quin_scanner/inventory/js_sites.py` | create | `new Agent({...})` object literals → `AgentSite`s (moved from `agent_tool_relationships.py`). |
| `src/quin_scanner/inventory/resolver.py` | create | `resolve()` and `fallback()`: sites → `Inventory`. |
| `src/quin_scanner/models.py` | modify | `InstanceTool`, `AgentInstance`, `LLMInferredItem`, `AgentEnrichment`; new fields on `AgentProfile`, `ToolUsage`, `AgentToolRelationship`, `ScanReport`; new `SynthesisResult`. |
| `src/quin_scanner/schema.py` | modify | `REPORT_SCHEMA_VERSION = "1.1"`. |
| `docs/schema/report-1.json` | modify | New optional definitions and properties. |
| `docs/schema/README.md` | modify | 1.1 fields and records. |
| `src/quin_scanner/scanners/base.py` | modify | `EvidenceProducer` protocol. |
| `src/quin_scanner/scanners/agent_instance_scanner.py` | modify | Emit `AgentSite`s (test files included). |
| `src/quin_scanner/scanners/tool_definition_scanner.py` | modify | Emit `ToolSite`s (test files included). |
| `src/quin_scanner/agent_tool_relationships.py` | delete | Replaced by the resolver. |
| `src/quin_scanner/orchestrator.py` | modify | Build the inventory; replace post-processing Rules 2–4; LLM digest and enrichment merge. |
| `src/quin_scanner/llm/synthesis_agent.py` | modify | Inventory-by-ID prompt contract and parser. |
| `src/quin_scanner/html_template.py` | modify | Agents tab: instances table, scope filter, flags, unverified suggestions. |
| `tests/test_inventory_scope.py` | create | Scope rules and `InstructionsRef`. |
| `tests/test_inventory_models.py` | create | New model fields and serialisation. |
| `tests/test_inventory_python_sites.py` | create | Python extraction. |
| `tests/test_inventory_js_sites.py` | create | JS/TS extraction. |
| `tests/test_tool_definition_scanner.py` | create | Tool evidence. |
| `tests/test_inventory_resolver.py` | create | Every resolver rule. |
| `tests/test_inventory_orchestrator.py` | create | End-to-end scans, LLM contract, outputs. |
| `tests/test_agent_instance_scanner.py`, `tests/test_agent_tool_relationships.py`, `tests/test_llm_parsing.py`, `tests/test_orchestrator_helpers.py`, `tests/test_report_schema.py`, `tests/test_hash_seed_determinism.py` | modify | As described per task. |
| `tests/corpus/expected/*.json` | modify | Regenerated and reviewed. |
| `CHANGELOG.md`, `README.md` | modify | Release notes and feature table. |

---

### Task 1: Scope rules and evidence types

**Files:**
- Create: `src/quin_scanner/rules/scope.yaml`
- Create: `src/quin_scanner/inventory/__init__.py` (temporary, completed in Task 9)
- Create: `src/quin_scanner/inventory/evidence.py`
- Create: `src/quin_scanner/inventory/scope.py`
- Test: `tests/test_inventory_scope.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_scope.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_inventory_scope.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'quin_scanner.inventory'`.

- [ ] **Step 3: Create the scope rules**

`src/quin_scanner/rules/scope.yaml`:

```yaml
# Where a path lives, for agents, instances and tools in the inventory (inventory/scope.py).
# Patterns are regular expressions matched case-insensitively against the repo-relative path with "/" separators.
# Test rules are checked before example rules; a path that matches neither is production.
test:
  - '(^|/)(tests?|__tests__|fixtures)/'
  - '(^|/)test_[^/]*$'
  - '(^|/)conftest\.py$'
  - '[._]test\.[^/]*$'
  - '\.spec\.[^/]*$'
example:
  - '(^|/)(examples?|samples?|cookbooks?|notebooks?|docs|demos?|tutorials?)/'
```

- [ ] **Step 4: Create the package and evidence types**

`src/quin_scanner/inventory/__init__.py` (Task 9 adds the resolver exports):

```python
"""The inventory of record: typed scanner evidence resolved into agents, instances and tools."""
```

`src/quin_scanner/inventory/evidence.py`:

```python
"""Typed evidence that scanners hand to the inventory resolver. Internal: never serialised into a report."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class InstructionsRef:
    """What an agent's instructions are: part of the agent's identity (with its name)."""
    kind: str = "none"   # "literal" | "file" | "var" | "config" | "none"
    value: str = ""      # literal → sha256 of the whitespace-normalised text; else the path, variable or config key

    @classmethod
    def literal(cls, text: str) -> InstructionsRef:
        normalised = " ".join(text.split())
        return cls("literal", hashlib.sha256(normalised.encode("utf-8")).hexdigest())

    @property
    def is_known(self) -> bool:
        return self.kind != "none"


NO_INSTRUCTIONS = InstructionsRef()


@dataclass(frozen=True)
class AgentSite:
    """One place in the code or configuration that defines and/or creates an agent."""
    role: str                                  # "definition" | "instance" | "both"
    kind: str                                  # "constructor" | "subclass" | "config_entry" | "decorator" | "graph_node"
    name: str | None                           # literal name only; None when dynamic
    file_path: str
    line: int | None
    instructions: InstructionsRef = NO_INSTRUCTIONS
    model_expr: str | None = None              # redacted literal or reference, e.g. "env:MODEL", "var:settings.llm"
    tool_refs: tuple[str, ...] | None = None   # () = no tools passed; None = not statically known
    in_loop: bool = False                      # inside a for/while/comprehension (Python only)
    framework_hint: str = ""


@dataclass(frozen=True)
class ToolSite:
    """One place that defines a tool (not a reference to one in a tools=[...] list)."""
    name: str
    kind: str                                  # the scanner's label: "@tool", "BaseTool", "config", "function", ...
    file_path: str
    line: int | None
```

- [ ] **Step 5: Create the scope module**

`src/quin_scanner/inventory/scope.py`:

```python
"""Where a path lives: production, test or example code (rules/scope.yaml; first match wins)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

_RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "scope.yaml"


@lru_cache(maxsize=1)
def _rules() -> tuple[tuple[str, re.Pattern[str]], ...]:
    data = yaml.safe_load(_RULES_FILE.read_text(encoding="utf-8")) or {}
    return tuple(
        (scope, re.compile(pattern, re.IGNORECASE))
        for scope in ("test", "example")
        for pattern in data.get(scope, [])
    )


def scope_of(path: str) -> str:
    """"test", "example" or "production" for a repo-relative path."""
    normalised = path.replace("\\", "/")
    for scope, pattern in _rules():
        if pattern.search(normalised):
            return scope
    return "production"
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_inventory_scope.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/quin_scanner/rules/scope.yaml src/quin_scanner/inventory tests/test_inventory_scope.py
git commit -m "feat(inventory): scope rules and typed evidence for agents and tools"
```

---

### Task 2: Report model and schema 1.1

**Files:**
- Modify: `src/quin_scanner/models.py` (classes `AgentProfile` at ~line 85, `AgentToolRelationship` ~108, `ToolUsage` ~160, `ScanReport` ~385)
- Modify: `src/quin_scanner/schema.py`
- Modify: `docs/schema/report-1.json`
- Modify: `docs/schema/README.md`
- Modify: `tests/test_report_schema.py`
- Test: `tests/test_inventory_models.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_models.py`:

```python
"""Report records added by the inventory (schema 1.1)."""
from __future__ import annotations

from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    AgentToolRelationship,
    InstanceTool,
    LLMInferredItem,
    ScanReport,
    ToolUsage,
)


def test_agent_profile_serialises_the_new_fields_with_defaults():
    d = AgentProfile(name="a", agent_type="unknown", goal="").to_dict()
    assert (d["id"], d["identity"], d["scope"]) == ("", "strong", "production")
    assert (d["flags"], d["provenance"], d["instances"]) == ([], {}, [])


def test_agent_instance_round_trip():
    instance = AgentInstance(
        id="agent:r/a.py#1", file="a.py", line=3, scope="production", multiplicity="many", model="env:MODEL",
        tools=[InstanceTool(name="search", tool_id="tool:search", resolved=True), InstanceTool(name="ghost")],
    )
    assert instance.to_dict() == {
        "id": "agent:r/a.py#1", "file": "a.py", "line": 3, "scope": "production", "multiplicity": "many",
        "model": "env:MODEL",
        "tools": [
            {"name": "search", "tool_id": "tool:search", "resolved": True},
            {"name": "ghost", "tool_id": None, "resolved": False},
        ],
    }


def test_existing_records_gain_ids():
    tool = ToolUsage(tool_name="t").to_dict()
    assert (tool["id"], tool["scope"]) == ("", "production")
    edge = AgentToolRelationship(agent_name="a", tool_name="t", source_file="a.py", line_number=1).to_dict()
    assert (edge["agent_id"], edge["instance_id"], edge["tool_id"]) == ("", "", None)


def test_report_carries_the_llm_inferred_lists():
    report = ScanReport(
        repo_path="r", scan_timestamp="t", is_ai_application=False, confidence=0.0,
        llm_inferred_agents=[LLMInferredItem(name="planner", evidence="factory", file="a.py")],
    )
    data = report.to_dict()
    assert data["llm_inferred_agents"] == [{"name": "planner", "evidence": "factory", "file": "a.py"}]
    assert data["llm_inferred_tools"] == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_models.py -q`
Expected: FAIL with `ImportError: cannot import name 'AgentInstance'`.

- [ ] **Step 3: Add the new records to `models.py`**

Insert directly **above** `class AgentProfile`:

```python
@dataclass
class InstanceTool:
    """A tool passed to one agent instance, linked to its definition when one was found."""
    name: str
    tool_id: str | None = None
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "tool_id": self.tool_id, "resolved": self.resolved}


@dataclass
class AgentInstance:
    """A place in the code that creates an agent, with what is passed there."""
    id: str
    file: str
    line: int | None
    scope: str = "production"            # "production" | "test" | "example"
    multiplicity: str = "one"            # "many" when created inside a loop or comprehension
    model: str | None = None             # redacted literal or reference ("env:MODEL", "var:settings.llm")
    tools: list[InstanceTool] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "scope": self.scope,
            "multiplicity": self.multiplicity,
            "model": self.model,
            "tools": [t.to_dict() for t in self.tools],
        }
```

Replace `class AgentProfile` with:

```python
@dataclass
class AgentProfile:
    name: str
    agent_type: str                      # "supervisor" | "utility" | "worker" | "unknown"
    goal: str
    capabilities: list[str] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)   # union of the instances' tools
    source_file: str = ""                            # the definition site
    id: str = ""                                     # "agent:<name>", "agent:<name>@<path>", "agent:@<path>#<n>"
    identity: str = "strong"                         # "strong" (literal name) | "weak"
    scope: str = "production"                        # production if any instance is, else test, else example
    flags: list[str] = field(default_factory=list)   # name_collision, tool_divergence, model_divergence, ambiguous_instance
    provenance: dict[str, str] = field(default_factory=dict)   # field name → "static" | "llm"
    instances: list[AgentInstance] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "agent_type": self.agent_type,
            "goal": self.goal,
            "capabilities": self.capabilities,
            "risk_signals": [r.to_dict() if isinstance(r, RiskIndicator) else r for r in self.risk_signals],
            "skills": self.skills,
            "tools": self.tools,
            "source_file": self.source_file,
            "id": self.id,
            "identity": self.identity,
            "scope": self.scope,
            "flags": self.flags,
            "provenance": self.provenance,
            "instances": [i.to_dict() for i in self.instances],
        }
```

In `AgentToolRelationship`, add three fields after `evidence` and three keys at the end of `to_dict`:

```python
    agent_id: str = ""
    instance_id: str = ""
    tool_id: str | None = None
```

```python
            "agent_id": self.agent_id,
            "instance_id": self.instance_id,
            "tool_id": self.tool_id,
```

In `ToolUsage`, add two fields after `line_number` and two keys at the end of `to_dict`:

```python
    id: str = ""                         # "tool:<name>", or "tool:<name>@<path>" when two files define the name
    scope: str = "production"
```

```python
            "id": self.id,
            "scope": self.scope,
```

Insert directly **below** `class ToolUsage` (above `SynthesisResult`):

```python
@dataclass
class LLMInferredItem:
    """An agent or tool the LLM suggested that has no static evidence: reported, never part of the inventory."""
    name: str
    evidence: str = ""
    file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "evidence": self.evidence, "file": self.file}
```

In `ScanReport`, add after `agent_tool_relationships`:

```python
    llm_inferred_agents: list[LLMInferredItem] = field(default_factory=list)
    llm_inferred_tools: list[LLMInferredItem] = field(default_factory=list)
```

and in `_base_dict`, after the `"agent_tool_relationships"` entry:

```python
            "llm_inferred_agents": [i.to_dict() for i in self.llm_inferred_agents],
            "llm_inferred_tools": [i.to_dict() for i in self.llm_inferred_tools],
```

- [ ] **Step 4: Run the new tests**

Run: `python3 -m pytest tests/test_inventory_models.py -q`
Expected: PASS.

- [ ] **Step 5: Run the schema tests to see what they now require**

Run: `python3 -m pytest tests/test_report_schema.py tests/test_stability_docs.py -q`
Expected: FAIL in `test_every_emitted_field_is_documented_in_the_schema` (undocumented `$.agents[0].id` and others) and `test_documented_report_fields_match_the_report` (`llm_inferred_agents`, `llm_inferred_tools`).

- [ ] **Step 6: Bump the schema version**

`src/quin_scanner/schema.py`: change `REPORT_SCHEMA_VERSION = "1.0"` to `REPORT_SCHEMA_VERSION = "1.1"`.

- [ ] **Step 7: Extend `docs/schema/report-1.json`**

All changes are additions. Keep the file's 2-space indentation.

In `$defs.agent.properties`, add:

```json
"id": {"type": "string", "description": "Stable ID: agent:<name>; agent:<name>@<definition path> on a name collision; agent:@<path>#<n> without a literal name."},
"identity": {"type": "string", "description": "strong (literal name) or weak (no literal name)."},
"scope": {"type": "string", "description": "production, test or example: production if any instance is."},
"flags": {"type": "array", "items": {"type": "string"}, "description": "name_collision, tool_divergence, model_divergence, ambiguous_instance."},
"provenance": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Field name to static or llm."},
"instances": {"type": "array", "items": {"$ref": "#/$defs/agentInstance"}}
```

Do **not** add them to `$defs.agent.required`: 1.x only adds optional fields, so a 1.0 report must still validate (they are always emitted anyway).

Add three new definitions to `$defs`:

```json
"instanceTool": {
  "type": "object",
  "required": ["name", "tool_id", "resolved"],
  "properties": {
    "name": {"type": "string"},
    "tool_id": {"type": ["string", "null"], "description": "ID of the tool definition, null when none was found."},
    "resolved": {"type": "boolean"}
  }
},
"agentInstance": {
  "type": "object",
  "required": ["id", "file", "line", "scope", "multiplicity", "model", "tools"],
  "properties": {
    "id": {"type": "string", "description": "<agent id>/<path>#<n>."},
    "file": {"type": "string"},
    "line": {"type": ["integer", "null"]},
    "scope": {"type": "string"},
    "multiplicity": {"type": "string", "description": "one, or many when created inside a loop."},
    "model": {"type": ["string", "null"]},
    "tools": {"type": "array", "items": {"$ref": "#/$defs/instanceTool"}}
  }
},
"llmInferred": {
  "type": "object",
  "required": ["name", "evidence", "file"],
  "properties": {
    "name": {"type": "string"},
    "evidence": {"type": "string"},
    "file": {"type": "string"}
  }
}
```

In `$defs.toolUsage.properties` add `"id": {"type": "string"}` and `"scope": {"type": "string"}`, (not in `required`).

In `$defs.relationship.properties` add:

```json
"agent_id": {"type": "string"},
"instance_id": {"type": "string"},
"tool_id": {"type": ["string", "null"]}
```

(not in `required`).

In the top-level `properties` add:

```json
"llm_inferred_agents": {"type": "array", "items": {"$ref": "#/$defs/llmInferred"}, "description": "Agents the LLM suggested with no code evidence; not part of the inventory."},
"llm_inferred_tools": {"type": "array", "items": {"$ref": "#/$defs/llmInferred"}, "description": "Tools the LLM suggested with no code evidence; not part of the inventory."}
```

(not in the top-level `required`). The three new `$defs` are new records, so they do list all their fields as required.

- [ ] **Step 8: Update `docs/schema/README.md`**

- Line 3 and the `schema_version` table row: `currently \`1.0\`` → `currently \`1.1\``.
- In the report-fields table, change the `agents` row's meaning to `Agents (one per logical agent) with their instances, tools, skills and risk signals.` and the `tool_usages` row to `Tool definitions, external services, skills and MCP tools in use.`; add after the `agent_tool_relationships` row:

```markdown
| `llm_inferred_agents` | always | list of object | Agents the LLM suggested that Quin found no code evidence for. |
| `llm_inferred_tools` | always | list of object | Tools the LLM suggested that Quin found no code evidence for. |
```

- Under `## Records`, after the **Tool usage** record, add:

```markdown
**Agent** (1.1 additions): `id`, `identity` (`strong` or `weak`), `scope` (`production`, `test` or `example`), `flags`, `provenance` (field name → `static` or `llm`) and `instances`. An agent is identified by its literal name and instructions; every place that creates it is an instance. `tools` is the union of the instances' tools and `source_file` is the definition site. IDs never contain line numbers or prompt text: `agent:<name>`, or `agent:<name>@<definition path>` when two different agents share a name, or `agent:@<path>#<n>` when there is no literal name. Static analysis cannot count runtime objects, so an instance created inside a loop has `multiplicity: many`.

**Agent instance**: `id` (`<agent id>/<path>#<n>`), `file`, `line`, `scope`, `multiplicity` (`one` or `many`), `model` (redacted literal or a reference such as `env:MODEL`), `tools` (list of `name`, `tool_id` (string or null) and `resolved`). Only explicit `tools=[...]` lists are read.

**Tool usage** (1.1 additions): `id` (`tool:<name>`, or `tool:<name>@<path>` when two files define the name) and `scope`.

**Agent-tool relationship** (1.1 additions): `agent_id`, `instance_id`, `tool_id` (string or null).

**LLM-inferred item**: `name`, `evidence`, `file`. These have no ID and are never part of the inventory, the BOM or divergence findings.

Flags: `name_collision` (another agent has the same name), `tool_divergence` (instances are given different tools; when production instances differ it is also a T006 risk signal), `model_divergence` (instances use different models; informational), `ambiguous_instance` (an instance with unknown instructions could belong to several same-named agents).
```

- [ ] **Step 9: Update `tests/test_report_schema.py`**

- Lines asserting `"1.0"` (`test_report_carries_schema_version_first`, `test_json_and_yaml_outputs_carry_schema_version`, `test_skills_scan_envelope_validates`): change to `"1.1"`.
- Add `AgentInstance, InstanceTool, LLMInferredItem` to the `quin_scanner.models` import.
- In `_rich_report()`, replace the `agents=[...]`, `tool_usages=[...]` and `agent_tool_relationships=[...]` arguments, and add the two inferred lists, so every new record type is exercised:

```python
        agents=[AgentProfile(name="a", agent_type="worker", goal="g", capabilities=["c"], risk_signals=[risk],
                             skills=["k"], tools=["t"], source_file="a.py", id="agent:a", identity="strong",
                             scope="production", flags=["tool_divergence"],
                             provenance={"name": "static", "goal": "llm"},
                             instances=[AgentInstance(id="agent:a/a.py#1", file="a.py", line=3, model=None,
                                                      tools=[InstanceTool(name="t", tool_id="tool:t", resolved=True),
                                                             InstanceTool(name="u")])])],
        tool_usages=[ToolUsage(tool_name="t", line_number=None, id="tool:t", scope="production")],
```

```python
        agent_tool_relationships=[AgentToolRelationship(agent_name="a", tool_name="t", source_file="a.py",
                                                        line_number=None, tool_source_file="", tool_line_number=None,
                                                        evidence="e", agent_id="agent:a",
                                                        instance_id="agent:a/a.py#1", tool_id="tool:t")],
        llm_inferred_agents=[LLMInferredItem(name="p", evidence="e", file="a.py")],
        llm_inferred_tools=[LLMInferredItem(name="q", evidence="e", file="a.py")],
```

- [ ] **Step 10: Run the schema, docs and model tests**

Run: `python3 -m pytest tests/test_report_schema.py tests/test_stability_docs.py tests/test_inventory_models.py -q`
Expected: PASS, including `test_schemas_are_compatible_with_the_frozen_1_0_baseline` (additions only).

- [ ] **Step 11: Run the full suite**

Run: `python3 -m pytest tests/ -q`
Expected: PASS. If another test pins `schema_version == "1.0"`, change it to `"1.1"`; it is the same deliberate bump.

- [ ] **Step 12: Commit**

```bash
git add src/quin_scanner/models.py src/quin_scanner/schema.py docs/schema tests/test_inventory_models.py tests/test_report_schema.py
git commit -m "feat(inventory): agent instances, IDs and LLM-inferred lists in the report (schema 1.1)"
```

---

### Task 3: Python agent sites

**Files:**
- Create: `src/quin_scanner/inventory/python_sites.py`
- Test: `tests/test_inventory_python_sites.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_python_sites.py`:

```python
"""Agent sites from one ast pass over a Python file."""
from __future__ import annotations

import pytest

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef
from quin_scanner.inventory.python_sites import agent_sites, parse_python


def _sites(source: str, path: str = "app.py"):
    tree = parse_python(source)
    assert tree is not None
    return agent_sites(tree, path)


def test_inline_constructor_carries_identity_and_instance_attributes():
    (site,) = _sites(
        'researcher = Agent(name="researcher", instructions="Find  facts.", model="gpt-4o",'
        ' tools=[search, "fetch", Tool(name="calc")])\n'
    )
    assert (site.role, site.kind, site.name, site.file_path, site.line) == ("both", "constructor", "researcher", "app.py", 1)
    assert site.instructions == InstructionsRef.literal("Find facts.")
    assert site.model_expr == "gpt-4o"
    assert site.tool_refs == ("search", "fetch", "calc")
    assert site.in_loop is False


def test_no_tools_argument_means_none_passed_and_a_non_literal_list_means_unknown():
    a, b = _sites('a = Agent(name="a")\nb = Agent(name="b", tools=TOOLS)\n')
    assert a.tool_refs == ()
    assert b.tool_refs is None


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("PROMPT", InstructionsRef("var", "PROMPT")),
        ("prompts.RESEARCHER", InstructionsRef("var", "prompts.RESEARCHER")),
        ('open("prompts/r.md").read()', InstructionsRef("file", "prompts/r.md")),
        ('Path("prompts/r.md").read_text()', InstructionsRef("file", "prompts/r.md")),
        ('f"Be {x}"', NO_INSTRUCTIONS),
    ],
)
def test_instruction_references(expr, expected):
    (site,) = _sites(f'a = Agent(name="a", instructions={expr})\n')
    assert site.instructions == expected


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ('os.getenv("MODEL")', "env:MODEL"),
        ('os.environ["MODEL"]', "env:MODEL"),
        ('os.environ.get("MODEL", "gpt-4o")', "env:MODEL"),
        ("settings.llm", "var:settings.llm"),
        ('OpenAIChat("gpt-4o")', "OpenAIChat('gpt-4o')"),
    ],
)
def test_model_expressions(expr, expected):
    (site,) = _sites(f'a = Agent(name="a", model={expr})\n')
    assert site.model_expr == expected


def test_autogen_keywords_and_positional_name():
    (site,) = _sites('a = AssistantAgent("helper", system_message=SYS, model_client=client)\n')
    assert (site.name, site.instructions, site.model_expr) == ("helper", InstructionsRef("var", "SYS"), "var:client")


def test_agents_built_in_loops_are_marked():
    sites = _sites('agents = [Agent(name="w", tools=[t]) for t in tools]\nfor i in range(3):\n    x = Agent(name="v")\n')
    assert [(s.name, s.in_loop) for s in sites] == [("w", True), ("v", True)]


def test_anonymous_agent_constructor_is_a_weak_site_but_other_agent_calls_are_not():
    sites = _sites(
        'a = Agent("openai:gpt-4o", system_prompt="Be brief.")\n'
        "b = create_react_agent(model, tools)\n"
        "c = evaluate_agent(agent=a)\n"
    )
    assert [(s.name, s.instructions.kind) for s in sites] == [(None, "literal")]


def test_subclass_definition_and_its_instances_in_the_same_file():
    sites = _sites("class Writer(BaseAgent):\n    pass\n\nw = Writer(tools=[pen])\nx = Writer()\n")
    assert [(s.role, s.kind, s.name, s.line, s.tool_refs) for s in sites] == [
        ("definition", "subclass", "Writer", 1, None),
        ("instance", "constructor", "Writer", 4, ("pen",)),
        ("instance", "constructor", "Writer", 5, None),
    ]


def test_crewai_agent_method_names_the_agent_it_builds():
    source = (
        "class Crew:\n"
        "    @agent\n"
        "    def researcher(self) -> Agent:\n"
        "        return Agent(config=self.agents_config['researcher'], tools=[search])\n"
    )
    (site,) = _sites(source)
    assert (site.name, site.instructions, site.tool_refs, site.line) == (
        "researcher", InstructionsRef("config", "researcher"), ("search",), 4,
    )


def test_a_decorated_agent_function_without_a_constructor_is_a_definition_and_its_calls_are_instances():
    sites = _sites("@agent\ndef planner():\n    pass\n\nplanner()\n")
    assert [(s.role, s.kind, s.name, s.line) for s in sites] == [
        ("definition", "decorator", "planner", 1),
        ("instance", "decorator", "planner", 5),
    ]


def test_literal_model_text_is_redacted():
    (site,) = _sites('a = Agent(name="a", model="https://user:sk-abc123def456ghi789jkl@host/v1")\n')
    assert "sk-abc123" not in site.model_expr


def test_unparseable_source_gives_none():
    assert parse_python("this is not python (\n") is None
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_python_sites.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'quin_scanner.inventory.python_sites'`.

- [ ] **Step 3: Implement `python_sites.py`**

`src/quin_scanner/inventory/python_sites.py`:

```python
"""Agent sites in Python source: one ``ast`` pass gives AgentInstanceScanner its typed evidence."""
from __future__ import annotations

import ast
import warnings

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef
from quin_scanner.redaction import redact_secrets

_NAME_KEYWORDS = frozenset({"name", "agent_name"})
_INSTRUCTION_KEYWORDS = ("instructions", "system_prompt", "system_message", "backstory")
_MODEL_KEYWORDS = ("model", "llm", "model_client")
# Base classes that make a subclass an agent (as AgentInstanceScanner's class patterns).
_AGENT_BASES = frozenset({"Role", "BaseAgent", "AssistantAgent", "ConversableAgent", "UserProxyAgent"})
# Constructors that create an agent even without a literal name; other ``...agent(...)`` calls need one.
_ANONYMOUS_CONSTRUCTORS = frozenset({"Agent", "AssistantAgent", "UserProxyAgent", "ConversableAgent", "GroupChatManager"})
# Calls whose first string argument is a file the instructions are read from.
_FILE_READERS = frozenset({"open", "Path", "read_text", "load_prompt"})


def parse_python(content: str) -> ast.Module | None:
    """The module's syntax tree, or None if the source does not parse."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None


def callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def string_constant(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def agent_name(call: ast.Call, callee: str) -> str | None:
    """The literal ``name=``/``agent_name=``, or for ``XAgent("...")`` classes (not bare ``Agent``) the first positional string."""
    name = next((string_constant(kw.value) for kw in call.keywords if kw.arg in _NAME_KEYWORDS), None)
    if name is None and callee.endswith("Agent") and callee != "Agent" and call.args:
        positional = string_constant(call.args[0])
        if positional is not None and 2 <= len(positional) <= 50:
            name = positional
    return name.strip() if name and name.strip() else None


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _first_string_arg(call: ast.Call) -> str | None:
    return next((s for s in (string_constant(a) for a in call.args) if s is not None), None)


def _config_key(node: ast.expr) -> str | None:
    """``self.agents_config['researcher']`` → ``researcher`` (CrewAI)."""
    if isinstance(node, ast.Subscript) and (_dotted(node.value) or "").endswith("agents_config"):
        return string_constant(node.slice)
    return None


def _instructions_ref(node: ast.expr) -> InstructionsRef:
    text = string_constant(node)
    if text is not None:
        return InstructionsRef.literal(text)
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and callee_name(sub.func) in _FILE_READERS:
            path = _first_string_arg(sub)
            if path:
                return InstructionsRef("file", path)
    dotted = _dotted(node)
    return InstructionsRef("var", dotted) if dotted else NO_INSTRUCTIONS


def instructions_of(call: ast.Call) -> InstructionsRef:
    for kw in call.keywords:
        if kw.arg == "config":
            key = _config_key(kw.value)
            if key:
                return InstructionsRef("config", key)
    for kw in call.keywords:
        if kw.arg in _INSTRUCTION_KEYWORDS:
            return _instructions_ref(kw.value)
    return NO_INSTRUCTIONS


def _env_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call):
        if callee_name(node.func) == "getenv" or (_dotted(node.func) or "").endswith("environ.get"):
            return _first_string_arg(node)
    if isinstance(node, ast.Subscript) and (_dotted(node.value) or "").endswith("environ"):
        return string_constant(node.slice)
    return None


def _expression(node: ast.expr) -> str | None:
    text = string_constant(node)
    if text is not None:
        return redact_secrets(text)
    env = _env_name(node)
    if env:
        return f"env:{env}"
    dotted = _dotted(node)
    if dotted:
        return f"var:{dotted}"
    if isinstance(node, ast.Call):
        callee = callee_name(node.func) or "call"
        arg = _first_string_arg(node)
        return redact_secrets(f"{callee}({arg!r})" if arg else f"{callee}()")
    return None


def model_of(call: ast.Call) -> str | None:
    return next((_expression(kw.value) for kw in call.keywords if kw.arg in _MODEL_KEYWORDS), None)


def _tool_reference(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    text = string_constant(node)
    if text is not None:
        return text
    if isinstance(node, ast.Call):
        return next((string_constant(kw.value) for kw in node.keywords if kw.arg == "name"), None)
    return None


def tool_refs_of(call: ast.Call, missing: tuple[str, ...] | None) -> tuple[str, ...] | None:
    """Names in an explicit ``tools=[...]``; ``missing`` when there is no ``tools=``; None when it is not a literal list."""
    kw = next((k for k in call.keywords if k.arg == "tools"), None)
    if kw is None:
        return missing
    if not isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
        return None
    refs = (_tool_reference(element) for element in kw.value.elts)
    return tuple(ref.strip() for ref in refs if ref and ref.strip())


def _agent_functions(tree: ast.Module) -> dict[str, int]:
    """Functions decorated with ``@agent`` (CrewAI and similar), with the decorator's line."""
    found: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if callee_name(target) == "agent":
                    found.setdefault(node.name, decorator.lineno)
    return found


def _agent_classes(tree: ast.Module) -> dict[str, int]:
    return {
        node.name: node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and any(callee_name(base) in _AGENT_BASES for base in node.bases)
    }


class _Collector(ast.NodeVisitor):
    def __init__(self, path: str, classes: dict[str, int], functions: dict[str, int]) -> None:
        self.path = path
        self.classes = classes
        self.functions = functions
        self.sites: list[AgentSite] = []
        self.functions_with_constructors: set[str] = set()
        self._loops = 0
        self._enclosing: list[str | None] = []   # innermost last; None for functions that are not @agent

    def _loop(self, node: ast.AST) -> None:
        self._loops += 1
        self.generic_visit(node)
        self._loops -= 1

    visit_For = visit_AsyncFor = visit_While = _loop
    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _loop

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._enclosing.append(node.name if node.name in self.functions else None)
        self.generic_visit(node)
        self._enclosing.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        site = self._site(node)
        if site is not None:
            self.sites.append(site)
        self.generic_visit(node)

    def _site(self, node: ast.Call) -> AgentSite | None:
        callee = callee_name(node.func)
        if not callee:
            return None
        common = {"file_path": self.path, "line": node.lineno, "in_loop": self._loops > 0}
        if callee in self.classes:
            return AgentSite(
                role="instance", kind="constructor", name=agent_name(node, callee) or callee,
                instructions=instructions_of(node), model_expr=model_of(node),
                tool_refs=tool_refs_of(node, missing=None), **common,
            )
        if isinstance(node.func, ast.Name) and callee in self.functions:
            return AgentSite(role="instance", kind="decorator", name=callee, **common)
        lowered = callee.lower()
        if lowered != "groupchatmanager" and not lowered.endswith("agent"):
            return None
        name = agent_name(node, callee)
        instructions = instructions_of(node)
        enclosing = next((f for f in reversed(self._enclosing) if f), None)
        if enclosing:
            self.functions_with_constructors.add(enclosing)
            name = name or enclosing
        if name is None and callee not in _ANONYMOUS_CONSTRUCTORS and instructions.kind != "config":
            return None
        return AgentSite(
            role="both", kind="constructor", name=name, instructions=instructions,
            model_expr=model_of(node), tool_refs=tool_refs_of(node, missing=()), **common,
        )


def agent_sites(tree: ast.Module, path: str) -> list[AgentSite]:
    """Every agent definition and instance in one parsed Python file, sorted by line."""
    classes = _agent_classes(tree)
    functions = _agent_functions(tree)
    collector = _Collector(path, classes, functions)
    collector.visit(tree)
    sites = list(collector.sites)
    sites += [
        AgentSite(role="definition", kind="subclass", name=name, file_path=path, line=line)
        for name, line in classes.items()
    ]
    sites += [
        AgentSite(role="definition", kind="decorator", name=name, file_path=path, line=line)
        for name, line in functions.items()
        if name not in collector.functions_with_constructors
    ]
    return sorted(sites, key=lambda s: (s.line or 0, s.name or "", s.kind))
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_inventory_python_sites.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/quin_scanner/inventory/python_sites.py tests/test_inventory_python_sites.py
git commit -m "feat(inventory): Python agent sites with instructions, model, tools and loop context"
```

---

### Task 4: JavaScript/TypeScript agent sites

**Files:**
- Create: `src/quin_scanner/inventory/js_sites.py`
- Test: `tests/test_inventory_js_sites.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_js_sites.py`:

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_js_sites.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `js_sites.py`**

The brace matcher and the agent-call, name, tools and tool-reference regexes move here unchanged from `src/quin_scanner/agent_tool_relationships.py` (deleted in Task 10).

`src/quin_scanner/inventory/js_sites.py`:

```python
"""Agent sites in JavaScript/TypeScript: ``new Agent({...})`` object literals (AgentInstanceScanner's evidence)."""
from __future__ import annotations

import re

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef
from quin_scanner.redaction import redact_secrets

_AGENT_CALL = re.compile(r"\b(?:new\s+)?(?:Agent|AssistantAgent|UserProxyAgent|ConversableAgent)\s*\(\s*\{")
_NAME = re.compile(r"\bname\s*:\s*(['\"])(.*?)\1", re.DOTALL)
_TOOLS_KEY = re.compile(r"\btools\s*:")
_TOOLS = re.compile(r"\btools\s*:\s*\[([^\]]*)\]", re.DOTALL)
_TOOL_REF = re.compile(r"^\s*([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*$")
_STRING_FIELD = r"\b{key}\s*:\s*(['\"`])(.*?)\1"
_EXPR_FIELD = r"\b{key}\s*:\s*([A-Za-z_$][\w$.]*(?:\([^)]*\))?)"


def _matching_brace(content: str, opening: int) -> int | None:
    """Find a closing brace while ignoring braces inside strings and comments."""
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    i = opening
    while i < len(content):
        char = content[i]
        nxt = content[i + 1] if i + 1 < len(content) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
        elif char == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif char == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _field(body: str, key: str) -> tuple[str, str] | None:
    """("literal", text) for a quoted value, ("expr", text) for an identifier or call, else None."""
    match = re.search(_STRING_FIELD.format(key=key), body, re.DOTALL)
    if match:
        return "literal", match.group(2)
    match = re.search(_EXPR_FIELD.format(key=key), body)
    if match:
        return "expr", match.group(1)
    return None


def _tool_refs(body: str) -> tuple[str, ...] | None:
    tools = _TOOLS.search(body)
    if tools is None:
        return None if _TOOLS_KEY.search(body) else ()
    refs = []
    for item in tools.group(1).split(","):
        match = _TOOL_REF.match(item)
        if match and match.group(1).strip("'\""):
            refs.append(match.group(1).strip("'\""))
    return tuple(refs)


def agent_sites(content: str, path: str) -> list[AgentSite]:
    sites: list[AgentSite] = []
    for call in _AGENT_CALL.finditer(content):
        opening = call.end() - 1
        closing = _matching_brace(content, opening)
        if closing is None:
            continue
        body = content[opening + 1:closing]
        name_match = _NAME.search(body)
        instructions = NO_INSTRUCTIONS
        found = _field(body, "instructions")
        if found:
            instructions = InstructionsRef.literal(found[1]) if found[0] == "literal" else InstructionsRef("var", found[1])
        model_expr = None
        found = _field(body, "model")
        if found:
            kind, text = found
            model_expr = redact_secrets(text if kind == "literal" or "(" in text else f"var:{text}")
        sites.append(AgentSite(
            role="both", kind="constructor",
            name=name_match.group(2).strip() or None if name_match else None,
            file_path=path, line=content.count("\n", 0, call.start()) + 1,
            instructions=instructions, model_expr=model_expr, tool_refs=_tool_refs(body),
        ))
    return sites
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_inventory_js_sites.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/quin_scanner/inventory/js_sites.py tests/test_inventory_js_sites.py
git commit -m "feat(inventory): JavaScript/TypeScript agent sites"
```

---

### Task 5: `AgentInstanceScanner` emits evidence

**Files:**
- Modify: `src/quin_scanner/scanners/base.py`
- Modify: `src/quin_scanner/scanners/agent_instance_scanner.py`
- Test: `tests/test_agent_instance_scanner.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_agent_instance_scanner.py`. Add `from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, InstructionsRef` to the imports.

```python
# --- typed evidence for the inventory ---------------------------------------------------------------------------


def _evidence(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    scanner = AgentInstanceScanner()
    findings = scanner.scan(accessor, index)
    return findings, scanner.evidence()


def test_python_evidence_carries_instance_details(tmp_path):
    findings, sites = _evidence(tmp_path, {"app.py": 'a = Agent(name="r", instructions="x", tools=[s])\n'})
    assert [f.match_text for f in findings] == ["r"]
    (site,) = sites
    assert (site.name, site.file_path, site.tool_refs) == ("r", "app.py", ("s",))


def test_test_files_give_evidence_but_no_findings(tmp_path):
    findings, sites = _evidence(tmp_path, {"tests/test_app.py": 'a = Agent(name="r")\n'})
    assert findings == []
    assert [(s.name, s.file_path) for s in sites] == [("r", "tests/test_app.py")]


def test_crew_yaml_entries_are_config_definitions(tmp_path):
    _, sites = _evidence(tmp_path, {"config/agents.yaml": "researcher:\n  role: Senior Researcher\n  goal: g\n"})
    (site,) = sites
    assert (site.role, site.kind, site.name, site.instructions) == (
        "definition", "config_entry", "Senior Researcher", InstructionsRef("config", "researcher"),
    )


def test_adk_root_agent_details(tmp_path):
    source = (
        "name: root\nmodel: gemini-2.0-flash\ninstruction: Help.\n"
        "tools:\n  - name: google_search\nsub_agents:\n  - name: helper\n"
    )
    _, sites = _evidence(tmp_path, {"root_agent.yaml": source})
    helper, root = sorted(sites, key=lambda s: s.name)
    assert (root.model_expr, root.tool_refs, root.instructions) == (
        "gemini-2.0-flash", ("google_search",), InstructionsRef.literal("Help."),
    )
    assert helper.tool_refs is None


def test_unparseable_python_falls_back_to_regex_sites(tmp_path):
    _, sites = _evidence(tmp_path, {"bad.py": 'agent = Agent(name="ok",\nthis is not python (\n'})
    assert [(s.name, s.tool_refs, s.instructions) for s in sites] == [("ok", None, NO_INSTRUCTIONS)]


def test_typescript_evidence(tmp_path):
    _, sites = _evidence(tmp_path, {"a.ts": 'const a = new Agent({ name: "triage", tools: [x] });\n'})
    assert [(s.name, s.tool_refs) for s in sites] == [("triage", ("x",))]


def test_workflow_graph_and_markdown_specs(tmp_path):
    _, sites = _evidence(tmp_path, {"flow.yaml": WORKFLOW, "agents/research.md": "# Research Agent\n**Role:** Researcher\n"})
    assert sorted((s.kind, s.name) for s in sites) == [
        ("config_entry", "Research Agent"),
        ("graph_node", "Programmer Code Review"),
        ("graph_node", "Reviewer"),
    ]
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_agent_instance_scanner.py -q`
Expected: the new tests FAIL with `AttributeError: 'AgentInstanceScanner' object has no attribute 'evidence'`; the existing tests PASS.

- [ ] **Step 3: Add the protocol to `scanners/base.py`**

Add at the end of the file, and add `from typing import Protocol, runtime_checkable` to the imports:

```python
@runtime_checkable
class EvidenceProducer(Protocol):
    """A scanner that also hands typed evidence (AgentSite, ToolSite) to the inventory after scan()."""

    def evidence(self) -> list: ...
```

- [ ] **Step 4: Refactor the Python name pass to take a tree**

In `agent_instance_scanner.py`:

- Add imports:

```python
from quin_scanner.inventory import js_sites, python_sites
from quin_scanner.inventory.evidence import AgentSite, InstructionsRef
```

- Delete `_NAME_KEYWORDS`, `_callee_name` and `_string_constant`, and replace `_python_agent_calls` with a version that takes a parsed tree and reuses the shared helpers:

```python
def _python_agent_calls(tree: ast.Module) -> list[tuple[int, str]]:
    """(line, name) of every named agent construction in a parsed Python module.

    A name is the literal ``name=`` (or ``agent_name=``) keyword of a call to ``...Agent(...)`` / ``GroupChatManager(...)``, or,
    for a class such as ``AssistantAgent`` that is not the bare ``Agent``, its first positional string.
    Text inside a string argument and the keywords of nested calls are not arguments of the agent.
    """
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = python_sites.callee_name(node.func)
        if not callee:
            continue
        lowered = callee.lower()
        if lowered != "groupchatmanager" and not lowered.endswith("agent"):
            continue
        name = python_sites.agent_name(node, callee)
        if name:
            found.append((node.lineno, node.col_offset, name))
    return [(line, name) for line, _, name in sorted(found)]
```

`agent_name` strips the name, which the old code did in `add()` anyway, so findings do not change. Remove the now-unused `import warnings`.

- [ ] **Step 5: Collect sites in `scan()` and `_scan_code()`**

Replace `scan()` with:

```python
    def scan(self, accessor: "RepoAccessor", file_index: "FileIndex") -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        seen: set[str] = set()
        self._sites: list[AgentSite] = []

        for path in file_index.all_files():
            # Test files give the inventory evidence (tagged scope: test) but no findings, as before.
            is_test = _is_test_path(path)
            p = Path(path)
            fname = p.name.lower()
            suffix = p.suffix.lower()

            try:
                if suffix in _CODE_EXTENSIONS:
                    found = self._scan_code(accessor.read_file(path), path, seen)
                elif fname in _AGENT_CONFIG_NAMES:
                    found = self._scan_agent_yaml(accessor.read_file(path), path, seen)
                elif fname in _ADK_ROOT_AGENT_NAMES:
                    found = self._scan_adk_root_agent(accessor.read_file(path), path, seen)
                elif fname == "flow.dag.yaml":
                    found = self._scan_flow_dag(accessor.read_file(path), path, seen)
                elif suffix in _WORKFLOW_YAML_SUFFIXES:
                    found = self._scan_workflow_graph(accessor.read_file(path), path, seen)
                elif suffix == ".md" and self._in_agent_dir(path):
                    found = self._scan_agent_markdown(accessor.read_file(path), path, seen)
                else:
                    continue
            except Exception:
                continue
            if not is_test:
                findings.extend(found)

        return findings

    def evidence(self) -> list[AgentSite]:
        """Typed agent sites from the last scan(), test files included."""
        return list(getattr(self, "_sites", []))
```

In `_scan_code`, replace the block that computes `calls` with:

```python
        tree = python_sites.parse_python(content) if path.lower().endswith(".py") else None
        calls = _python_agent_calls(tree) if tree is not None else None
```

and add these lines immediately before `return findings` at the end of `_scan_code`:

```python
        if tree is not None:
            self._sites.extend(python_sites.agent_sites(tree, path))
        else:
            sites = js_sites.agent_sites(content, path) if Path(path).suffix.lower() in _JS_EXTENSIONS else []
            covered = {(s.line, s.name) for s in sites}
            sites += [
                AgentSite(role="both", kind="constructor", name=f.match_text, file_path=path, line=f.line_number)
                for f in findings
                if (f.line_number, f.match_text) not in covered
            ]
            self._sites.extend(sites)
```

and define next to `_CODE_EXTENSIONS`:

```python
_JS_EXTENSIONS = {".ts", ".js", ".jsx", ".tsx", ".mjs"}
```

- [ ] **Step 6: Collect sites from the config parsers**

Add a helper at module level:

```python
def _literal_tool_refs(value: object) -> tuple[str, ...] | None:
    """Tool names from a YAML ``tools:`` list (strings, or mappings with a ``name``); None when absent."""
    if not isinstance(value, list):
        return None
    names = [item.get("name") if isinstance(item, dict) else item for item in value]
    return tuple(str(n) for n in names if isinstance(n, str) and n)
```

In `_scan_agent_yaml`, dict branch: immediately after `seen.add(key)`, add:

```python
                self._sites.append(AgentSite(
                    role="definition", kind="config_entry", name=str(agent_name), file_path=path, line=None,
                    instructions=InstructionsRef("config", str(agent_key)),
                    tool_refs=_literal_tool_refs(agent_val.get("tools")) if isinstance(agent_val, dict) else None,
                ))
```

List branch: immediately after `seen.add(key)`, add:

```python
                            self._sites.append(AgentSite(
                                role="definition", kind="config_entry", name=str(agent_name), file_path=path,
                                line=None, instructions=InstructionsRef("config", str(agent_name)),
                                tool_refs=_literal_tool_refs(item.get("tools")),
                            ))
```

In `_scan_adk_root_agent`, replace the inner `_add` and its three calls with:

```python
        def _add(item: dict, confidence: float) -> None:
            agent_name = item.get("name")
            if not agent_name or not isinstance(agent_name, str):
                return
            key = f"{path}::{agent_name}"
            if key in seen:
                return
            seen.add(key)
            findings.append(ScanFinding(
                scanner_name=self.name(),
                category="agent_instance",
                file_path=path,
                line_number=0,
                match_text=agent_name,
                capability_tag="multi-agent",
                confidence=confidence,
            ))
            instruction = item.get("instruction")
            model = item.get("model")
            self._sites.append(AgentSite(
                role="definition", kind="config_entry", name=agent_name, file_path=path, line=None,
                instructions=InstructionsRef.literal(instruction) if isinstance(instruction, str) else InstructionsRef(),
                model_expr=model if isinstance(model, str) else None,
                tool_refs=_literal_tool_refs(item.get("tools")),
            ))

        _add(data, 0.90)
        sub_agents = data.get("sub_agents", [])
        if isinstance(sub_agents, list):
            for item in sub_agents:
                if isinstance(item, dict):
                    _add(item, 0.88)
        return findings
```

In `_scan_flow_dag`, immediately after `seen.add(key)`, add:

```python
                        self._sites.append(AgentSite(
                            role="definition", kind="graph_node", name=str(node_name), file_path=path, line=None,
                        ))
```

In `_scan_workflow_graph`, immediately after `seen.add(key)`, add:

```python
            config = node.get("config") if isinstance(node.get("config"), dict) else {}
            role = config.get("role")
            self._sites.append(AgentSite(
                role="definition", kind="graph_node", name=str(node_id), file_path=path, line=None,
                instructions=InstructionsRef.literal(role) if isinstance(role, str) else InstructionsRef(),
            ))
```

In `_scan_agent_markdown`, immediately after `seen.add(key)`, add:

```python
        self._sites.append(AgentSite(
            role="definition", kind="config_entry", name=agent_name, file_path=path, line=None,
            instructions=InstructionsRef("file", path),
        ))
```

- [ ] **Step 7: Run the scanner tests**

Run: `python3 -m pytest tests/test_agent_instance_scanner.py -q`
Expected: PASS, both old and new tests. Existing findings are unchanged.

- [ ] **Step 8: Run the full suite**

Run: `python3 -m pytest tests/ -q`
Expected: PASS. The orchestrator does not read evidence yet.

- [ ] **Step 9: Commit**

```bash
git add src/quin_scanner/scanners/base.py src/quin_scanner/scanners/agent_instance_scanner.py tests/test_agent_instance_scanner.py
git commit -m "feat(inventory): AgentInstanceScanner emits typed agent sites, test files included"
```

---

### Task 6: `ToolDefinitionScanner` emits evidence

**Files:**
- Modify: `src/quin_scanner/scanners/tool_definition_scanner.py`
- Test: `tests/test_tool_definition_scanner.py` (create)

- [ ] **Step 1: Write the failing tests**

`tests/test_tool_definition_scanner.py`:

```python
"""ToolDefinitionScanner: typed tool sites for the inventory (definitions only)."""
from __future__ import annotations

from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.tool_definition_scanner import ToolDefinitionScanner


def _scan(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    scanner = ToolDefinitionScanner()
    findings = scanner.scan(accessor, index)
    return findings, scanner.evidence()


def test_decorated_tools_and_classes_are_tool_sites(tmp_path):
    _, sites = _scan(tmp_path, {"tools.py": "@tool\ndef search():\n    pass\n\nclass Calc(BaseTool):\n    pass\n"})
    assert [(s.name, s.kind, s.line) for s in sites] == [("search", "@tool", 1), ("Calc", "BaseTool", 5)]


def test_tools_list_references_are_findings_but_not_definitions(tmp_path):
    findings, sites = _scan(tmp_path, {"app.py": "a = Agent(name='a', tools=[search, fetch])\n"})
    assert sorted(f.match_text for f in findings) == ["fetch", "search"]
    assert sites == []


def test_test_files_give_tool_sites_but_no_findings(tmp_path):
    findings, sites = _scan(tmp_path, {"tests/test_tools.py": "@tool\ndef fake():\n    pass\n"})
    assert findings == []
    assert [(s.name, s.file_path) for s in sites] == [("fake", "tests/test_tools.py")]


def test_tools_yaml_entries(tmp_path):
    _, sites = _scan(tmp_path, {"tools.yaml": "tools:\n  - name: lookup\n"})
    assert [(s.name, s.kind, s.line) for s in sites] == [("lookup", "config", None)]
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_tool_definition_scanner.py -q`
Expected: FAIL with `AttributeError: ... no attribute 'evidence'`.

- [ ] **Step 3: Implement**

In `tool_definition_scanner.py`, add `from quin_scanner.inventory.evidence import ToolSite`.

Replace `scan()`:

```python
    def scan(self, accessor: "RepoAccessor", file_index: "FileIndex") -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        seen: set[str] = set()
        self._sites: list[ToolSite] = []

        for path in file_index.all_files():
            # Test files give the inventory evidence (tagged scope: test) but no findings, as before.
            is_test = _is_test_path(path)
            p = Path(path)
            fname = p.name.lower()
            suffix = p.suffix.lower()

            try:
                if suffix in _CODE_EXTENSIONS:
                    content = accessor.read_file(path)
                    found = self._scan_code(content, path, seen)
                    if self._in_tool_dir(path):
                        found += self._scan_tool_dir_functions(content, path, seen)
                elif fname in _TOOL_CONFIG_NAMES:
                    found = self._scan_tools_yaml(accessor.read_file(path), path, seen)
                elif fname == "flow.dag.yaml":
                    found = self._scan_flow_dag(accessor.read_file(path), path, seen)
                elif suffix == ".md" and self._in_agent_dir(path):
                    found = self._scan_md_tools_required(accessor.read_file(path), path, seen)
                else:
                    continue
            except Exception:
                continue
            if not is_test:
                findings.extend(found)
            self._sites_from(found)

        return findings

    def _sites_from(self, found: list[ScanFinding]) -> None:
        """Tool definitions among one file's findings; bare names from tools=[...] lists are references, not definitions."""
        for f in found:
            name, _, label = f.match_text.partition(" (")
            if label:
                kind = label.rstrip(")")
                kind = {"tools/": "function", "agent spec": "agent_spec"}.get(kind, kind)
            elif f.line_number == 0:      # tools.yaml and flow.dag.yaml entries
                kind = "config" if Path(f.file_path).name.lower() in _TOOL_CONFIG_NAMES else "graph_node"
            else:
                continue                  # a tools=[...] reference
            self._sites.append(ToolSite(name=name.strip(), kind=kind, file_path=f.file_path,
                                        line=f.line_number or None))

    def evidence(self) -> list[ToolSite]:
        """Typed tool definition sites from the last scan(), test files included, sorted by location."""
        return sorted(getattr(self, "_sites", []), key=lambda s: (s.file_path, s.line or 0, s.name))
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m pytest tests/test_tool_definition_scanner.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full suite and commit**

Run: `python3 -m pytest tests/ -q`
Expected: PASS.

```bash
git add src/quin_scanner/scanners/tool_definition_scanner.py tests/test_tool_definition_scanner.py
git commit -m "feat(inventory): ToolDefinitionScanner emits typed tool definition sites"
```

---

### Task 7: Resolver, part 1: tools

**Files:**
- Create: `src/quin_scanner/inventory/resolver.py`
- Test: `tests/test_inventory_resolver.py` (create)

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_resolver.py`:

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'quin_scanner.inventory.resolver'`.

- [ ] **Step 3: Implement the module skeleton and the tool step**

`src/quin_scanner/inventory/resolver.py`:

```python
"""Turn scanner evidence into the inventory of record: agents with instances, tools, links and flags.

Deterministic: no I/O beyond the scope rules and no LLM. The same sites always give the same output,
sorted by ID, whatever their input order.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from typing import Iterable

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.scope import scope_of
from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    AgentToolRelationship,
    EvidenceRef,
    InstanceTool,
    RiskIndicator,
    ToolUsage,
)
from quin_scanner.risk_taxonomy import get_control_label

_SCOPE_RANK = {"production": 0, "test": 1, "example": 2}


@dataclass
class Inventory:
    agents: list[AgentProfile] = field(default_factory=list)
    tools: list[ToolUsage] = field(default_factory=list)
    relationships: list[AgentToolRelationship] = field(default_factory=list)
    # agent id → "literal" | "file:<path>" | "var:<name>" | "config:<key>" | "none", for the LLM digest only
    instructions: dict[str, str] = field(default_factory=dict)


def resolve(
    agent_sites: Iterable[AgentSite],
    tool_sites: Iterable[ToolSite],
    extra_tools: Iterable[ToolUsage] = (),
) -> Inventory:
    tools = _resolve_tools(tool_sites, extra_tools)
    return Inventory(tools=tools)


def _resolve_tools(tool_sites: Iterable[ToolSite], extra_tools: Iterable[ToolUsage]) -> list[ToolUsage]:
    """One tool per (name, file). A name defined in more than one file is a collision: its IDs carry the path."""
    by_name: dict[str, dict[str, list[ToolSite]]] = defaultdict(dict)
    for site in sorted(tool_sites, key=lambda s: (s.name, s.file_path, s.line or 0)):
        by_name[site.name].setdefault(site.file_path, []).append(site)
    tools: list[ToolUsage] = []
    for name, files in by_name.items():
        collision = len(files) > 1
        for path, sites in files.items():
            tools.append(ToolUsage(
                tool_name=name, tool_type="tool_definition", source_file=path, line_number=sites[0].line,
                id=f"tool:{name}@{path}" if collision else f"tool:{name}", scope=scope_of(path),
            ))
    # Skills and external services: first name wins, except that an external service types a same-named definition.
    known = {t.tool_name.casefold(): t for t in tools}
    for extra in extra_tools:
        existing = known.get(extra.tool_name.casefold())
        if existing is None:
            added = replace(extra, id=f"tool:{extra.tool_name}", scope=scope_of(extra.source_file))
            tools.append(added)
            known[extra.tool_name.casefold()] = added
        elif extra.tool_type == "external_service" and existing.tool_type == "tool_definition":
            existing.tool_type = "external_service"
            existing.service_category = extra.service_category
    return sorted(tools, key=lambda t: t.id)


def fallback(agent_sites: Iterable[AgentSite]) -> Inventory:
    """Used only if resolve() raised: one weak agent per site and no tools, so the report is still produced."""
    raise NotImplementedError  # completed in Task 9
```

- [ ] **Step 4: Run the tool tests**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/quin_scanner/inventory/resolver.py tests/test_inventory_resolver.py
git commit -m "feat(inventory): resolve tool definitions into tools with stable IDs"
```

---

### Task 8: Resolver, part 2: agent grouping, IDs and scope

**Files:**
- Modify: `src/quin_scanner/inventory/resolver.py`
- Test: `tests/test_inventory_resolver.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_inventory_resolver.py`:

```python
# --- agent grouping and IDs ---------------------------------------------------------------------


def test_same_name_and_instructions_are_one_agent_with_instances():
    inv = resolve([
        agent("researcher", "src/a.py", 3, instructions=PROMPT),
        agent("researcher", "src/b.py", 7, instructions=PROMPT),
        agent("researcher", "src/a.py", 9, instructions=PROMPT),
    ], [])
    (a,) = inv.agents
    assert (a.id, a.identity, a.flags, a.name) == ("agent:researcher", "strong", [], "researcher")
    assert [i.id for i in a.instances] == [
        "agent:researcher/src/a.py#1", "agent:researcher/src/a.py#2", "agent:researcher/src/b.py#1",
    ]


def test_same_name_different_instructions_is_a_collision():
    inv = resolve([
        agent("assistant", "src/a.py", instructions=PROMPT),
        agent("assistant", "examples/b.py", instructions=OTHER),
    ], [])
    assert [(a.id, a.flags) for a in inv.agents] == [
        ("agent:assistant@examples/b.py", ["name_collision"]),
        ("agent:assistant@src/a.py", ["name_collision"]),
    ]


def test_collision_ids_in_one_file_get_a_counter():
    inv = resolve([agent("a", "src/x.py", 1, instructions=PROMPT), agent("a", "src/x.py", 2, instructions=OTHER)], [])
    assert [a.id for a in inv.agents] == ["agent:a@src/x.py", "agent:a@src/x.py#2"]


def test_unknown_instructions_join_the_single_same_named_agent():
    inv = resolve([agent("r", "src/a.py", instructions=PROMPT), agent("r", "src/b.py")], [])
    (a,) = inv.agents
    assert len(a.instances) == 2


def test_unknown_instructions_with_two_candidates_are_ambiguous():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT),
        agent("r", "src/b.py", instructions=OTHER),
        agent("r", "src/c.py"),
    ], [])
    flags = {a.source_file: a.flags for a in inv.agents}
    assert flags == {
        "src/a.py": ["name_collision"],
        "src/b.py": ["name_collision"],
        "src/c.py": ["ambiguous_instance", "name_collision"],
    }


def test_sites_without_a_name_are_weak_agents_numbered_per_file():
    inv = resolve([agent(None, "src/a.py", 5), agent(None, "src/a.py", 2), agent(None, "src/b.py", 1)], [])
    assert [(a.id, a.identity, a.name) for a in inv.agents] == [
        ("agent:@src/a.py#1", "weak", ""),
        ("agent:@src/a.py#2", "weak", ""),
        ("agent:@src/b.py#1", "weak", ""),
    ]
    assert inv.agents[0].instances[0].line == 2


def test_config_key_links_a_code_instance_to_its_yaml_definition():
    definition = agent("Senior Researcher", "config/agents.yaml", None, role="definition", kind="config_entry",
                       instructions=InstructionsRef("config", "researcher"), tools=None)
    instance = agent("researcher", "src/crew.py", 12, instructions=InstructionsRef("config", "researcher"),
                     tools=("search",))
    (a,) = resolve([definition, instance], []).agents
    assert (a.id, a.source_file) == ("agent:Senior Researcher", "config/agents.yaml")
    assert [i.file for i in a.instances] == ["src/crew.py"]


def test_a_definition_without_instances_is_its_own_instance():
    (a,) = resolve([agent("Writer", "src/w.py", 1, role="definition", kind="subclass", tools=None)], []).agents
    assert [i.id for i in a.instances] == ["agent:Writer/src/w.py#1"]


@pytest.mark.parametrize(
    ("paths", "scope"),
    [
        (["tests/test_a.py", "src/b.py"], "production"),
        (["tests/test_a.py", "examples/b.py"], "test"),
        (["examples/b.py"], "example"),
    ],
)
def test_agent_scope_is_production_if_any_site_is(paths, scope):
    (a,) = resolve([agent("r", p, instructions=PROMPT) for p in paths], []).agents
    assert a.scope == scope


def test_ids_do_not_depend_on_line_numbers():
    before = resolve([agent("r", "src/a.py", 3, instructions=PROMPT), agent(None, "src/a.py", 10)], [])
    after = resolve([agent("r", "src/a.py", 40, instructions=PROMPT), agent(None, "src/a.py", 80)], [])
    assert [a.id for a in before.agents] == [a.id for a in after.agents]
    assert [i.id for a in before.agents for i in a.instances] == [i.id for a in after.agents for i in a.instances]


def test_output_is_sorted_and_independent_of_input_order():
    sites = [agent("b", "src/b.py", instructions=PROMPT), agent("a", "src/a.py", instructions=PROMPT), agent(None, "src/c.py")]
    forward = resolve(sites, [])
    backward = resolve(list(reversed(sites)), [])
    assert [a.to_dict() for a in forward.agents] == [a.to_dict() for a in backward.agents]
    assert [a.id for a in forward.agents] == ["agent:@src/c.py#1", "agent:a", "agent:b"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q`
Expected: the new tests FAIL (`inv.agents` is empty).

- [ ] **Step 3: Implement grouping, IDs and agent building**

In `resolver.py`, add below `Inventory`:

```python
@dataclass
class _Group:
    name: str | None
    instructions: InstructionsRef
    sites: list[AgentSite] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


def _site_key(site: AgentSite) -> tuple:
    return (site.file_path, site.line or 0, site.name or "", site.kind)
```

Replace `resolve` with:

```python
def resolve(
    agent_sites: Iterable[AgentSite],
    tool_sites: Iterable[ToolSite],
    extra_tools: Iterable[ToolUsage] = (),
) -> Inventory:
    tools = _resolve_tools(tool_sites, extra_tools)
    tool_index: dict[str, list[ToolUsage]] = defaultdict(list)
    for t in tools:
        tool_index[t.tool_name.casefold()].append(t)
    groups = _group_agents(agent_sites)
    inventory = Inventory(tools=tools)
    for group, agent_id in sorted(zip(groups, _agent_ids(groups)), key=lambda pair: pair[1]):
        agent, relationships = _build_agent(group, agent_id, tool_index)
        inventory.agents.append(agent)
        inventory.relationships.extend(relationships)
        inventory.instructions[agent_id] = _describe(group.instructions)
    inventory.relationships.sort(key=lambda e: (e.source_file, e.line_number or 0, e.agent_name, e.tool_name))
    return inventory
```

Add:

```python
def _group_agents(agent_sites: Iterable[AgentSite]) -> list[_Group]:
    """Same name and same instructions fingerprint → one agent; see spec §6 step 3."""
    sites = sorted(agent_sites, key=_site_key)
    # CrewAI: code that loads agents_config['key'] is an instance of the agents.yaml entry with that key.
    config_names = {
        s.instructions.value: s.name
        for s in sites
        if s.kind == "config_entry" and s.instructions.kind == "config" and s.name
    }
    named: list[AgentSite] = []
    unnamed: list[AgentSite] = []
    for site in sites:
        if site.kind != "config_entry" and site.instructions.kind == "config" and site.instructions.value in config_names:
            site = replace(site, name=config_names[site.instructions.value])
        (named if site.name else unnamed).append(site)

    groups: dict[tuple[str, InstructionsRef], _Group] = {}
    pending: list[AgentSite] = []
    for site in named:
        if site.instructions.is_known:
            key = (site.name, site.instructions)
            groups.setdefault(key, _Group(site.name, site.instructions)).sites.append(site)
        else:
            pending.append(site)
    known_by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups.values():
        known_by_name[group.name].append(group)
    for site in pending:
        candidates = known_by_name.get(site.name, [])
        if len(candidates) == 1:
            candidates[0].sites.append(site)
            continue
        group = groups.setdefault((site.name, NO_INSTRUCTIONS), _Group(site.name, NO_INSTRUCTIONS))
        group.sites.append(site)
        if candidates:
            group.flags.add("ambiguous_instance")

    by_name: dict[str, list[_Group]] = defaultdict(list)
    for group in groups.values():
        by_name[group.name].append(group)
    for same_name in by_name.values():
        if len(same_name) > 1:
            for group in same_name:
                group.flags.add("name_collision")

    weak = [_Group(None, site.instructions, [site]) for site in unnamed]
    return list(groups.values()) + weak


def _definition(group: _Group) -> AgentSite:
    return next((s for s in group.sites if s.role in ("definition", "both")), group.sites[0])


def _agent_ids(groups: list[_Group]) -> list[str]:
    ids: list[str] = []
    weak_per_file: dict[str, int] = defaultdict(int)
    for group in groups:
        if group.name is None:
            path = group.sites[0].file_path
            weak_per_file[path] += 1
            ids.append(f"agent:@{path}#{weak_per_file[path]}")
        elif "name_collision" in group.flags:
            ids.append(f"agent:{group.name}@{_definition(group).file_path}")
        else:
            ids.append(f"agent:{group.name}")
    seen: dict[str, int] = defaultdict(int)
    unique: list[str] = []
    for agent_id in ids:
        seen[agent_id] += 1
        unique.append(agent_id if seen[agent_id] == 1 else f"{agent_id}#{seen[agent_id]}")
    return unique


def _describe(instructions: InstructionsRef) -> str:
    if instructions.kind in ("literal", "none"):
        return instructions.kind
    return f"{instructions.kind}:{instructions.value}"


def _build_agent(
    group: _Group, agent_id: str, tool_index: dict[str, list[ToolUsage]],
) -> tuple[AgentProfile, list[AgentToolRelationship]]:
    instance_sites = [s for s in group.sites if s.role in ("instance", "both")] or list(group.sites)
    per_file: dict[str, int] = defaultdict(int)
    instances: list[AgentInstance] = []
    for site in instance_sites:
        per_file[site.file_path] += 1
        instances.append(AgentInstance(
            id=f"{agent_id}/{site.file_path}#{per_file[site.file_path]}",
            file=site.file_path,
            line=site.line,
            scope=scope_of(site.file_path),
            multiplicity="many" if site.in_loop else "one",
            model=site.model_expr,
        ))
    scopes = {scope_of(s.file_path) for s in group.sites}
    agent = AgentProfile(
        name=group.name or "",
        agent_type="unknown",
        goal="",
        source_file=_definition(group).file_path,
        id=agent_id,
        identity="strong" if group.name else "weak",
        scope=min(scopes, key=_SCOPE_RANK.__getitem__),
        flags=sorted(group.flags),
        provenance={"name": "static", "tools": "static"},
        instances=instances,
    )
    return agent, []
```

- [ ] **Step 4: Run the resolver tests**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/quin_scanner/inventory/resolver.py tests/test_inventory_resolver.py
git commit -m "feat(inventory): group agent sites into agents and instances with stable IDs"
```

---

### Task 9: Resolver, part 3: tool links, relationships, divergence, fallback

**Files:**
- Modify: `src/quin_scanner/inventory/resolver.py`
- Modify: `src/quin_scanner/inventory/__init__.py`
- Test: `tests/test_inventory_resolver.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_inventory_resolver.py`:

```python
# --- instance tools, relationships and divergence ---------------------------------------------


def test_instance_tools_link_to_a_same_file_definition_first():
    inv = resolve([agent("r", "src/a.py", 5, tools=("search", "ghost"))],
                  [tool("search", "src/a.py", 2), tool("search", "src/b.py", 1)])
    (instance,) = inv.agents[0].instances
    assert [t.to_dict() for t in instance.tools] == [
        {"name": "search", "tool_id": "tool:search@src/a.py", "resolved": True},
        {"name": "ghost", "tool_id": None, "resolved": False},
    ]


def test_instance_tools_link_to_a_repo_unique_name():
    inv = resolve([agent("r", "src/a.py", tools=("lookup",))], [tool("lookup", "src/tools.py", 2)])
    assert inv.agents[0].instances[0].tools[0].tool_id == "tool:lookup"


def test_a_colliding_tool_name_from_other_files_stays_unresolved():
    inv = resolve([agent("r", "src/a.py", tools=("search",))], [tool("search", "src/b.py"), tool("search", "src/c.py")])
    assert inv.agents[0].instances[0].tools[0].resolved is False


def test_relationships_are_built_from_instances():
    inv = resolve([agent("researcher", "agent.py", 5, tools=("lookup_customer",))],
                  [tool("lookup_customer", "agent.py", 2)])
    assert [r.to_dict() for r in inv.relationships] == [{
        "agent_name": "researcher", "tool_name": "lookup_customer", "source_file": "agent.py", "line_number": 5,
        "tool_source_file": "agent.py", "tool_line_number": 2, "evidence": "explicit_tools_argument",
        "agent_id": "agent:researcher", "instance_id": "agent:researcher/agent.py#1",
        "tool_id": "tool:lookup_customer",
    }]
    assert inv.agents[0].tools == ["lookup_customer"]


def test_production_tool_divergence_is_a_t006_risk_signal():
    inv = resolve([
        agent("r", "src/a.py", 1, instructions=PROMPT, tools=("search",)),
        agent("r", "src/admin.py", 1, instructions=PROMPT, tools=("search", "shell_exec")),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["tool_divergence"]
    (signal,) = a.risk_signals
    assert (signal.threat_id, signal.severity, signal.recommended_controls) == (
        "T006", "medium", ["C003: Access Control & Least Privilege"],
    )
    assert "shell_exec" in signal.signal
    assert [(r.file_path, r.line_number) for r in signal.evidence_refs] == [("src/a.py", 1), ("src/admin.py", 1)]


def test_divergence_only_in_test_code_is_a_flag_without_a_signal():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, tools=("search",)),
        agent("r", "tests/test_a.py", instructions=PROMPT, tools=("search", "fake")),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["tool_divergence"]
    assert a.risk_signals == []


def test_unknown_tool_lists_do_not_count_as_divergence():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, tools=("search",)),
        agent("r", "src/b.py", instructions=PROMPT, tools=None),
    ], [])
    assert inv.agents[0].flags == []


def test_model_divergence_is_informational_and_loops_are_marked():
    inv = resolve([
        agent("r", "src/a.py", instructions=PROMPT, model="gpt-4o", in_loop=True),
        agent("r", "src/b.py", instructions=PROMPT, model="env:MODEL"),
    ], [])
    (a,) = inv.agents
    assert a.flags == ["model_divergence"]
    assert a.risk_signals == []
    assert [i.multiplicity for i in a.instances] == ["many", "one"]


def test_provenance_and_digest_instructions():
    inv = resolve([agent("r", instructions=InstructionsRef("file", "prompts/r.md"))], [])
    assert inv.agents[0].provenance == {"name": "static", "tools": "static"}
    assert inv.instructions == {"agent:r": "file:prompts/r.md"}


def test_fallback_gives_one_weak_agent_per_site():
    inv = fallback([agent("r", "src/a.py", 3), agent(None, "src/a.py", 1)])
    assert [(a.id, a.name, a.identity) for a in inv.agents] == [
        ("agent:@src/a.py#1", "", "weak"),
        ("agent:@src/a.py#2", "r", "weak"),
    ]
    assert inv.tools == [] and inv.relationships == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q`
Expected: the new tests FAIL (instances have no tools; `fallback` raises `NotImplementedError`).

- [ ] **Step 3: Implement tool links, relationships and divergence**

In `resolver.py`, replace `_build_agent` with:

```python
def _link_tool(ref: str, path: str, tool_index: dict[str, list[ToolUsage]]) -> ToolUsage | None:
    """A tool defined in the same file, else a repo-unique name, else None (unresolved)."""
    candidates = tool_index.get(ref.casefold(), [])
    same_file = [t for t in candidates if t.source_file == path]
    if same_file:
        return same_file[0]
    return candidates[0] if len(candidates) == 1 else None


def _build_agent(
    group: _Group, agent_id: str, tool_index: dict[str, list[ToolUsage]],
) -> tuple[AgentProfile, list[AgentToolRelationship]]:
    instance_sites = [s for s in group.sites if s.role in ("instance", "both")] or list(group.sites)
    per_file: dict[str, int] = defaultdict(int)
    pairs: list[tuple[AgentInstance, AgentSite]] = []
    relationships: list[AgentToolRelationship] = []
    for site in instance_sites:
        per_file[site.file_path] += 1
        instance_id = f"{agent_id}/{site.file_path}#{per_file[site.file_path]}"
        tools: list[InstanceTool] = []
        for ref in site.tool_refs or ():
            linked = _link_tool(ref, site.file_path, tool_index)
            tools.append(InstanceTool(name=ref, tool_id=linked.id if linked else None, resolved=linked is not None))
            relationships.append(AgentToolRelationship(
                agent_name=group.name or "",
                tool_name=ref,
                source_file=site.file_path,
                line_number=site.line,
                tool_source_file=linked.source_file if linked else "",
                tool_line_number=linked.line_number if linked else None,
                agent_id=agent_id,
                instance_id=instance_id,
                tool_id=linked.id if linked else None,
            ))
        instance = AgentInstance(
            id=instance_id,
            file=site.file_path,
            line=site.line,
            scope=scope_of(site.file_path),
            multiplicity="many" if site.in_loop else "one",
            model=site.model_expr,
            tools=tools,
        )
        pairs.append((instance, site))
    flags = set(group.flags)
    risk_signals = _divergence(group.name or agent_id, pairs, flags)
    scopes = {scope_of(s.file_path) for s in group.sites}
    instances = [instance for instance, _ in pairs]
    agent = AgentProfile(
        name=group.name or "",
        agent_type="unknown",
        goal="",
        risk_signals=risk_signals,
        tools=sorted({t.name for instance in instances for t in instance.tools}),
        source_file=_definition(group).file_path,
        id=agent_id,
        identity="strong" if group.name else "weak",
        scope=min(scopes, key=_SCOPE_RANK.__getitem__),
        flags=sorted(flags),
        provenance={"name": "static", "tools": "static"},
        instances=instances,
    )
    return agent, relationships


def _divergence(
    label: str, pairs: list[tuple[AgentInstance, AgentSite]], flags: set[str],
) -> list[RiskIndicator]:
    """Flags for instances that differ; a T006 signal when production instances are given different tools."""
    known = [(instance, frozenset(site.tool_refs)) for instance, site in pairs if site.tool_refs is not None]
    if len({tools for _, tools in known}) > 1:
        flags.add("tool_divergence")
    if len({site.model_expr for _, site in pairs if site.model_expr}) > 1:
        flags.add("model_divergence")
    production = [(instance, tools) for instance, tools in known if instance.scope == "production"]
    tool_sets = {tools for _, tools in production}
    if len(tool_sets) < 2:
        return []
    differing = sorted(frozenset.union(*tool_sets) - frozenset.intersection(*tool_sets))
    return [RiskIndicator(
        signal=f"Instances of agent '{label}' are given different tools: {', '.join(differing)}",
        recommended_controls=[get_control_label("C003")],
        threat_id="T006",
        severity="medium",
        evidence_refs=[
            EvidenceRef(file_path=instance.file, line_number=instance.line, scanner="AgentInstanceScanner")
            for instance, _ in production
        ],
    )]
```

Replace `fallback` with:

```python
def fallback(agent_sites: Iterable[AgentSite]) -> Inventory:
    """Used only if resolve() raised: one weak agent per site and no tools, so the report is still produced."""
    inventory = Inventory()
    per_file: dict[str, int] = defaultdict(int)
    for site in sorted(agent_sites, key=_site_key):
        per_file[site.file_path] += 1
        inventory.agents.append(AgentProfile(
            name=site.name or "", agent_type="unknown", goal="", source_file=site.file_path,
            id=f"agent:@{site.file_path}#{per_file[site.file_path]}", identity="weak",
            scope=scope_of(site.file_path), provenance={"name": "static"},
        ))
    return inventory
```

- [ ] **Step 4: Export the package API**

Replace `src/quin_scanner/inventory/__init__.py` with:

```python
"""The inventory of record: typed scanner evidence resolved into agents, instances and tools."""
from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef, ToolSite
from quin_scanner.inventory.resolver import Inventory
from quin_scanner.inventory.resolver import fallback as fallback_inventory
from quin_scanner.inventory.resolver import resolve as resolve_inventory

__all__ = [
    "NO_INSTRUCTIONS",
    "AgentSite",
    "InstructionsRef",
    "Inventory",
    "ToolSite",
    "fallback_inventory",
    "resolve_inventory",
]
```

- [ ] **Step 5: Run the resolver tests and the full suite**

Run: `python3 -m pytest tests/test_inventory_resolver.py -q && python3 -m pytest tests/ -q`
Expected: PASS. If importing `quin_scanner.inventory` from the scanners causes a circular import, check that `quin_scanner/models.py` and `quin_scanner/risk_taxonomy.py` do not import any scanner. They do not on `main` today.

- [ ] **Step 6: Commit**

```bash
git add src/quin_scanner/inventory tests/test_inventory_resolver.py
git commit -m "feat(inventory): instance tool links, relationships, divergence flags and the T006 signal"
```

---

### Task 10: The orchestrator uses the inventory (static path)

**Files:**
- Modify: `src/quin_scanner/orchestrator.py`
- Delete: `src/quin_scanner/agent_tool_relationships.py`
- Modify: `tests/test_agent_tool_relationships.py`
- Modify: `tests/test_orchestrator_helpers.py`
- Test: `tests/test_inventory_orchestrator.py` (create)

- [ ] **Step 1: Write the failing tests**

`tests/test_inventory_orchestrator.py`:

```python
"""End to end: the report's agents, tools and relationships come from the inventory."""
from __future__ import annotations

from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor


def _scan(tmp_path, files: dict[str, str], **config):
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    settings = {"enabled_scanners": ["agent_instance", "tool_definition"], "no_llm": True, "vuln_check_enabled": False}
    settings.update(config)
    return ScanOrchestrator().run(LocalRepoAccessor(tmp_path), ScannerConfig(**settings), verbose=False)


def test_static_scan_reports_agents_with_instances(tmp_path):
    report = _scan(tmp_path, {
        "src/a.py": "from fw import Agent, tool\n@tool\ndef search():\n    pass\n"
                    "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/admin.py": "from fw import Agent\nfrom ops import shell_exec\n"
                        "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
        "tests/test_a.py": "r = Agent(name='researcher', instructions='Find.', tools=[])\n",
    })
    (agent,) = report.agents
    assert (agent.id, agent.scope, agent.flags) == ("agent:researcher", "production", ["tool_divergence"])
    assert [i.file for i in agent.instances] == ["src/a.py", "src/admin.py", "tests/test_a.py"]
    assert [s.threat_id for s in agent.risk_signals] == ["T006"]
    assert [t.id for t in report.tool_usages] == ["tool:search"]
    assert report.llm_inferred_agents == [] and report.llm_inferred_tools == []


def test_no_cap_on_agents(tmp_path):
    source = "".join(f"a{i} = Agent(name='agent{i}')\n" for i in range(60))
    report = _scan(tmp_path, {"src/many.py": source})
    assert len(report.agents) == 60


def test_an_inventory_error_does_not_lose_the_report(tmp_path, monkeypatch):
    import quin_scanner.orchestrator as orchestrator

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(orchestrator, "resolve_inventory", broken)
    report = _scan(tmp_path, {"src/a.py": "r = Agent(name='researcher')\n"})
    assert [(a.id, a.name) for a in report.agents] == [("agent:@src/a.py#1", "researcher")]
    assert report.metadata["inventory_error"] == "RuntimeError: boom"
```

In `tests/test_agent_tool_relationships.py`, add the three new keys to each expected dict:

- test 1 and test 2: `"agent_id": "agent:researcher", "instance_id": "agent:researcher/agent.py#1", "tool_id": "tool:lookup_customer"`
- test 3 (JS): `"agent_id": "agent:researcher", "instance_id": "agent:researcher/agent.ts#1", "tool_id": None`

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest tests/test_inventory_orchestrator.py tests/test_agent_tool_relationships.py -q`
Expected: FAIL (agents have no `id`; relationships lack the new keys; 60 agents are capped at 50).

- [ ] **Step 3: Wire the inventory into `orchestrator.py`**

1. **Imports.**
   - Remove `from quin_scanner.agent_tool_relationships import discover_agent_tool_relationships`.
   - Change `from quin_scanner.scanners.base import BaseScanner` to `from quin_scanner.scanners.base import BaseScanner, EvidenceProducer`.
   - Add `LLMInferredItem` and `ToolUsage` to the `from quin_scanner.models import (...)` list.
   - Add:

```python
from quin_scanner.inventory import AgentSite, Inventory, ToolSite, fallback_inventory, resolve_inventory
```

2. **Helpers.** Add these module-level helpers next to `_extract_tool_services`:

```python
def _skill_tool_usages(skill_scanner: SkillScanner | None) -> list[ToolUsage]:
    """Discovered Agent Skills as tool usages (tool_type="skill"), one per name."""
    if skill_scanner is None:
        return []
    from quin_scanner.scanners.skills.discovery import is_pseudo_record
    usages: list[ToolUsage] = []
    seen: set[str] = set()
    for assessment in skill_scanner.assessments:
        record = assessment.record
        if is_pseudo_record(record) or record.name.lower() in seen:
            continue
        seen.add(record.name.lower())
        usages.append(ToolUsage(tool_name=record.name, tool_type="skill", source_file=record.skill_md_path,
                                line_number=None))
    return usages


def _build_inventory(
    scanners: list[BaseScanner], skill_scanner: SkillScanner | None, tool_services: list[ToolUsage],
) -> tuple[Inventory, str | None]:
    """Resolve the scanners' typed evidence into the inventory; on an internal error, weak agents and no tools."""
    agent_sites: list[AgentSite] = []
    tool_sites: list[ToolSite] = []
    for scanner in scanners:
        if isinstance(scanner, EvidenceProducer):
            for item in scanner.evidence():
                if isinstance(item, AgentSite):
                    agent_sites.append(item)
                elif isinstance(item, ToolSite):
                    tool_sites.append(item)
    extras = _skill_tool_usages(skill_scanner) + list(tool_services)
    try:
        return resolve_inventory(agent_sites, tool_sites, extras), None
    except Exception as exc:  # noqa: BLE001 - a resolver bug costs detail, never the report
        _log(f"inventory resolution failed: {exc}")
        return fallback_inventory(agent_sites), f"{type(exc).__name__}: {exc}"
```

3. **Remove the old relationship pass.** Delete the `agent_tool_relationships = discover_agent_tool_relationships(...)` statement (3 lines, after `inventory = [finding.to_dict() for finding in all_findings]`).

4. **Build the inventory.** Directly after `tool_services = _extract_tool_services(all_findings)`, add:

```python
        # 4b. The inventory of record: agents with instances, tools and agent-tool links from static evidence only.
        agent_inventory, inventory_error = _build_inventory(scanners, skill_scanner, tool_services)
```

The name `inventory` is already taken by the raw-findings list, so the inventory object is `agent_inventory`.

5. **Record a resolver failure.** After the `if config.no_llm: metadata["analysis"] = "static-only"` lines, add:

```python
        if inventory_error:
            metadata["inventory_error"] = inventory_error
```

6. **Replace post-processing Rules 2 to 4.** Replace everything from the line `# Rule 2: agents — fall back to AgentInstanceScanner findings when empty` down to and including `pp_tool_usages = _deduped_tools` (the end of Rule 4) with:

```python
        # Rule 2: the inventory of record. Agents (with instances), tools and agent-tool links come from static
        # evidence only (inventory/resolver.py); no caps. The LLM may enrich them by ID; it never adds, renames
        # or removes items (see _apply_enrichment).
        pp_agents = agent_inventory.agents
        pp_tool_usages = agent_inventory.tools
        _classify_tool_usages(pp_tool_usages, mcp_servers)
        llm_inferred_agents: list[LLMInferredItem] = []
        llm_inferred_tools: list[LLMInferredItem] = []
```

7. **Stop validating static signals.** In the block after `# ── End post-processing`, delete:

```python
        for _a in pp_agents:
            _validate_evidence_refs(getattr(_a, "risk_signals", []), _scanned_paths)
```

Static T006 signals cite instance sites, which can be in files with no finding. LLM signals are validated before they are merged (Task 11). Keep the `_scanned_paths = ...` line and `if synthesis: _validate_evidence_refs(synthesis.risk_signals, _scanned_paths)`, but **move the `_scanned_paths` line up** so it sits directly above the new Rule 2 block (Task 11 needs it there).

8. **ScanReport.** In the `return ScanReport(...)` call, set `agent_tool_relationships=agent_inventory.relationships`, and add `llm_inferred_agents=llm_inferred_agents, llm_inferred_tools=llm_inferred_tools`.

9. **Delete the LLM clean-up helpers.** Delete `_MODEL_NAME_PREFIXES`, `_looks_like_model_name` and `_filter_hallucinated_tools`. They only cleaned LLM agent and tool lists, which no longer exist. In `tests/test_orchestrator_helpers.py`, remove `_filter_hallucinated_tools` and `_looks_like_model_name` from the imports and delete `class TestFilterHallucinatedTools` and `class TestLooksLikeModelName`.

The synthesis call still passes `agent_instances`, `tool_definitions` and `external_services`, and still reads `synthesis.agents` in its verbose log. Leave both alone in this task; Task 11 replaces them.

- [ ] **Step 4: Delete the old module**

```bash
git rm src/quin_scanner/agent_tool_relationships.py
```

- [ ] **Step 5: Run the targeted tests**

Run: `python3 -m pytest tests/test_inventory_orchestrator.py tests/test_agent_tool_relationships.py tests/test_orchestrator_helpers.py -q`
Expected: PASS.

- [ ] **Step 6: Run the full suite and lint**

Run: `python3 -m pytest tests/ -q && ruff check src/ --select F,E4,E7,E9`
Expected: PASS, and no unused imports reported (`re` is still used in the orchestrator; if ruff flags anything from the deleted rules, remove that import).

The corpus check `tests/test_corpus_runner.py` tests the runner, not the snapshots; snapshot diffs are reviewed in Task 14. If a test that runs a full scan asserts agent names or counts (for example in `test_skill_orchestrator.py` or `test_portable_paths.py`), check whether the new behaviour is right (test files and `examples/` are now included and tagged; no caps; `tools=[...]` references are no longer standalone tool usages). If it is, update the expectation and say why in the commit message. If it is not, fix the code.

- [ ] **Step 7: Commit**

```bash
git add -A src/quin_scanner tests
git commit -m "feat(inventory): report agents, tools and relationships from the inventory, without caps

Static evidence is the inventory of record. Removes the 50-agent/100-tool
fallback caps, the LLM-output clean-up rules and agent_tool_relationships.py,
whose AST pass now lives in AgentInstanceScanner."
```

---

### Task 11: The LLM enriches by ID

**Files:**
- Modify: `src/quin_scanner/models.py` (`SynthesisResult`, new `AgentEnrichment`)
- Modify: `src/quin_scanner/llm/synthesis_agent.py`
- Modify: `src/quin_scanner/orchestrator.py`
- Modify: `tests/test_llm_parsing.py`
- Test: `tests/test_inventory_orchestrator.py` (append)

- [ ] **Step 1: Write the failing parser tests**

In `tests/test_llm_parsing.py`, inside `class TestParseSynthesisResponse`:

- Replace `test_valid_full_response` with:

```python
    def test_valid_full_response(self):
        data = {
            "is_ai_application": True,
            "framework": "LangChain",
            "summary": "An AI app using LangChain.",
            "enrichment": {
                "agent:researcher": {
                    "agent_type": "worker",
                    "goal": "Research topics",
                    "capabilities": ["web-search"],
                    "risk_signals": [{"signal": "Has internet access", "recommended_controls": ["C001: Control"]}],
                }
            },
            "tool_enrichment": {"tool:google_search": {"service_category": "web_search"}},
            "suggested_agents": [{"name": "planner", "evidence": "built by make_planner()", "file": "agents.py"}],
            "suggested_tools": [{"name": "browse", "evidence": "registered at runtime", "file": "tools.py"}],
            "risk_signals": [{"signal": "No observability", "recommended_controls": ["C005: Monitoring"]}],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert result.is_ai_application is True
        assert result.framework == "LangChain"
        enrichment = result.enrichment["agent:researcher"]
        assert (enrichment.agent_type, enrichment.goal, enrichment.capabilities) == ("worker", "Research topics", ["web-search"])
        assert [s.signal for s in enrichment.risk_signals] == ["Has internet access"]
        assert result.tool_enrichment == {"tool:google_search": "web_search"}
        assert [(i.name, i.file) for i in result.suggested_agents] == [("planner", "agents.py")]
        assert [i.name for i in result.suggested_tools] == ["browse"]
        assert len(result.risk_signals) == 1
```

- In `test_invalid_json_returns_fallback`, replace `assert result.agents == []` with `assert result.enrichment == {}`.
- Replace `test_invalid_tool_type_defaults` with:

```python
    def test_malformed_enrichment_is_ignored(self):
        data = {
            "is_ai_application": True, "framework": "unknown", "summary": "",
            "enrichment": {"agent:a": "not an object", "agent:b": {"agent_type": "boss", "capabilities": ["x", 3]}},
            "tool_enrichment": ["not", "a", "dict"],
            "suggested_agents": [{"name": ""}, "x", {"name": "ok"}],
        }
        result = _parse_synthesis_response(json.dumps(data))
        assert list(result.enrichment) == ["agent:b"]
        assert result.enrichment["agent:b"].agent_type == "unknown"
        assert result.enrichment["agent:b"].capabilities == ["x"]
        assert result.tool_enrichment == {}
        assert [i.name for i in result.suggested_agents] == ["ok"]

    def test_old_style_agents_and_tool_usages_are_ignored(self):
        data = {"is_ai_application": True, "framework": "x", "summary": "",
                "agents": [{"name": "invented"}], "tool_usages": [{"tool_name": "gpt-4o"}]}
        result = _parse_synthesis_response(json.dumps(data))
        assert result.enrichment == {}
        assert result.suggested_agents == []
```

Add this module-level test at the end of the file, and add `_build_evidence_block` to the `synthesis_agent` import:

```python
def test_evidence_block_lists_the_inventory_by_id():
    block = _build_evidence_block(
        [], [], [],
        agent_inventory=[{"id": "agent:r", "name": "r", "scope": "production", "instances": 2,
                          "instructions": "literal", "tools": ["search"], "file": "a.py"}],
        tool_inventory=[{"id": "tool:search", "name": "search", "type": "tool_definition", "category": "",
                         "file": "t.py", "line": 3}],
    )
    assert 'id=agent:r name="r" scope=production instances=2 instructions=literal tools=[search] file=a.py' in block
    assert 'id=tool:search name="search" type=tool_definition at t.py:3' in block
```

- [ ] **Step 2: Write the failing end-to-end test**

Append to `tests/test_inventory_orchestrator.py`, and add `import json` at the top:

```python
def test_the_llm_enriches_by_id_and_cannot_change_the_inventory(tmp_path, monkeypatch):
    prompts: list[str] = []
    synthesis = {
        "is_ai_application": True, "framework": "x", "summary": "s",
        "enrichment": {
            "agent:researcher": {"agent_type": "worker", "goal": "Finds facts", "capabilities": ["search"]},
            "agent:ghost": {"goal": "invented"},
        },
        "tool_enrichment": {"tool:search": {"service_category": "web_search"}},
        "suggested_agents": [{"name": "planner", "evidence": "factory", "file": "src/a.py"}],
        "agents": [{"name": "invented"}],
    }

    class Stub:
        def generate(self, prompt):
            prompts.append(prompt)
            if "AGENT INVENTORY" in prompt:
                return json.dumps(synthesis)
            return '{"system_types": ["agentic_ai"], "relevant_threats": []}'

    monkeypatch.setattr(ScannerConfig, "provider_factory", lambda self: Stub())
    report = _scan(
        tmp_path,
        {"src/a.py": "@tool\ndef search():\n    pass\nr = Agent(name='researcher', tools=[search])\n"},
        no_llm=False, llm_provider="openai", llm_api_key="x",
    )
    (agent,) = report.agents
    assert (agent.id, agent.goal, agent.agent_type, agent.capabilities) == (
        "agent:researcher", "Finds facts", "worker", ["search"],
    )
    assert agent.provenance == {
        "name": "static", "tools": "static", "agent_type": "llm", "goal": "llm", "capabilities": "llm",
    }
    assert report.tool_usages[0].service_category == "web_search"
    assert report.metadata["llm_unknown_ids"] == 1
    assert [i.name for i in report.llm_inferred_agents] == ["planner"]
    assert "id=agent:researcher" in next(p for p in prompts if "AGENT INVENTORY" in p)
```

- [ ] **Step 3: Run to verify they fail**

Run: `python3 -m pytest tests/test_llm_parsing.py tests/test_inventory_orchestrator.py -q`
Expected: FAIL (`SynthesisResult` has no `enrichment`; `_build_evidence_block` has no `agent_inventory`).

- [ ] **Step 4: Change `SynthesisResult` in `models.py`**

Replace `class SynthesisResult` with the following. `LLMInferredItem` (Task 2) is defined above it, and `AgentEnrichment` goes directly above it.

```python
@dataclass
class AgentEnrichment:
    """What the LLM may add to a verified agent, merged by its ID."""
    agent_type: str = "unknown"
    goal: str = ""
    capabilities: list[str] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)


@dataclass
class SynthesisResult:
    """Internal result from SynthesisAgent — not serialised directly."""
    is_ai_application: bool
    framework: str
    summary: str
    enrichment: dict[str, AgentEnrichment] = field(default_factory=dict)    # agent id → fields
    tool_enrichment: dict[str, str] = field(default_factory=dict)           # tool id → service_category
    suggested_agents: list[LLMInferredItem] = field(default_factory=list)
    suggested_tools: list[LLMInferredItem] = field(default_factory=list)
    risk_signals: list[RiskIndicator] = field(default_factory=list)  # repo-level risks
    confidence_adjustment: float = 0.0   # -0.1 to +0.1, applied to static confidence
```

- [ ] **Step 5: Change the synthesis prompt**

In `synthesis_agent.py`, update the imports: replace `AgentProfile` and `ToolUsage` with `AgentEnrichment` and `LLMInferredItem` in the `quin_scanner.models` import (keep the others).

In `_SYSTEM_PROMPT`, replace the JSON block from the line `  "agents": [` down to the closing `  ]` of `"tool_usages"` (the last lines before the final `}`) with:

```text
  "enrichment": {
    "<agent id exactly as listed in AGENT INVENTORY>": {
      "agent_type": "<supervisor|utility|worker|unknown>",
      "goal": "<one sentence>",
      "capabilities": ["<capability>"],
      "risk_signals": [
        {
          "signal": "<Key Risk Indicator text from the THREAT REFERENCE>",
          "threat_id": "<T0NN — the threat this KRI belongs to>",
          "recommended_controls": ["<control ID: control name>"],
          "evidence_refs": [
            {"file_path": "<scanner-found path>", "line_number": <int or null>, "scanner": "<scanner name>"}
          ]
        }
      ]
    }
  },
  "tool_enrichment": {
    "<tool id exactly as listed in TOOL INVENTORY>": {"service_category": "<category from the list below>"}
  },
  "suggested_agents": [
    {"name": "<agent name>", "evidence": "<why you believe this is an agent>", "file": "<scanner-found path>"}
  ],
  "suggested_tools": [
    {"name": "<tool name>", "evidence": "<why you believe this is a tool>", "file": "<scanner-found path>"}
  ]
```

Make sure the line before it (the end of the repo-level `"risk_signals": [...]`) ends with a comma, as it does today.

In the evidence_refs rule, replace `(under "Scanner summaries", "AGENT INSTANCES",\n  "TOOL DEFINITIONS", or "EXTERNAL SERVICES")` with `(under "Scanner summaries", "AGENT INVENTORY" or\n  "TOOL INVENTORY")`.

Replace the rules from the line starting `- agents: Populate using AGENT INSTANCES` down to and including the line `- tool_usages: repo-wide tool/function references not already captured per agent` with:

```text
- The AGENT INVENTORY and TOOL INVENTORY are verified by static analysis and are FIXED. You cannot add,
  remove, rename, merge or split agents or tools. Refer to them only by their id, exactly as listed.

- enrichment: one entry per inventory agent you have evidence about, keyed by its id. agent_type, goal
  (one sentence, from surrounding comments, prompts or configuration) and capabilities describe that agent.
  Per-agent risk_signals follow the per-agent rules above. Omit agents you know nothing about.

- tool_enrichment: for inventory tools, classify service_category by what the tool DOES (infer from its
  name and context) into one of:
  * "web_search" — search engines, SERP queries (e.g. google_search, tavily_search)
  * "web_browsing" — page fetching, scraping, crawling (e.g. browse_url, scrape_page)
  * "code_execution" — running code, sandboxes, REPLs (e.g. execute_code, run_python)
  * "vector_database" — vector store operations (e.g. query_vectors, upsert_embeddings)
  * "database" — SQL/NoSQL/graph DB operations (e.g. run_query, neo4j_search)
  * "communication" — messaging, email, notifications (e.g. send_slack, send_email)
  * "document_processing" — PDF/DOCX parsing, OCR (e.g. parse_pdf, extract_text)
  * "image_generation" — image creation/editing (e.g. text_to_image, generate_image)
  * "voice_audio" — TTS, STT, audio processing (e.g. text_to_speech, transcribe)
  * "embeddings" — text-to-embedding operations (e.g. text_to_embedding, embed_text)
  * "data_processing" — data transformation, feature engineering, analytics
  * "file_operations" — file read/write/management (e.g. read_file, write_file)
  * "api_integration" — external HTTP/REST API calls (e.g. http_request, call_api)
  * "orchestration" — planning, routing, delegation (e.g. plan, delegate_task)
  * "tool_management" — tool registration, schema management (e.g. register_tool)
  * "testing" — test helpers, validation tools (e.g. validate, run_test)
  * "other" — only if none of the above categories fit
  Do not include tools that already show a category in the TOOL INVENTORY.

- suggested_agents / suggested_tools: agents or tools you believe exist but that are NOT in the
  inventories (for example agents built by a factory function). Each needs a file path that appears in the
  Evidence and a short reason. These are reported as unverified. Never suggest model names (gpt-4o,
  claude-3-sonnet, ...) or package names (faiss-cpu, chromadb, ...) as tools. Return [] when there are none.
```

- [ ] **Step 6: Change the evidence block and parser**

Replace `_build_evidence_block`'s signature and its three inventory sections (agent instances, tool definitions, external services) so it reads:

```python
def _build_evidence_block(
    scanner_summaries: list[dict],
    model_usages: list[ModelUsage],
    capability_tags: list[str],
    framework_candidate: str = "unknown",
    agent_inventory: list[dict] | None = None,
    tool_inventory: list[dict] | None = None,
    threat_reference: str = "",
) -> str:
    lines: list[str] = []

    lines.append(f"FRAMEWORK CANDIDATE (rule-based): {framework_candidate}")
    lines.append("Confirm if correct, or override with a more specific framework name.\n")

    lines.append(f"Capability tags: {', '.join(capability_tags) if capability_tags else 'none'}")

    if model_usages:
        lines.append("\nModel usages:")
        for m in model_usages[:30]:  # cap at 30 to avoid flooding the context
            lines.append(
                f"  - {m.provider}/{m.model_name} ({m.role}) at {m.file_path}:{m.line_number}"
            )

    if agent_inventory:
        lines.append("\n--- AGENT INVENTORY (verified; enrich by id, never rename or add) ---")
        for a in agent_inventory:
            tools = ", ".join(a["tools"]) or "none"
            lines.append(
                f"  - id={a['id']} name=\"{a['name']}\" scope={a['scope']} instances={a['instances']} "
                f"instructions={a['instructions']} tools=[{tools}] file={a['file']}"
            )

    if tool_inventory:
        lines.append("\n--- TOOL INVENTORY (verified) ---")
        for t in tool_inventory:
            category = f" category={t['category']}" if t["category"] else ""
            lines.append(f"  - id={t['id']} name=\"{t['name']}\" type={t['type']}{category} at {t['file']}:{t['line'] or ''}")
```

Keep the rest of the function (scanner summaries, threat reference) unchanged.

Replace the body of `_parse_synthesis_response` after the `json.loads` fallback. The fallback `return SynthesisResult(...)` must drop its `agents=[]` and `tool_usages=[]` arguments.

```python
    enrichment: dict[str, AgentEnrichment] = {}
    raw_enrichment = data.get("enrichment")
    if isinstance(raw_enrichment, dict):
        for agent_id, fields in raw_enrichment.items():
            if not isinstance(fields, dict):
                continue
            agent_type = fields.get("agent_type", "unknown")
            raw_signals = fields.get("risk_signals")
            enrichment[str(agent_id)] = AgentEnrichment(
                agent_type=agent_type if agent_type in _VALID_AGENT_TYPES else "unknown",
                goal=str(fields.get("goal") or ""),
                capabilities=[c for c in fields.get("capabilities") or [] if isinstance(c, str)],
                risk_signals=_parse_risk_signals(raw_signals if isinstance(raw_signals, list) else []),
            )

    tool_enrichment: dict[str, str] = {}
    raw_tools = data.get("tool_enrichment")
    if isinstance(raw_tools, dict):
        for tool_id, fields in raw_tools.items():
            if isinstance(fields, dict) and fields.get("service_category"):
                tool_enrichment[str(tool_id)] = str(fields["service_category"])

    return SynthesisResult(
        is_ai_application=bool(data.get("is_ai_application", False)),
        framework=data.get("framework", "unknown") or "unknown",
        summary=data.get("summary", ""),
        enrichment=enrichment,
        tool_enrichment=tool_enrichment,
        suggested_agents=_parse_suggestions(data.get("suggested_agents")),
        suggested_tools=_parse_suggestions(data.get("suggested_tools")),
        risk_signals=_parse_risk_signals(data.get("risk_signals", [])),
    )
```

Add above `_parse_synthesis_response`:

```python
_VALID_AGENT_TYPES = {"supervisor", "utility", "worker", "unknown"}


def _parse_suggestions(raw: object) -> list[LLMInferredItem]:
    if not isinstance(raw, list):
        return []
    items: list[LLMInferredItem] = []
    for item in raw:
        if isinstance(item, dict) and str(item.get("name") or "").strip():
            items.append(LLMInferredItem(
                name=str(item["name"]).strip(),
                evidence=str(item.get("evidence") or ""),
                file=str(item.get("file") or ""),
            ))
    return items
```

In `SynthesisAgent.synthesize`, replace the parameters `agent_instances`, `tool_definitions` and `external_services` with `agent_inventory: list[dict] | None = None` and `tool_inventory: list[dict] | None = None`, and pass them to `_build_evidence_block` as `agent_inventory=agent_inventory, tool_inventory=tool_inventory`.

- [ ] **Step 7: Use the new contract in the orchestrator**

1. Add a module-level constant and two helpers next to `_build_inventory`:

```python
# Agents and tools listed to the synthesis LLM; agents beyond the bound get no enrichment (spec §7).
_LLM_INVENTORY_CAP = 30


def _inventory_digest(agent_inventory: Inventory) -> tuple[list[dict], list[dict], int]:
    """The inventory as the LLM sees it, production first then by ID; and how many agents did not fit."""
    agents = sorted(agent_inventory.agents, key=lambda a: (a.scope != "production", a.id))
    tools = sorted(agent_inventory.tools, key=lambda t: (t.scope != "production", t.id))
    agent_digest = [
        {"id": a.id, "name": a.name, "scope": a.scope, "instances": len(a.instances),
         "instructions": agent_inventory.instructions.get(a.id, "none"), "tools": a.tools, "file": a.source_file}
        for a in agents[:_LLM_INVENTORY_CAP]
    ]
    tool_digest = [
        {"id": t.id, "name": t.tool_name, "type": t.tool_type, "category": t.service_category,
         "file": t.source_file, "line": t.line_number}
        for t in tools[:_LLM_INVENTORY_CAP]
    ]
    return agent_digest, tool_digest, max(0, len(agents) - _LLM_INVENTORY_CAP)


def _apply_enrichment(
    agents: list[AgentProfile], tools: list[ToolUsage], synthesis: SynthesisResult, scanned_paths: set[str],
) -> int:
    """Merge LLM enrichment into verified items by ID; return how many IDs did not exist."""
    by_id = {a.id: a for a in agents}
    unknown = 0
    for agent_id, fields in synthesis.enrichment.items():
        agent = by_id.get(agent_id)
        if agent is None:
            unknown += 1
            continue
        agent.agent_type = fields.agent_type
        agent.goal = fields.goal
        agent.capabilities = list(fields.capabilities)
        _validate_evidence_refs(fields.risk_signals, scanned_paths)
        agent.risk_signals.extend(fields.risk_signals)
        agent.provenance.update({"agent_type": "llm", "goal": "llm", "capabilities": "llm"})
    tools_by_id = {t.id: t for t in tools}
    for tool_id, category in synthesis.tool_enrichment.items():
        tool = tools_by_id.get(tool_id)
        if tool is None:
            unknown += 1
        elif not tool.service_category:
            tool.service_category = category
    return unknown
```

Add `AgentProfile` to the models import if it is not already there.

2. Before `if not config.no_llm:` (step 6), add `llm_unenriched_agents = 0`.

3. Inside the synthesis block, replace everything from `# Extract structured hints from new scanners for the evidence bundle.` down to and including the closing `)` of `evidence_facts = EvidenceFacts(...)` with the code below. Keep the `_synthesis_step`/`_synthesis_progress` progress code, which sits between them; place it before the digest.

```python
            agent_digest, tool_digest, llm_unenriched_agents = _inventory_digest(agent_inventory)
            evidence_facts = EvidenceFacts(
                system_types=frozenset(classification.system_types if classification else []),
                capability_tags=frozenset(capability_tags),
                mcp_servers_count=len(mcp_servers),
                agent_instances_count=len(agent_inventory.agents),
                tool_definitions_count=sum(1 for t in agent_inventory.tools if t.tool_type == "tool_definition"),
                external_service_categories=frozenset(
                    t.service_category for t in agent_inventory.tools
                    if t.tool_type == "external_service" and t.service_category
                ),
                cloud_llm_count=sum(
                    1 for m in model_usages
                    if (m.provider or "").lower() in CLOUD_LLM_PROVIDERS
                ),
            )
```

4. In the `agent.synthesize(...)` call, replace the three arguments `agent_instances=...`, `tool_definitions=...` and `external_services=...` with:

```python
                    agent_inventory=agent_digest or None,
                    tool_inventory=tool_digest or None,
```

5. In the verbose log after synthesis, replace the `n_agents` and `agent_risks` lines and their messages with:

```python
                    n_enriched = len(synthesis.enrichment)
                    n_risks = len(synthesis.risk_signals)
                    agent_risks = sum(len(e.risk_signals) for e in synthesis.enrichment.values())
                    _log(f"  framework: {synthesis.framework}  |  {n_enriched} agent{'s' if n_enriched != 1 else ''} enriched")
                    _log(f"  risks: {n_risks} system-wide, {agent_risks} agent-specific")
```

6. After `if inventory_error: metadata["inventory_error"] = inventory_error`, add:

```python
        if llm_unenriched_agents:
            metadata["llm_unenriched_agents"] = llm_unenriched_agents
```

7. At the end of the Rule 2 block from Task 10, add:

```python
        if synthesis:
            unknown_ids = _apply_enrichment(pp_agents, pp_tool_usages, synthesis, _scanned_paths)
            if unknown_ids:
                metadata["llm_unknown_ids"] = unknown_ids
            llm_inferred_agents = list(synthesis.suggested_agents)
            llm_inferred_tools = list(synthesis.suggested_tools)
```

- [ ] **Step 8: Run the targeted tests, the full suite and lint**

Run: `python3 -m pytest tests/test_llm_parsing.py tests/test_inventory_orchestrator.py -q && python3 -m pytest tests/ -q && ruff check src/ --select F,E4,E7,E9`
Expected: PASS. If a test elsewhere builds `SynthesisResult(agents=...)` or calls `synthesize(agent_instances=...)`, port it to the new fields; `grep -rn "agent_instances=\|SynthesisResult(" tests src` finds them.

- [ ] **Step 9: Commit**

```bash
git add src/quin_scanner/models.py src/quin_scanner/llm/synthesis_agent.py src/quin_scanner/orchestrator.py tests/test_llm_parsing.py tests/test_inventory_orchestrator.py
git commit -m "feat(inventory): the LLM enriches verified agents and tools by ID; suggestions are reported as unverified"
```

---

### Task 12: HTML Agents tab

**Files:**
- Modify: `src/quin_scanner/html_template.py` (CSS near line 144; `renderAgents` near line 1037)
- Test: `tests/test_inventory_orchestrator.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_inventory_orchestrator.py`:

```python
def test_html_report_renders_instances_flags_and_unverified_suggestions(tmp_path):
    from quin_scanner.models import LLMInferredItem
    from quin_scanner.report import ReportGenerator

    report = _scan(tmp_path, {
        "src/a.py": "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/b.py": "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
    })
    report.llm_inferred_agents = [LLMInferredItem(name="planner", evidence="factory", file="src/a.py")]
    html = ReportGenerator.to_html(report)
    assert "inst-table" in html
    assert "inst-diff" in html
    assert "Suggested by the LLM" in html
    assert '"llm_inferred_agents"' in html and "planner" in html
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_inventory_orchestrator.py -q -k html`
Expected: FAIL (`inst-table` not in the template).

- [ ] **Step 3: Add CSS**

After the `.agent-card__footer{...}` rule, add:

```css
.agent-card__meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.agent-flag{background:#fef3c7;color:#92400e}
.scope-filter{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.scope-filter button{border:1px solid var(--color-border);background:var(--color-surface);border-radius:var(--radius-md);padding:4px 10px;cursor:pointer;font-size:.8rem}
.scope-filter button[aria-pressed="true"]{font-weight:700;border-color:#525252}
.inst-wrap{overflow-x:auto;margin-top:8px}
.inst-table{border-collapse:collapse;font-size:.78rem;width:100%}
.inst-table th,.inst-table td{border-bottom:1px solid #f3f4f6;padding:4px 6px;text-align:left;white-space:nowrap}
.inst-table .inst-diff{background:#fef3c7}
.agents-more{margin-top:12px}
.agents-inferred{margin-top:20px}
```

- [ ] **Step 4: Replace `renderAgents`**

Replace the whole `(function renderAgents(){ ... })();` block with:

```javascript
  /* ---- Agents Tab ---- */
  (function renderAgents(){
    var panel=$("panel-agents");
    var agents=D.agents||[];
    var inferredAgents=D.llm_inferred_agents||[], inferredTools=D.llm_inferred_tools||[];
    if(!agents.length&&!inferredAgents.length&&!inferredTools.length){panel.innerHTML='<div class="empty">No agents identified.</div>';return}

    var PAGE=50, scope="production", shown=PAGE;
    var FLAG_LABELS={tool_divergence:"tool divergence",name_collision:"name collision",model_divergence:"model divergence",ambiguous_instance:"ambiguous instance"};
    var typeBadge=function(t){
      var cls="pill--gray";
      if(t==="supervisor") cls="pill--indigo";
      else if(t==="worker") cls="pill--blue";
      return '<span class="pill '+cls+'">'+esc(t||"unknown")+'</span>';
    };
    var pillList=function(arr,cls){
      if(!arr||!arr.length) return '<span style="color:var(--color-muted);font-size:.78rem">None</span>';
      return arr.map(function(s){return '<span class="pill '+(cls||"")+'">'+esc(s)+'</span>'}).join(" ");
    };
    var llmTag=function(a,field){return (a.provenance||{})[field]==="llm"?' <span class="pill pill--gray" title="Written by the LLM">LLM</span>':""};
    var hasTool=function(inst,name){return (inst.tools||[]).some(function(t){return t.name===name})};

    function toolMatrix(a){
      var insts=a.instances||[];
      if(!insts.length) return "";
      var names=[];
      insts.forEach(function(i){(i.tools||[]).forEach(function(t){if(names.indexOf(t.name)<0) names.push(t.name)})});
      names.sort();
      var prod=insts.filter(function(i){return i.scope==="production"});
      var partial={};
      names.forEach(function(n){
        var holders=prod.filter(function(i){return hasTool(i,n)}).length;
        partial[n]=holders>0&&holders<prod.length;
      });
      var h='<div class="inst-wrap"><table class="inst-table"><thead><tr><th>Location</th><th>Scope</th><th>Model</th>';
      names.forEach(function(n){h+='<th class="'+(partial[n]?"inst-diff":"")+'">'+esc(n)+'</th>'});
      h+='</tr></thead><tbody>';
      insts.forEach(function(i){
        var loc=i.file+(i.line?":"+i.line:"");
        h+='<tr><td class="mono" title="'+esc(loc)+'">'+esc(truncPath(loc,3))+(i.multiplicity==="many"?' <span class="pill pill--gray" title="Created inside a loop">&times;many</span>':'')+'</td>';
        h+='<td>'+esc(i.scope||"")+'</td><td class="mono">'+esc(i.model||"—")+'</td>';
        names.forEach(function(n){
          var t=(i.tools||[]).filter(function(x){return x.name===n})[0];
          var mark=t?(t.resolved?"✓":'<span title="No definition found">✓?</span>'):"";
          h+='<td class="'+(partial[n]?"inst-diff":"")+'">'+mark+'</td>';
        });
        h+='</tr>';
      });
      return h+'</tbody></table></div>';
    }

    function card(a){
      var n=(a.instances||[]).length, many=(a.instances||[]).some(function(i){return i.multiplicity==="many"});
      var h='<div class="agent-card">';
      h+='<div class="agent-card__header"><span class="agent-card__name">'+esc(a.name||"Unnamed Agent")+'</span>'+typeBadge(a.agent_type)+llmTag(a,"agent_type")+'</div>';
      h+='<div class="agent-card__meta"><span class="pill pill--gray">'+esc(a.scope||"production")+'</span>';
      h+='<span class="pill pill--blue">'+n+' instance'+(n===1?"":"s")+(many?" &times;many":"")+'</span>';
      (a.flags||[]).forEach(function(f){h+='<span class="pill agent-flag">'+esc(FLAG_LABELS[f]||f)+'</span>'});
      if(a.identity==="weak") h+='<span class="pill agent-flag" title="No literal name in the code">weak identity</span>';
      h+='</div>';
      if(a.goal) h+='<div class="agent-card__goal">'+esc(a.goal)+llmTag(a,"goal")+'</div>';
      if((a.capabilities||[]).length) h+='<div class="agent-card__section"><div class="agent-card__label">Capabilities'+llmTag(a,"capabilities")+'</div><div class="pills" style="margin-top:0">'+pillList(a.capabilities)+'</div></div>';
      if((a.skills||[]).length) h+='<div class="agent-card__section"><div class="agent-card__label">Skills</div><div class="pills" style="margin-top:0">'+pillList(a.skills)+'</div></div>';
      if((a.instances||[]).length) h+='<div class="agent-card__section"><div class="agent-card__label">Instances and tools</div>'+toolMatrix(a)+'</div>';
      if((a.risk_signals||[]).length){
        h+='<div class="agent-card__section"><div class="agent-card__label">Risk Signals</div>'+renderRiskSignals(a.risk_signals)+'</div>';
      }
      if(a.id||a.source_file){
        h+='<div class="agent-card__footer" title="'+esc(a.source_file||"")+'">'+esc(a.id||"")+(a.source_file?" &middot; "+esc(truncPath(a.source_file,3)):"")+'</div>';
      }
      return h+'</div>';
    }

    function inferred(){
      if(!inferredAgents.length&&!inferredTools.length) return "";
      var rows=inferredAgents.map(function(i){return ["agent",i]}).concat(inferredTools.map(function(i){return ["tool",i]}));
      var h='<details class="agents-inferred"><summary>Suggested by the LLM, no code evidence found ('+rows.length+')</summary><ul>';
      rows.forEach(function(r){h+='<li><b>'+esc(r[0])+'</b> '+esc(r[1].name)+(r[1].file?' <span class="mono">'+esc(r[1].file)+'</span>':'')+(r[1].evidence?' &mdash; '+esc(r[1].evidence):'')+'</li>'});
      return h+'</ul></details>';
    }

    function draw(){
      var visible=agents.filter(function(a){return scope==="all"||(a.scope||"production")===scope});
      var h='<div class="scope-filter" role="group" aria-label="Filter agents by scope">';
      [["production","Production"],["test","Test"],["example","Example"],["all","All"]].forEach(function(s){
        var count=s[0]==="all"?agents.length:agents.filter(function(a){return (a.scope||"production")===s[0]}).length;
        h+='<button type="button" data-scope="'+s[0]+'" aria-pressed="'+(scope===s[0])+'">'+s[1]+' ('+count+')</button>';
      });
      h+='</div>';
      if(!visible.length) h+='<div class="empty">No agents in this scope.</div>';
      else h+='<div class="agent-grid">'+visible.slice(0,shown).map(card).join("")+'</div>';
      if(visible.length>shown) h+='<button type="button" class="agents-more" data-more="1">Show '+Math.min(PAGE,visible.length-shown)+' more of '+(visible.length-shown)+'</button>';
      h+=inferred();
      panel.innerHTML=h;
    }

    panel.addEventListener("click",function(e){
      var b=e.target.closest("button");
      if(!b||!panel.contains(b)) return;
      if(b.dataset.scope){scope=b.dataset.scope;shown=PAGE;draw()}
      else if(b.dataset.more){shown+=PAGE;draw()}
    });
    if(!agents.some(function(a){return (a.scope||"production")==="production"})&&agents.length) scope="all";
    draw();
  })();
```

`renderRiskSignals`, `esc`, `truncPath` and `$` are existing helpers in the template. If `.mono` is not an existing class, add `.mono{font-family:var(--font-mono)}` to the CSS.

- [ ] **Step 5: Run the test**

Run: `python3 -m pytest tests/test_inventory_orchestrator.py -q -k html`
Expected: PASS.

- [ ] **Step 6: Check it in a browser**

```bash
mkdir -p /tmp/quin-demo/src /tmp/quin-demo/tests
printf "from fw import Agent, tool\n@tool\ndef search():\n    pass\nr = Agent(name='researcher', instructions='Find.', tools=[search])\n" > /tmp/quin-demo/src/a.py
printf "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\nfor i in range(3):\n    w = Agent(name='worker', model=os.getenv('MODEL'))\n" > /tmp/quin-demo/src/admin.py
printf "r = Agent(name='researcher', instructions='Find.', tools=[])\n" > /tmp/quin-demo/tests/test_a.py
quin-scanner scan /tmp/quin-demo --no-llm --no-vuln-check -d /tmp/quin-demo-report
```

Open the HTML file in `/tmp/quin-demo-report/`, go to the Agents tab, and check:
- `researcher` shows 3 instances, a `tool divergence` chip, and a highlighted `shell_exec` column;
- `worker` shows `×many`;
- the scope buttons switch between Production / Test / Example / All;
- there are no console errors.

- [ ] **Step 7: Commit**

```bash
git add src/quin_scanner/html_template.py tests/test_inventory_orchestrator.py
git commit -m "feat(inventory): Agents tab shows instances, tool differences, scope filter and unverified suggestions"
```

---

### Task 13: SARIF and determinism checks

**Files:**
- Test: `tests/test_inventory_orchestrator.py` (append)
- Modify: `tests/test_hash_seed_determinism.py`

- [ ] **Step 1: Write the tests**

Append to `tests/test_inventory_orchestrator.py`:

```python
def test_production_tool_divergence_reaches_sarif(tmp_path):
    from quin_scanner.report import ReportGenerator

    report = _scan(tmp_path, {
        "src/a.py": "r = Agent(name='researcher', instructions='Find.', tools=[search])\n",
        "src/b.py": "r = Agent(name='researcher', instructions='Find.', tools=[search, shell_exec])\n",
    })
    sarif = json.loads(ReportGenerator.to_sarif(report))
    assert "T006" in [result["ruleId"] for result in sarif["runs"][0]["results"]]
```

In `tests/test_hash_seed_determinism.py`, add to the `repo` fixture, before `return root`:

```python
    (root / "agents").mkdir()
    for name in ("planner", "researcher", "writer", "critic", "editor", "router"):
        (root / "agents" / f"{name}.py").write_text(
            "from framework import Agent, tool\n@tool\ndef search():\n    return 1\n"
            f"{name} = Agent(name='{name}', instructions='Be {name}.', tools=[search])\n"
            "shared = Agent(name='shared', instructions='Same.', tools=[search])\n",
            encoding="utf-8",
        )
```

and append:

```python
def _inventory(report: dict) -> str:
    return json.dumps([report["agents"], report["tool_usages"], report["agent_tool_relationships"]], sort_keys=True)


def test_inventory_does_not_depend_on_the_hash_seed(tmp_path, repo):
    reports = {seed: _scan(repo, tmp_path / f"i{seed}.json", seed) for seed in ("1", "2", "3")}
    assert len({_inventory(r) for r in reports.values()}) == 1, "the inventory changes with PYTHONHASHSEED"
    shared = next(a for a in reports["1"]["agents"] if a["name"] == "shared")
    assert len(shared["instances"]) == 6
    assert {t["id"] for t in reports["1"]["tool_usages"]} == {f"tool:search@agents/{n}.py" for n in
                                                             ("planner", "researcher", "writer", "critic", "editor", "router")}
```

- [ ] **Step 2: Run them**

Run: `python3 -m pytest tests/test_inventory_orchestrator.py tests/test_hash_seed_determinism.py -q`
Expected: PASS. If the determinism test fails, find the iteration over a `set` or `dict` built from unordered input in `inventory/` and sort it. Do not loosen the test.

- [ ] **Step 3: Commit**

```bash
git add tests/test_inventory_orchestrator.py tests/test_hash_seed_determinism.py
git commit -m "test(inventory): tool divergence reaches SARIF; the inventory is hash-seed independent"
```

---

### Task 14: Corpus, CHANGELOG, README and final verification

**Files:**
- Modify: `tests/corpus/expected/*.json`
- Modify: `CHANGELOG.md`
- Modify: `README.md`

- [ ] **Step 1: Regenerate the corpus snapshots**

Run: `python3 scripts/run_corpus.py --check`
Expected: exit 1 with differences in `agents` (names now include test/example agents and weak agents with name `""`; no 50 cap) and `tools` (counts change: `tools=[...]` references are no longer tool usages; test-file tools are included).

Run: `python3 scripts/run_corpus.py --update`, then `git diff --stat tests/corpus/expected`.

- [ ] **Step 2: Review every snapshot diff**

For each changed file, `git diff tests/corpus/expected/<name>.json` and check:
- Agent names that appear are real agents or come from test/example code.
- Removed agent names were LLM-only or capped (static runs had no LLM, so removals can only come from the cap or from `tools=[...]` fallout; investigate any other removal).
- Tool count changes are explained by clarification 4 (references are not definitions) or by test files.
- `flask.json`, `express.json` and `cobra.json` (non-AI repos) gain no agents.

Write the before/after agent and tool counts per corpus entry into a scratch note; you need them for the CHANGELOG. Anything unexplained is a bug: fix it and rerun from Step 1.

- [ ] **Step 3: Update `CHANGELOG.md`**

Under `## [Unreleased]`, add:

```markdown
### Added

- **Agents and their instances.** Each entry in `agents` is now one logical agent, identified by its name and instructions, with an `instances` list of every place in the code that creates it (file, line, scope, model, the tools passed there, and `multiplicity: many` when created inside a loop). New fields: `id`, `identity`, `scope`, `flags`, `provenance`, `instances`. `tool_usages` and `agent_tool_relationships` gain stable IDs (`id`, `agent_id`, `instance_id`, `tool_id`). IDs never contain line numbers or prompt text, so unrelated edits do not change them.
- **Tool differences between instances.** When instances of the same agent in production code are given different tools, the agent carries a medium-severity T006 risk signal (Excessive Permissions & Privilege Abuse) that also appears in SARIF. The HTML Agents tab shows a table of instances by tool, with the differing tools highlighted, and a Production / Test / Example / All filter.
- `llm_inferred_agents` and `llm_inferred_tools`: agents and tools the LLM suggested that Quin found no code evidence for. They are listed separately and are never part of the inventory.
- Report schema **1.1** (additive; 1.0 consumers keep working).

### Detection changes

- **Static evidence decides the inventory.** `agents` and `tool_usages` are now built from scanner evidence whether or not an LLM runs, so the same commit gives the same inventory on every run. Before, an LLM scan used the LLM's agent and tool lists, which could rename, merge or invent agents. The LLM now only fills in `goal`, `agent_type`, `capabilities`, per-agent risk signals and tool categories for agents and tools it is given by ID.
- **No caps.** Static scans no longer stop at 50 agents and 100 tools.
- **Test and example code is included and tagged** with `scope: test` or `scope: example` (rules in `rules/scope.yaml`). Agents found only there are listed but do not raise tool-divergence risk signals.
- `tool_usages` lists tool definitions only. Names inside `tools=[...]` lists are references: they appear as the instance's tools (linked to a definition when one exists) and as artifacts, but not as separate tool usages.
- The agent and tool scanners now read test files to tag their agents and tools, so read-coverage counts are higher.
- Corpus: <one line per repository with before → after agent and tool counts, from Step 2>.
```

Replace the placeholder line in angle brackets with the real numbers from Step 2 before committing.

- [ ] **Step 4: Update `README.md`**

In the feature table, change the **Agent and prompt discovery** row to:

```markdown
| **Agent and prompt discovery** | Agents and every place each one is created (instances), with the tools and model passed at each instance and a flag when instances differ; system prompts, prompt templates, agent skills and related source files. Each agent, instance and tool has a stable ID. Test and example code is included and tagged. |
```

and change the last sentence under the table to:

```markdown
Quin's detections are evidence for review, not proof that an application is safe or unsafe. Agent-to-tool links come from explicit `tools=[...]` lists in source code; tools attached through MCP servers, toolkits or variables are not linked yet.
```

- [ ] **Step 5: Final verification**

Run each and check the result:

```bash
python3 -m pytest tests/ -q
ruff check src/ --select F,E4,E7,E9
python3 scripts/run_corpus.py --check
quin-scanner scan /tmp/quin-demo --no-llm --no-vuln-check -o json -f /tmp/quin-demo.json && python3 -c "import json; d=json.load(open('/tmp/quin-demo.json')); print(d['schema_version'], [(a['id'], len(a['instances']), a['flags']) for a in d['agents']])"
```

Expected:
- all tests pass;
- ruff reports nothing;
- the corpus check exits 0;
- the last command prints `1.1` and `('agent:researcher', 3, ['tool_divergence'])` among the agents.

- [ ] **Step 6: Commit**

```bash
git add tests/corpus/expected CHANGELOG.md README.md
git commit -m "docs(inventory): CHANGELOG, README and reviewed corpus snapshots for the inventory core"
```

- [ ] **Step 7: Open the PR**

Push `feat/inventory-core` and open a PR against `main`. In the description, link the spec and include the corpus before/after table from Step 2.

---

## Self-review against the spec

| Spec section | Task |
|---|---|
| §2.1 static evidence is the inventory, same on any OS and seed | 9, 10, 13 |
| §2.2 agents with instances; divergence highlighted | 8, 9, 12 |
| §2.3 stable IDs | 8, 9 (`test_ids_do_not_depend_on_line_numbers`) |
| §2.4 LLM enriches by ID, suggestions separate, provenance | 11 |
| §2.5 no caps | 10 (`test_no_cap_on_agents`) |
| §3 non-goals (explicit `tools=[...]` only, no call graph, sites not runtime counts) | 3, 4, 9 |
| §5.1 typed evidence, single agent parse, redaction | 1, 3, 4, 5, 6, 10 (module deleted) |
| §5.2 ID formats | 7, 8, 9 |
| §5.3 report types | 2 |
| §6 resolver steps 1–5 and sorting | 1, 7, 8, 9 |
| §7 orchestrator flow, digest, unknown IDs, unenriched count, removed code | 10, 11 |
| §8 schema 1.1, HTML, SARIF | 2, 12, 13 |
| §9 error handling | 3 (unparseable → None), 5 (regex fallback sites), 10 (`inventory_error`), 11 (malformed LLM output) |
| §10 testing, corpus | every task, 13, 14 |
| §11 rollout | Before you start, 14 |
