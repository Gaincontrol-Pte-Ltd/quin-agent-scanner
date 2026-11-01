# Deterministic Inventory Core (F) — Design

| Field | Value |
|---|---|
| Status | Approved design, not yet planned |
| Date | 2026-11-01 |
| Target version | 1.1.0 (after 1.0.0; additive, schema 1.1) |
| Follow-ups that depend on it | C1 CycloneDX AI-BOM → C2 regulatory mapping → A1 per-agent capability profile |

---

## 1. Problem

Quin's agent and tool inventory is not reproducible, and it has no notion of "the same agent".

- With an LLM, `report.agents` and `report.tool_usages` are whatever the synthesis LLM returns. It is told to use static agent instances as its primary source, but it can rename, merge, drop or invent agents, so the same commit can produce different inventories on different runs.
- Without an LLM (or when synthesis returns nothing), the orchestrator falls back to parsing `ScanFinding.match_text` strings (`match_text.split(" (")[0]`), capped at 50 agents and 100 tools (`orchestrator.py`, post-processing Rules 2 and 3).
- Nothing gives an agent or tool a stable identity. Agents are matched by name strings across `agents`, `agent_tool_relationships` and risk signals.
- Agents are detected twice: by `AgentInstanceScanner` and again by `agent_tool_relationships.py`, which re-parses files with its own list of agent constructors.
- Several post-processing rules exist only to clean up LLM output (hallucinated tools, model names and dependency names reported as tools, duplicates).

A BOM (C1), regulatory evidence (C2) and a per-agent capability profile (A1) all need a repeatable inventory with stable IDs. That is this design.

## 2. Goals

1. Static evidence is the inventory of record. The same commit yields the same agents, instances and tools, with or without an LLM, on any OS and hash seed.
2. Two levels: an **Agent** (logical identity) has one or more **Instances** (code sites that create it). Highlighting how instances of one agent differ, especially in their tools, is a primary output.
3. Stable IDs for agents, instances and tools that do not change when unrelated code moves.
4. The LLM only enriches verified items (by ID) and suggests unverified ones in a separate list. Every field records whether it came from static evidence or the LLM.
5. No inventory caps. Bounding applies only to LLM context and HTML pagination.

## 3. Non-goals

- Tool grants beyond explicit `tools=[...]` lists. MCP-server attachments, toolkits/loaders (`load_tools`, `SQLDatabaseToolkit(...).get_tools()`, CrewAI/Agno toolkits) and tool lists built from variables are out of scope; candidates for A1/A4.
- Side-effect analysis inside tool bodies (A1).
- Cross-file call-graph linking of definitions to instances.
- Runtime instance counts. Instances are code sites; loops are flagged, not counted.
- CycloneDX output (C1) and the experimental `ui/`.

## 4. Decisions

| # | Decision |
|---|---|
| D1 | Static evidence decides the inventory; the LLM enriches by ID and its extra suggestions go to `llm_inferred_agents` / `llm_inferred_tools`. |
| D2 | An **agent's identity** is its literal name + instructions. Model, tools, handoffs, guardrails and MCP servers are **instance attributes**. Models change often; tools are the most important attribute. |
| D3 | Inline constructor sites with the same name **and** the same instructions fingerprint are instances of one agent. Same name, different instructions → separate agents, all flagged `name_collision`. |
| D4 | Instance tools = explicit `tools=[...]` lists only, linked to tool definitions or marked unresolved. |
| D5 | Test and example code is included and tagged `scope: production | test | example`. An agent is production if any instance is. |
| D6 | The agent/instance structure extends the existing `report.agents` objects (additive, schema 1.1); no parallel top-level lists. |
| D7 | Implementation: scanners emit typed evidence alongside their findings; a new deterministic `inventory/` package resolves it (Approach 1 of 3 considered). |
| D8 | IDs never contain line numbers or prompt text. |
| D9 | Definition ↔ instance linking is same-file only. |
| D10 | Tool divergence across **production** instances is a risk signal (T006 / C003, medium); elsewhere it is informational. |

## 5. Data model

### 5.1 Typed evidence (internal, not in the report)

`BaseScanner` is unchanged. Scanners that can say more than a string also implement:

```python
class EvidenceProducer(Protocol):
    def evidence(self) -> list[Evidence]: ...   # read by the orchestrator after scan()
```

```python
@dataclass(frozen=True)
class InstructionsRef:
    kind: str   # "literal" | "file" | "var" | "config" | "none"
    value: str  # literal → sha256 of whitespace-normalised text; else the path / var name / config key

@dataclass(frozen=True)
class AgentSite:                       # AgentInstanceScanner
    role: str                          # "definition" | "instance" | "both"
    kind: str                          # "constructor" | "subclass" | "config_entry" | "decorator" | "graph_node"
    name: str | None                   # literal name only; None if dynamic
    file_path: str
    line: int | None
    instructions: InstructionsRef
    model_expr: str | None             # redacted literal or reference, e.g. "env:MODEL", "var:settings.llm"
    tool_refs: tuple[str, ...] | None  # () = no tools passed; None = not statically known
    in_loop: bool                      # inside a for/while/comprehension
    framework_hint: str

@dataclass(frozen=True)
class ToolSite:                        # ToolDefinitionScanner
    name: str
    kind: str                          # "decorator" | "class" | "function_schema" | "agent_spec" | ...
    file_path: str
    line: int | None
```

`ScanFinding` artifacts are still emitted exactly as today. The agent→tool linking currently in `agent_tool_relationships.py` (Python AST and the JS/TS agent-object regex) moves into `AgentInstanceScanner`'s single pass, which fills `tool_refs`. `model_expr`, instruction references and tool names pass through `redact_secrets`.

### 5.2 IDs

| Item | ID |
|---|---|
| Agent, unique name | `agent:<name>` |
| Agent, name collision | `agent:<name>@<definition path>` |
| Agent, no literal name (weak identity) | `agent:@<path>#<n>`, n = position among unnamed sites in that file |
| Instance | `<agent id>/<path>#<n>`, n = position among that agent's sites in that file |
| Tool, unique name | `tool:<name>` |
| Tool, name collision | `tool:<name>@<path>` |

Paths are repo-relative with forward slashes. Editing a prompt does not change an ID. A prompt edit that makes two same-named sites diverge is a collision, so both IDs switch to the path-qualified form; the report states this.

### 5.3 Report types (additive)

- `AgentProfile` + optional `id`, `identity` (`strong` | `weak`), `scope`, `flags` (list of `name_collision`, `tool_divergence`, `model_divergence`, `ambiguous_instance`), `provenance` (field name → `static` | `llm`), `instances: list[AgentInstance]`.
  - Existing fields keep their meaning: `tools` = union of instance tools; `source_file` = definition site; `goal`, `agent_type`, `capabilities` = LLM enrichment (empty without an LLM).
- `AgentInstance`: `id`, `file`, `line`, `scope`, `multiplicity` (`one` | `many`), `model`, `tools: list[{tool_id: str | None, name: str, resolved: bool}]`.
- `ToolUsage` + optional `id`, `scope`.
- `AgentToolRelationship` + optional `agent_id`, `instance_id`, `tool_id`.
- `ScanReport` + `llm_inferred_agents`, `llm_inferred_tools` (name, evidence text, file; no ID, no instances).

## 6. Inventory resolver (`quin_scanner/inventory/`)

Deterministic, no I/O, no LLM. Input: `AgentSite`s, `ToolSite`s, the static tool sources that already exist (skills from `SkillScanner`, external services from `tool_services.yaml`, MCP tool classification) and rules. Output: agents with instances, tools, flags, relationships. Steps, in this order:

1. **Scope tagging.** New `rules/scope.yaml`, first match wins, default `production`.
   - test: the patterns now in `_TEST_PATH_PATTERNS` (moved out of `orchestrator.py`).
   - example: `examples/`, `samples/`, `cookbook/`, `notebooks/`, `docs/`, `demo/`, `demos/`, `tutorials/`.
2. **Tools.** Group tool sites by name. Unique → `tool:<name>`; collision → `tool:<name>@<path>` plus `name_collision`.
3. **Agent grouping.**
   - Literal-name sites group by `(name, instructions fingerprint)`. Different fingerprints for one name → separate agents, all `name_collision`.
   - Sites whose instructions are `none` or dynamic join the single same-name group if exactly one exists; otherwise they join none and are flagged `ambiguous_instance`.
   - Sites with no literal name → one agent each, `identity: weak`.
   - Definition ↔ instance links, same file only:
     (A definition site whose instructions are unknown joins only a same-named agent with a site in its own file (D9); an instance site may join across files.)
     - subclass name ↔ `ClassName(...)` calls;
     - CrewAI config key ↔ `agents_config['key']` or `@agent def key`;
     - decorated function ↔ calls of that function.
   - Unlinked definition sites are agents whose only instance is their own site (`role: both`).
   - Agent scope: production if any instance is production, else test, else example.
4. **Instance tool linking.** For each `tool_refs` entry:
   1. a tool defined or imported in the same file;
   2. else a repo-unique tool name;
   3. else `resolved: false`, `tool_id: None`, raw name kept.
5. **Divergence**, per agent across its instances.
   - `tool_divergence` when tool sets differ. When production instances differ, also emit a `RiskIndicator` on the agent: threat `T006`, control `C003`, severity `medium`, one `EvidenceRef` per differing instance. Test- or example-only differences are flags only.
   - `model_divergence` when model expressions differ (informational).
   - `multiplicity: many` on instances with `in_loop`.

All output is sorted by ID.

## 7. Orchestrator and LLM integration

```
scanners (parallel) ──► findings (unchanged) ─────────────► artifacts / coverage / SARIF
            └─────────► evidence() ─► inventory.resolve() ─► Inventory
                                                              │
                                    ┌─────────────────────────┤
                                    ▼                         ▼
                        LLM synthesis (optional)     report.agents / tool_usages / relationships
                        input: Inventory digest        (always from Inventory)
                        output: enrichment by ID ───► agents[].goal / agent_type / capabilities / risk_signals
                                + suggestions   ───► llm_inferred_agents / llm_inferred_tools
```

- **Synthesis input:** a bounded digest of the inventory, production agents first, then by ID: ID, name, instance count, instructions reference, tool names. Classification and repo-level risk signals work as today.
- **Synthesis output contract:**
  ```json
  {"enrichment": {"agent:researcher": {"goal": "...", "agent_type": "worker", "capabilities": ["..."], "risk_signals": ["..."]}},
   "suggested_agents": [{"name": "...", "evidence": "...", "file": "..."}],
   "suggested_tools": [{"name": "...", "evidence": "...", "file": "..."}]}
  ```
  - Enrichment for unknown IDs is dropped and counted in `metadata.llm_unknown_ids`.
  - The LLM cannot add, rename or remove verified agents or tools.
- **Agents beyond the LLM context bound get no enrichment.** Their `goal` stays empty and `metadata` records how many were not enriched. No multi-call enrichment.
- **Provenance:** with `--no-llm` every field is `static` and LLM fields are empty, as today.
- **Removed code:**
  - post-processing Rules 2 and 3 (static fallback and caps);
  - Rules 3a-ii and 3b-ii, and the LLM-cleanup parts of Rules 3b and 4;
  - the AST pass in `agent_tool_relationships.py`, which now builds `AgentToolRelationship`s from the inventory.

## 8. Outputs

### JSON / YAML (schema 1.1)

- `REPORT_SCHEMA_VERSION = "1.1"`.
- `docs/schema/report-1.json` gains optional fields and the definitions `agentInstance`, `instanceTool`, `llmInferredAgent`, `llmInferredTool`. The CI comparison against the frozen 1.0 schema must still pass.
- `docs/schema/README.md` gains a 1.1 section.

### HTML (Agents tab)

- **Agent card:** name, scope chip, "N instances" badge (×many if any instance is in a loop), flag chips.
- **Expanded card:** an instances table with location, scope, model, then one column per tool with a tick per instance. Tools not held by every production instance are highlighted.
- **Scope filter:** Production (default) / Test / Example / All. Pagination at 50 replaces the caps.
- **Provenance:** LLM-written fields carry an "LLM" label.
- **Unverified suggestions:** a collapsed section, "Suggested by the LLM, no code evidence found", for `llm_inferred_*`.

### SARIF

- Production tool divergence appears through the existing risk-signal path (rule ID `T006`); no new rule IDs.
- Name collisions, model divergence and test/example divergence are not SARIF results.

## 9. Error handling

- **Unparseable files** keep today's regex path and yield `AgentSite`s with `instructions: none` and `tool_refs: None`.
- **Resolver exception:** log a warning, set `metadata.inventory_error`, and build `identity: weak` agents from findings. The report is always produced.
- **LLM failure** (bad JSON, timeout, unknown IDs): no enrichment, reason in `metadata.llm_errors`. The verified inventory is unaffected.

## 10. Testing

- **`tests/test_inventory_resolver.py`** (new): hand-built sites, one test per rule:
  - grouping, collisions, `ambiguous_instance`, weak identity;
  - scope and production-wins;
  - tool resolution order and unresolved tools;
  - divergence flags and the production-only T006 signal;
  - ID format and IDs unchanged when lines move;
  - sort order.
- **Scanner tests:** `test_agent_instance_scanner.py` and a new `test_tool_definition_scanner.py` check `evidence()` for subclass, CrewAI config, decorator, inline constructor, loop and JS/TS patterns.
- **Relationships:** `test_agent_tool_relationships.py` checks that relationships come from the inventory and that every existing case keeps its links.
- **LLM contract:** `test_llm_parsing.py` checks that unknown IDs are dropped, suggestions are routed to `llm_inferred_*`, and verified fields cannot be overwritten (fake provider, no network).
- **Determinism:** `test_hash_seed_determinism.py` compares `agents` (with instances) and `tool_usages` byte for byte across hash seeds.
- **Schema:** `test_report_schema.py` validates 1.1 output; the frozen 1.0 baseline comparison still passes.
- **Corpus:** `scripts/run_corpus.py --update`, and every snapshot diff is reviewed. Expected: no caps, instances grouped under agents, scope tags. Anything else is a bug.

## 11. Rollout

- Feature branch after 1.0.0 ships; released as **1.1.0**. No frozen contract changes.
- **CHANGELOG** *Added*: agents and instances, IDs, scope, `llm_inferred_*`, schema 1.1.
- **CHANGELOG** *Detection changes*: static evidence decides the inventory, caps removed, LLM enrichment only, with before/after corpus numbers.
- **Docs:** README feature table, `docs/schema/README.md`, and an "Agents and instances" docs section.
- Commit convention `feat(inventory): ...`.

## 12. Constraints this sets for later work

- **C1 (CycloneDX AI-BOM):** converts the report and makes no LLM decisions. It uses IDs as `bom-ref`s, excludes `llm_inferred_*`, and its `dependencies` graph links agent → instance tools and agent → model. Already decided: CycloneDX 1.6 only; AI components only (document `cyclonedx merge` with syft/cdxgen); inventory + vulnerabilities only; `-o cyclonedx` on `scan`, `scan-batch`, `scan-org`. Open: OSV lookup currently covers only the primary framework.
- **C2 (regulatory mapping):** evidence is keyed by item IDs.
- **A1 (capability profile):** builds on per-instance tool lists and may widen tool grants (MCP, toolkits, variables), as excluded in §3.
