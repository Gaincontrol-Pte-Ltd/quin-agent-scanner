# CycloneDX AI-BOM Export (C1) — Design

| Field | Value |
|---|---|
| Status | Implemented on feat/cyclonedx-aibom (not yet released) |
| Date | 2026-11-02 |
| Target version | 1.1.0 (after 1.0.0; new output format, report schema unchanged) |
| Depends on | F deterministic inventory core (PR #91, branch `feat/inventory-core`) |
| Followed by | C2 regulatory mapping, A1 per-agent capability profile |

---

## 1. Problem

Quin finds the AI parts of a repository — framework, models, agents with their instances, tools, MCP servers, LLM endpoints — and known vulnerabilities in the framework. That inventory lives only in Quin's own JSON, YAML, HTML and SARIF reports. Teams that track software with BOM tooling (Dependency-Track, `cyclonedx merge`, compliance reviews) cannot use it without writing a converter.

F made the inventory deterministic with stable IDs. C1 exports it as a CycloneDX 1.6 BOM.

## 2. Goals

1. `-o cyclonedx` on `scan`, `scan-batch` and `scan-org` writes a CycloneDX 1.6 JSON BOM that validates against the official schema.
2. The BOM holds AI components only. Package SBOMs come from syft or cdxgen; the docs show how to combine them with `cyclonedx merge`.
3. The BOM holds inventory and vulnerabilities only: no risk signals, divergence flags or LLM-written text.
4. The same commit, the same Quin version and the same OSV data give the same BOM, with or without the LLM pass. Only `serialNumber` and `metadata.timestamp` differ between runs.
5. Agents keep the agent/instance structure from F: one component per agent, one occurrence per instance.
6. No new runtime dependency.

## 3. Non-goals

- CycloneDX versions other than 1.6, and XML output.
- Package dependencies (syft/cdxgen do this).
- An org-level combined BOM (`cyclonedx merge` does this; the org dashboard idea C3 was rejected).
- Risk properties, regulatory mapping (C2), capability profiles (A1).
- A BOM for `skills scan`.
- A GitHub Action input for the BOM (small follow-up).
- Changes to the JSON report schema (the framework fix adds two informational `metadata` keys, §5.2; `metadata` is an open map).

## 4. Decisions

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | How agents and tools appear | Components; instances as `evidence.occurrences`; links in `dependencies` | Services (no occurrences, weaker tooling support); agents only as names on the root |
| D2 | Which vulnerabilities | OSV entries with an ID only | Web-search results too, labelled; web-search results with an ID |
| D3 | Test and example code | Included; test/example-only agents get `scope: "excluded"` | Production only plus `--include-tests`; included without scope |
| D4 | `scan-batch` / `scan-org` | One BOM per repository | Also a combined org BOM; only a combined BOM |
| D5 | How the BOM is built | Hand-written dict builder, validated in tests against the vendored 1.6 schema | `cyclonedx-python-lib` as runtime dependency or optional extra |
| D6 | Agent and tool component type | `application` with property `quin:kind` = `agent` / `tool`; no `quin:service-category` (§5.2) | — (CycloneDX has no agent or tool type) |
| D7 | `serialNumber` | Random `urn:uuid` per BOM | Deterministic UUID (the spec requires a new serial number for every BOM, even when content is unchanged) |
| D8 | Which framework | The rule-based framework is the framework of record; the LLM fills it in only when static detection finds none; the BOM includes the framework only when `metadata.framework_source == "static"` | The LLM's framework with the rule-based one as fallback (the framework, and the OSV results, changed with an LLM key) |

## 5. Mapping

### 5.1 Header

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:<random uuid4>",
  "version": 1,
  "metadata": {
    "timestamp": "<report.scan_timestamp, ISO 8601 UTC>",
    "tools": {"components": [{"type": "application", "name": "quin-scanner", "version": "<quin version>"}]},
    "component": {"type": "application", "bom-ref": "repo", "name": "<repository name>"}
  },
  "components": [...],
  "services": [...],
  "dependencies": [...],
  "vulnerabilities": [...]
}
```

The repository name is `owner/repo` for GitHub targets, given as `owner/repo` or as a GitHub URL (`https://github.com/owner/repo`, `http://…`, `git@github.com:owner/repo`, each with an optional `.git` and trailing `/`), and the directory name for local paths (`_repo_name` in `cyclonedx.py`). Empty arrays are omitted.

### 5.2 Components

Order: framework, then models, then agents, then tools. Within each group, sorted by `bom-ref`.

| Quin item | `type` | `bom-ref` | Other fields |
|---|---|---|---|
| Framework (only when it comes from static detection, `metadata.framework_source == "static"`, and `parse_framework_ref(report.framework)` resolves) | `framework` | purl, e.g. `pkg:pypi/crewai@0.80.0` | `name`, `version`, `purl` |
| `model_usages` entry with a literal model name | `machine-learning-model` | `model:<provider>/<model_name>`; `model:unknown/<model_name>` when the provider is empty | `name`, `publisher` = provider (omitted when the provider is empty or `unknown`); one occurrence per usage (file, line) |
| Agent | `application` | agent ID | `name` (the agent ID for a weak agent without a literal name), `scope`, properties, occurrences (5.3) |
| Tool (`tool_usages`) | `application` | tool ID | `name`, properties; one occurrence at the tool's own location when known |

The report's framework is the rule-based one whenever static detection finds it (the orchestrator records `metadata.framework_source = "static"`, and keeps a different LLM answer in `metadata.llm_framework`); only when static detection finds none does the LLM's answer become the framework (`framework_source = "llm"`). An LLM-named framework is left out of the BOM because it can differ between runs.

`scope` on agents: `required` when the agent's scope is `production`, `excluded` when it is `test` or `example`. Tools and models carry no `scope`.

Properties (namespace `quin:`):

| Property | On | Value |
|---|---|---|
| `quin:kind` | agents, tools | `agent` / `tool` |
| `quin:identity` | agents | `strong` / `weak` (from F) |
| `quin:tool-type` | tools | `tool_definition` / `external_service` / `skill` / `mcp_tool` |

Properties are sorted by name. Fields the LLM can write (`goal`, `agent_type`, `capabilities`) are not exported. `service_category` is not exported either: the LLM can fill an empty one and `ToolUsage` does not record which source set it, so exporting it would make the BOM depend on the LLM pass.

### 5.3 Instances as occurrences

Each agent instance becomes one entry of the agent's `evidence.occurrences`:

```json
{
  "bom-ref": "<instance id>",
  "location": "<file, repo-relative>",
  "line": 42,
  "additionalContext": "scope=test; model=gpt-4o; tools=search,scrape"
}
```

- `line` is omitted when unknown.
- `model=` is the instance model as recorded (literal or reference such as `env:MODEL`); omitted when none.
- `tools=` lists the instance's tool names in order; `tools=unknown` when `tools_known` is false; `tools=` (empty) when none were passed.
- `multiplicity=many` is appended when the instance is created in a loop.
- Occurrences are sorted by location, then line, then instance ID.

### 5.4 Services

| Quin item | `bom-ref` | Fields |
|---|---|---|
| MCP server | `service:mcp:<name>` | `name`, property `quin:transport`, property `quin:source-file` |
| `llm_endpoints` entry whose `kind` is not `unresolved` | `service:endpoint:<host>` | `name` = host, `endpoints` = redacted URLs (sorted, deduplicated), property `quin:endpoint-kind` (the host's kinds, sorted and comma-separated when there are several, e.g. `hosted_provider,remote`) |

Endpoints are grouped by host. Services are sorted by `bom-ref`.

Endpoints whose host contains `$`, or whose host or URL contains any of `{ } < > " | \ ^` `` ` `` or whitespace, are treated like unresolved addresses (template placeholders such as `${HOST}` or `$HOST`) and left out.

### 5.5 Dependencies

- `repo` depends on the framework, every agent and every service.
- Each agent depends on the tool IDs it links to (resolved instance tools and agent skills) and on the model components whose name matches a literal model of one of its instances.
- Tool references without a tool ID, and model references, are not dependencies.
- The root, every component and every service get a `dependencies` entry (`dependsOn` omitted when empty). Occurrence and vulnerability `bom-ref`s do not. Entries and `dependsOn` lists are sorted.

### 5.6 Vulnerabilities

Only `report.vulnerabilities` entries with `source == "osv"` and a non-empty `cve_id`, and only when a framework component exists.

```json
{
  "bom-ref": "vuln:<id>",
  "id": "<CVE-… or GHSA-…>",
  "source": {"name": "OSV", "url": "<source_url>"},
  "ratings": [{"score": 7.5, "severity": "high"}],
  "description": "<summary>",
  "published": "<ISO 8601 date-time>",
  "affects": [{"ref": "<framework purl>"}]
}
```

- `ratings[].score` omitted when `cvss_score` is null; `severity` uses the CycloneDX enum (`unknown` stays `unknown`).
- `published` is normalised to a date-time (`YYYY-MM-DDT00:00:00Z` for a bare date); omitted when missing or unparsable.
- Duplicate IDs are de-duplicated deterministically: the entry that ranks first (severity, then higher score, then summary, then URL) is kept, whatever the input order.
- Sorted by severity (critical first), then `id`.

### 5.7 Left out

`llm_inferred_agents`, `llm_inferred_tools`, `risk_signals` (repo and agent), `flags`, `provenance`, LLM text, web-search vulnerabilities, `artifacts`, `skills`, `governance`, `coverage`, `file_hashes`, `infra`.

## 6. Identity and uniqueness

`bom-ref` values come from F's stable IDs, so they are unique by construction across agents (`agent:`), tools (`tool:`) and instances. The prefixes `model:`, `service:mcp:`, `service:endpoint:`, `vuln:` and `repo` keep the groups apart. When two items in the same group would share a `bom-ref` (e.g. two MCP servers with the same name), the second and later get `#2`, `#3`, … in their sorted order. Component and service refs are claimed before any occurrence or vulnerability ref, so a component always keeps its bare ID and a colliding occurrence or vulnerability ref is the one that gets the suffix.

## 7. CLI and files

- `cyclonedx` is added to `_OUTPUT_CHOICES` for `scan`, `scan-batch`, `scan-org`.
- Auto-named files use the extension `.cdx.json` (`<name>_<ts>.cdx.json`); other formats keep `.<fmt>`.
- `-f FILE` and stdout behave as for SARIF.
- When web-search vulnerabilities were left out, one line goes to stderr: `N web-search vulnerabilities omitted from the BOM (OSV only)`.
- The BOM does not depend on whether the LLM pass ran: it uses static evidence only, and the framework (with its OSV vulnerabilities) only when static detection found it.

## 8. Code

- New `src/quin_scanner/cyclonedx.py`, same style as `sarif.py`: private builders returning plain dicts, public `build_bom(report) -> dict`, `to_cyclonedx(report: ScanReport) -> str` (JSON, 2-space indent, `ensure_ascii=False`, written like the other formats) and `omitted_vulnerability_count(report) -> int`.
- `ReportGenerator.render` gets a `cyclonedx` branch; `ReportGenerator.to_cyclonedx` mirrors `to_sarif`.
- `cli.py`: output choice, extension mapping, stderr note.
- No change to `models.py` or the report schema. `orchestrator.py` makes the rule-based framework the framework of record and records `metadata.framework_source` / `metadata.llm_framework` (§5.2).

## 9. Errors

- An empty inventory produces a valid BOM with only the root component and its empty dependency entry.
- A framework without a resolvable purl, or one not from static detection, produces no framework component and no vulnerabilities.
- If building the BOM raises, `scan` fails through its existing error path with `Scan failed: could not build the CycloneDX BOM: <reason>` and exit code 1; no partial file is written (render first, then write). In `scan-batch` and `scan-org` that target is reported and counted as failed, and the run continues.

## 10. Testing

- Vendor the official CycloneDX 1.6 JSON schema (`bom-1.6.schema.json`) and the schemas it references (`spdx.schema.json`, `jsf-0.82.schema.json`) in `tests/cyclonedx_schema/`, with their source URLs and licence noted in a README. Validate offline with the existing `jsonschema` dev dependency.
- Unit tests in `tests/test_cyclonedx.py`:
  - header fields; serial number format; timestamp;
  - framework component and purl; no framework when unresolved;
  - model components and occurrences; reference-only models not components;
  - agent components with `scope` `required` / `excluded`; `quin:` properties;
  - occurrences: instance ID as `bom-ref`, `additionalContext` for known, unknown and empty tool lists, `multiplicity=many`;
  - tool components; services for MCP servers and resolved endpoints; unresolved endpoints left out;
  - dependency graph, including unlinked tool references left out;
  - OSV-only vulnerabilities, entries without an ID dropped, `affects` points at the framework;
  - `bom-ref` collision suffixes;
  - LLM-only fields and `llm_inferred_*` absent;
  - every output validates against the vendored schema.
- Determinism: export twice under different `PYTHONHASHSEED` values; after removing `serialNumber` and `metadata.timestamp`, output is byte-identical.
- CLI tests: `-o cyclonedx` on `scan` (file and stdout), `scan-batch` auto-naming `.cdx.json`, stderr note.
- Corpus: `scripts/run_corpus.py --check` also builds and schema-validates a BOM for every corpus repository. No BOM snapshots are stored. A BOM export that fails or a BOM that fails the schema marks the entry `INVALID` (exit 1, a product defect, not an infrastructure error); the corpus workflow also runs when `cyclonedx.py`, `report.py`, `tests/cyclonedx_support.py` or `tests/cyclonedx_schema/` change.

## 11. Docs

- `docs/cli.md`: the new format.
- New `docs/ai-bom.md`: mapping table, `quin:` properties, what is left out and why, combining with syft/cdxgen via `cyclonedx merge`, importing into Dependency-Track.
- `CHANGELOG.md` [Unreleased] entry; README output-format list.

## 12. Release

Ships in 1.1.0 together with F. Branch `feat/cyclonedx-aibom` is based on `feat/inventory-core`; it is rebased after PR #91 merges.
