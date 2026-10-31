# Changelog

All notable changes to Quin Agent Scanner are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.0.0rc2] — 2026-10-31

**Second release candidate for 1.0.** Fixes the problems the `1.0.0rc1` pilot found: report and baseline files are written with LF line endings on every OS, agent names are read from real constructor arguments instead of text inside strings (and many agents the old matching missed are now found), agents defined as workflow-graph nodes in YAML are detected, Browser Use is a recognised framework, and the MCP SDK is recognised. No stable interface changed: the CLI, report schema (`schema_version` 1.0), exit codes, rule IDs, config, baseline and Action interfaces are the same as in `1.0.0rc1`. Detection results change as listed under *Detection changes*. The two-week soak period restarts with this release; `1.0.0` follows if it passes without a contract change or an open critical bug. Please [report problems](https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/issues).

### Added

- Quality corpus: five external repositories from the 1.0.0rc1 pilot (gpt-researcher, browser-use, modelcontextprotocol/servers, ChatDev and the awesome-claude-skills collection), pinned at commit SHAs. Their snapshots record today's results including known gaps (#70, #71, #72), so the fixes that follow show up as snapshot diffs.

### Detection changes

- **Agent names are read from real arguments (#70).** In Python files the agent-instance scanner now parses the code and takes the literal `name=` (or `agent_name=`) keyword of a call to `...Agent(...)` or `GroupChatManager(...)`. Before, a regex also matched text inside string arguments (`Customer name: "Alice Johnson"` inside an `Agent(task="""...""")`), the tail of other keywords (`vault_name=`, `eval_name=`), the keywords of nested calls (`Agent(tools=[Tool(name="x")])`), and the first positional string of a bare `Agent("...")`, which for several frameworks is a task or a model, not a name (`Agent('Find the founders...')`, `Agent('openai:gpt-4o')`). A class such as `AssistantAgent("assistant")` still takes its first positional string as the name. The same parse also finds agents the regex missed because a `)` appeared inside the call's arguments: in the corpus, agno +7 and microsoft-agent-framework +194 agent instances (their reported lists are capped at 50, so which 50 are shown changed). Files that do not parse, and TypeScript/JavaScript, keep regex matching, now with `name` anchored so it no longer matches `vault_name`. Corpus: browser-use goes from 4 false agents to none.
- **Browser Use is a recognised framework (#70).** Self-imports (`from browser_use`), the `browser-use` dependency, and an OSV lookup entry; the lowest priority, so an application built on another framework keeps it. Side effects on the browser-use repository itself: its `from browser_use import ...` lines are now code-pattern artifacts (396 to 1275), and its own `browser-use` skill is no longer also listed as a tool (28 to 27 tools), because tools named like a known dependency are filtered.
- **Agent nodes of YAML workflow graphs are agents (#72).** A YAML file with any name whose `graph.nodes` list contains items with `type: agent` now yields one agent per such node, named by its `id` (ChatDev defines its agents this way under `yaml_instance/`). Only files mentioning both `nodes` and `agent` are parsed, and files over 512 KB are skipped; `agents.yaml`, `crew.yaml`, `root_agent.yaml` and `flow.dag.yaml` keep their own parsers. Corpus: ChatDev goes from 0 agents to 40 (and gains the `multi-agent` tag). ChatDev's framework stays `unknown`: it has no marker file or published package to recognise it by.
- **The MCP SDK is recognised (#71, first part).** Dependency rules for `mcp`, `fastmcp` and `@modelcontextprotocol/sdk`, and code patterns for `from mcp`, `FastMCP(`, `new McpServer(` and imports of the TypeScript SDK, all with the existing `tool-use` capability tag. A repository that builds an MCP server or client is now recognised as an AI project and its SDK usage shows up as artifacts; before, an MCP server project with no `mcp.json` was not recognised at all. Effects in the corpus: more artifacts in repositories that import the SDK (for example modelcontextprotocol/servers 10 to 81), and ChatDev gains the `tool-use` tag. No report field changes, and `mcp_servers` still lists only servers named in configuration files: listing the servers a repository *implements*, and their tools, needs a new field (schema 1.1) and is planned after 1.0. Depending on the SDK does not set `framework`: clients and multi-agent systems use it too, so the unused `mcp` and `modelcontextprotocol` entries were removed from the framework lookup rather than activated.

### Changed

- The locked `openai` is 2.54.0 and the CI workflows use newer versions of their actions (checkout, setup-uv, cache, setup-node). Neither affects what users install: the runtime dependency ranges are unchanged.

### Fixed

- Windows: report files (`scan -f`/`-d`, `skills scan -f`) and skills baseline files were written with CRLF line endings, so the same scan was not byte-identical across operating systems. They are now written with LF everywhere.

## [1.0.0rc1] — 2026-10-28

**First release candidate for 1.0.** The interfaces in the [stability policy](docs/stability.md) are frozen from this release: the CLI and its exit codes, the JSON/YAML report schema (`schema_version` 1.0), SARIF output and rule IDs, and the config, baseline and GitHub Action interfaces. Quin is now tested on Linux, macOS and Windows with Python 3.11, 3.12 and 3.13, and a pinned corpus of public repositories guards detection quality. `1.0.0` follows after about two weeks without a contract change or an open critical bug; please try this release on your repositories and [report problems](https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/issues). Upgrading from a beta? Read [Migrating from the betas](docs/migrating-from-the-betas.md) first.

### Added

- Quality corpus: `tests/corpus/manifest.yaml` pins 5 public skill collections, 11 framework example repositories (at commit SHAs) and the in-repo fixtures; `scripts/run_corpus.py` scans them with the public CLI (no LLM) and compares a deterministic summary with `tests/corpus/expected/`. A new required-able `Corpus` workflow runs it on pull requests that touch scanners, rules or the corpus, and fails if a snapshot moved without being updated or updated without a `### Detection changes` CHANGELOG entry; a weekly run reports drift against upstream HEAD. The in-repo entries also run in the normal test suite on every OS.
- macOS and Windows are now tested in CI: the full suite runs on `macos-latest` and `windows-latest` for Python 3.11, 3.12 and 3.13, and the GitHub Action is exercised on all three operating systems. Tests that simulate Windows inputs (backslash paths, drive-letter and UNC targets, read-only files, BOM and CRLF text) also run on Linux.
- Releases: pushing a version tag now also creates a GitHub Release whose notes are that version's CHANGELOG section (pre-releases are marked as such), with the built package attached. `scripts/release_notes.py` extracts the section.
- Repository: issue forms (bug, detection issue, feature request), a pull request template with the CHANGELOG, corpus and stability checklist, a `CODEOWNERS` file for the stable surfaces, and a `Frontend` workflow that builds the experimental web UI when it changes.
- Documentation: a generated command-line reference (`docs/cli.md`, produced by `scripts/gen_cli_reference.py` from the CLI; a test fails when it is stale), a migration note for users of the betas (`docs/migrating-from-the-betas.md`), and a test that fails when the README mentions a flag or command that does not exist.
- CI job "Tests on the oldest allowed dependencies": runs the whole suite with every direct runtime dependency resolved to its lowest allowed version, so the floors are real. `tests/test_dependency_policy.py` checks that every runtime dependency has a floor, the LLM SDKs have a ceiling, the locked versions satisfy the ranges, and the SDK ranges in `docs/stability.md` match `pyproject.toml`.
- `SECURITY.md` explains how to verify a release's PyPI attestation; the publish workflow requests attestations explicitly (previously the action's default).
- GitHub Action: new optional inputs `path`, `skills-baseline`, `fail-on` (gate the job on skill verdicts, checked after the SARIF upload), `upload-sarif`, `output-report`, `version` and `python-version`, and outputs `sarif-path`, `report-path` and `version`. `.github/workflows/test-action.yml` runs the action on fixtures in CI, and `tests/test_action_contract.py` freezes the inputs and outputs.
- Config files may carry `config_version` (default 1); a newer version is rejected with an error that says to upgrade. Unknown config keys now produce a warning on stderr instead of being silently ignored. A missing, unreadable or invalid config file exits 2 in `scan`, `scan-batch` and `scan-org` (it used to surface as a traceback); `scan-org` now validates the config before listing repositories.
- ID registry tests (`tests/test_id_registry.py`, frozen `tests/id_baseline_1.0.json`): a skill rule ID that existed at 1.0 may not disappear unless it is listed in the new "Retired rules" table in `docs/skill-rules.md`; a retired ID may never be emitted again; threat (`T001`-`T014`) and control (`C001`-`C014`) IDs and names are pinned.
- Baseline compatibility tests: the fingerprint algorithm is pinned by a golden value, and a frozen baseline written by this release must keep loading and suppressing findings.
- CLI contract tests: `tests/cli_snapshot.json` pins every command, option, default and type, and a frozen 1.0 baseline fails the build on a breaking CLI change (removed or renamed command or option, changed default, type or requiredness, a new required option); `tests/test_exit_codes.py` pins the exit codes of every command.
- Report `schema_version` (`"1.0"`) in the JSON and YAML reports and in the `skills scan -o json` envelope, and `quin-scanner --version` now also prints the report schema version.
- JSON Schemas for the report (`docs/schema/report-1.json`) and the `skills scan` envelope (`docs/schema/skills-scan-1.json`). Tests validate real output against them, fail when an emitted field is missing from the schema, and compare the schemas with a frozen 1.0 baseline so a breaking schema change cannot slip in.
- `docs/stability.md`: the stability and support policy that takes effect with 1.0.0: which surfaces are stable (CLI and exit codes, report schema, SARIF and rule IDs, config/baseline/Action), what counts as a breaking change, detection changes, the deprecation window (one minor release and 90 days), exit codes, supported platforms and the support policy.
- `docs/schema/README.md`: the report schema reference (compatibility rules, conventions, top-level fields, key records, the `skills scan` envelope and the baseline file).
- `tests/test_stability_docs.py`: tests that fail when the documented commands or top-level report fields drift from the code, or when a relative link in the docs breaks.
- README "Stability" section; the Python import API and the web UI (`ui/`) are declared not public and the UI is marked experimental.

### Changed

- Dependency ranges now match what is tested: `click>=8.2` (was 8.1), `openai>=1.55.3,<3` (was `>=1.0`; older versions break with current `httpx`), `google-genai>=1.15,<3` (was `>=1.0`), `httpx>=0.28.1` (was `>=0.27`; `google-genai` already required it). The vendor SDKs now have a ceiling at the next major version, like `anthropic` already had. Installs that pin older versions of these packages must upgrade them.
- GitHub Action: by default the action now installs quin-scanner from its own checkout, so the tag you pin selects the scanner version; it used to install the latest PyPI release whatever the tag. Inputs are passed to the shell through environment variables instead of string interpolation. Takes effect for a tag once a release moves it; `@v1` stays frozen at `v0.1.0b4`.
- The skills baseline loader accepts any version from 1 up to the current one (only 1 exists so far) and rejects a newer version with an error that says to upgrade, and a malformed version with its own message.
- `scan` and `scan-batch` now reject a local path that does not exist or is not a directory (exit 1, or a failed target in a batch) instead of scanning nothing and succeeding with an empty report, so a mistyped path no longer passes in CI.
- `scan-batch` and `scan-org` now exit 1 when at least one target (or repository) failed, after scanning all of them and writing the reports that succeeded, and print `N of M targets failed: ...` on stderr. Previously they exited 0 even if every target failed, which made them unusable in CI. The exit codes of every command are now listed in each command's `--help` and in `docs/stability.md`.
- Removed the `Typing :: Typed` classifier: the package ships no `py.typed` marker and CI runs no type checker.
- Removed two links to a project plan document that never existed from `CONTRIBUTING.md`.

### Fixed

- Windows: skill, MCP and instruction-file discovery found nothing because file paths used backslashes (repo-relative paths are now always `/`-separated, at the accessor boundary and again in the file index).
- Windows: cleaning up a cloned GitHub repository raised `PermissionError` on git's read-only files, so a scan of a GitHub URL failed at cleanup; temporary clones are now removed with a helper that handles read-only files.
- Windows: `C:\...`, `C:/...`, UNC (`\\server\share`) and `~` paths were not recognised as local paths (`C:/work/repo` was even read as an `owner/repo` shorthand).
- Windows: report file names were built from the whole target path, so `scan-batch` and `scan -d` could not write reports for a local path; the name is now the last path component reduced to characters valid on every OS (this also changes names containing spaces or punctuation, which are now replaced by `_`).
- The `scan-batch` targets file is read as UTF-8 and tolerates a BOM and CRLF line endings; the Git askpass helper is written with LF line endings and a securely created temporary file.
- Reproducible results: the same repository could produce different agents and tools on different machines. File listings are now sorted, scanner results are merged in a fixed order rather than thread-completion order, and on equal confidence the specific scanner (for example agent instances) wins over the generic code-pattern scanner when both report the same location. Capped lists (50 agents, 100 tools) therefore keep the same items everywhere.

---

## [0.1.0b5] — 2026-10-26

**Fixes, a security update and release-process changes.** There is still no stable release.

- **Security:** `anthropic` requirement raised to `>=0.87,<1` (locked 0.125.0), closing two advisories in the SDK's local memory tool.
- **Fix:** the default LLM model is now chosen per provider. `--llm-provider anthropic`, `google` or `ollama` without `--llm-model` previously sent `gpt-4o-mini` to that provider's API.
- **Releases:** pre-release tags move a `beta` tag instead of `v1`; Action examples use `@beta`.

### Fixed

- The default LLM model is now chosen per provider. Previously `ScannerConfig.llm_model` defaulted to `gpt-4o-mini` for every provider, so `--llm-provider anthropic`, `google` or `ollama` without `--llm-model` (or a config file with no `llm.model`) sent `gpt-4o-mini` to that provider's API and failed. `llm_model` is now unset by default and resolved through `ScannerConfig.resolved_model()`: the configured model, else `claude-haiku-4-5-20251001` (anthropic), `gemini-2.0-flash` (google), `llama3.2` (ollama) or `gpt-4o-mini` (openai, and OpenAI-compatible endpoints as before).

### Changed

- Release tags: pre-release tags (`v0.1.0b4`, `...rc1`) now move a new `beta` tag and no longer move `v1`. Stable tags move a major tag (`v0` for 0.x, `v1` for 1.x). `v1` stays at `v0.1.0b4` until `1.0.0` is released. GitHub Action examples now use `@beta`; pin an exact tag such as `@v0.1.0b4` for reproducible builds.
- Docs no longer imply a stable `0.1.0` exists: the changelog section for the first drop is now `0.1.0b1`, and the roadmap marks the first drop as beta.

### Security

- Raised the `anthropic` requirement to `>=0.87,<1` (locked at 0.125.0). 0.87.0 fixes two medium advisories in the SDK's local memory tool (insecure default file permissions and a path-validation race); Quin does not use that tool, but the floor ensures installs get the fixed SDK. The `<1` cap is deliberate: 2.x removed `temperature` from `messages.create()` and changed its HTTP layer and auth headers, so it needs its own change and a live check.

### Maintenance

- CI now runs lint, tests, build and smoke test on Python 3.11, 3.12 and 3.13 (previously 3.11 only).
- Ruff's rule selection is explicit in `pyproject.toml` (`F`, `E4`, `E7`, `E9`), so CI and any local ruff version agree; CI uses the ruff version pinned in `uv.lock`.
- Added `.github/dependabot.yml`: weekly updates for Python dependencies (including `uv.lock`) and GitHub Actions, grouped to keep the number of PRs low.
- Added `tests/test_llm_providers.py`: key-free contract tests that run the Anthropic, Google, OpenAI and OpenAI-compatible providers through their real SDKs against mocked HTTP endpoints (request body, auth header, empty responses, `analyze_prompt`, API errors, and skills LLM review), so dependency bumps of the LLM SDKs are actually exercised by CI.
- The Anthropic provider now passes `temperature` via `extra_body`, because `anthropic` 2.x removed it from `messages.create()`; the request sent is unchanged and works on both SDK lines.

## [0.1.0b4] — 2026-10-25

**Agent Skills security scanning.** Quin now scans Agent Skills, MCP tool definitions and agent instruction files for prompt injection, hidden content, exfiltration, dangerous code, supply-chain risk and excessive permissions, scores each skill (SAFE / CAUTION / HIGH_RISK), and can check a skill before you install it:

- `skills` scanner, on by default in `quin-scanner scan` (see [docs/skills-scanning.md](docs/skills-scanning.md) and [docs/skill-rules.md](docs/skill-rules.md)).
- `quin-scanner skills scan <folder|zip|url>` for pre-install checks, with `--fail-on` exit codes, JSON and SARIF output, and hardened zip extraction.
- `quin-scanner skills baseline` and `--baseline` / `scan --skills-baseline` to accept reviewed findings and report only new ones.
- Optional LLM review that confirms or disputes findings (never downgrades critical, AST or taint findings).
- OSV lookups for exact-pinned PyPI and npm skill dependencies, and a bounded shared read cache that reduces repeated file fetches for hosted scans.
- Noise tuning against 532 public skills (`docs/skill-scanner-tuning-2026-10.md`).

This changelog was not split per beta, so the sections below also list changes first shipped in 0.1.0b1–b3.

### Added

#### Skills Security Scanner
- New `skills` scanner (on by default): discovers Agent Skills (`SKILL.md` packages, including `.claude/skills`, `.codex/skills`, `.opencode/skill(s)`) and MCP tool definitions, and assesses each for prompt injection, hidden Unicode/HTML-comment instructions, credential access and exfiltration, dangerous code (Python AST and taint tracking), supply-chain risk (unpinned/typosquatted dependencies, optional OSV lookup), excessive `allowed-tools`, description/capability mismatch, and MCP tool-description poisoning. Rules are listed in `docs/skill-rules.md`.
- Report gains a `skills` array: per skill a record, findings (rule, severity, `file:line`, redacted evidence, taxonomy threat) and a deterministic 0–100 risk score with a SAFE / CAUTION / HIGH_RISK verdict. The HTML report shows per-skill risk cards; the CLI prints a verdict summary to stderr.
- High and critical findings are promoted into `risk_signals`, so they appear in SARIF output with file and line locations.
- Optional LLM review (skipped with `--no-llm`) confirms or disputes findings and explains them; disputed findings count at half weight and are not promoted. It sends only flagged evidence snippets and fails soft.
- Coverage gains `skills_capped`, the number of times a limit was hit (skill cap, per-skill file cap, MCP source read cap, OSV lookup cap); the details are in `metadata.skills_notes`.
- Skill artifacts use confidence 0.45, so a repository containing only skills is not by itself classified as an AI application.
- New `quin-scanner skills scan <target>` command for a pre-install check of a skill folder, `.zip` file or GitHub/Azure DevOps URL. Runs only the skills scanner; static unless an LLM option is given. Output `--output terminal|json|sarif` (terminal: per-skill verdicts plus findings with `file:line`; JSON: `{target, scanned_at, skills, notes, coverage}`; SARIF: same rules and locations as `scan`), `-f/--output-file`. Exit `0` (below `--fail-on`), `1` (any skill at or above `--fail-on caution|high_risk`, default `high_risk`), `2` (error). Zip files are extracted safely into a temporary directory (at most 5000 members and 200 MB, no absolute paths, `..` or symlinks) and removed afterwards.
- Skills baseline: `quin-scanner skills baseline <target> -o FILE` writes every current skill finding (static, no LLM; `--force` to overwrite) as a YAML list of fingerprints (`version: 1`, `generated`, `entries` of `{fingerprint, rule_id, skill, file_path, note}`; no raw evidence). `skills scan --baseline FILE` and `scan --skills-baseline FILE` drop matching findings before LLM review, scoring, promotion and output, so later scans report only new findings. Fingerprints are `sha256(rule_id | skill | file_path | evidence)` with whitespace collapsed and no line number, so edits elsewhere in a file keep them valid. The result is recorded as `metadata.skills_baseline` (`file`, `suppressed_count`, `stale_count`) and printed as `Baseline: N finding(s) suppressed, M stale entries`. Stale entries are counted, not errors; a missing or malformed baseline file exits `2`.
- Instruction-file scanning: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` (any depth), `.cursorrules`, `.windsurfrules`, `.clinerules` (file or directory of Markdown), `.cursor/rules/**/*.md|.mdc`, `.github/copilot-instructions.md`, `.github/instructions/*.md` and `.roo/rules*/` Markdown are grouped into one "Agent instruction files" record (ecosystem `instructions`) checked with the text rules only. It is listed on its own line (`Agent instruction files: <verdict> <score>`) and as an HTML card, counts for `--fail-on` and baselines, and is not counted in `coverage.skills_found`; new `coverage.skills_instruction_files` holds the number of files analysed. `.mdc` and the extensionless rules files are now read as Markdown.

#### LLM Inference Endpoint Detection
- New `llm_endpoints` list in the report (all scans): the address of each LLM inference endpoint found in code (`base_url=`, `api_base=`, `azure_endpoint=`, hosted-provider URLs, `/chat/completions`-style paths), config files (YAML/JSON/TOML keys in LLM-related blocks) and `.env` files. Each entry has a `kind` (`hosted_provider`, `local`, `private`, `remote`, `unresolved`), the setting it came from, and file/line. Addresses built from config (e.g. `f"{cfg['url']}/v1"`) are resolved to the config value where possible.
- Credentials are always omitted: URL userinfo (`user:pass@`) and secret-like query parameters (`api_key`, `token`, `password`, ...) are redacted before anything is stored.
- HTML report: new "Inference Endpoints" table at the top of the Models tab.
- Precision guards: build output (`.next`, `.nuxt`, `coverage`, ...), minified files and very long lines are skipped; generic `base_url`/`api_url` kwargs only count with LLM context within three lines; function signatures and pass-through variables are ignored; `/messages`-style paths must be `/v1/...`.

#### Aegis Governed-Agent Detection (opt-in)
- `--detect-aegis` flag on `scan`, `scan-batch` and `scan-org` (or `governance.detect_aegis: true` in the config file). Off by default; without it scan output is unchanged.
- New `AegisScanner` (rules in `rules/aegis.yaml`) detects Aegis SDK dependencies (`aegis-core`, `aegis-<framework>`, `aegis-secret-manager-*`, `aegis-openclaw-plugin`), imports, integration calls (`aegis_initialize`, `AegisBaseTool`, `AegisFunctionMiddleware`, ...), OpenClaw/Pi/Claude hook markers, and `aegis:` engine config.
- Report gains a `governance` object (`status`: `governed` | `declared_only` | `ungoverned` | `not_applicable`, plus evidence). Aegis evidence is kept out of `artifacts`, so AI-detection and confidence are unaffected.

#### Scan Options in Report
- The report shows the CLI flags the scan was run with (`--no-llm`, `--no-vuln-check`, `--detect-aegis`, `--llm-provider`, `--min-confidence`, ...) in a "Scan options" strip and in `metadata.scan_options.flags`. Secrets are never listed; `--openai-compatible-url` is shown without its value and `--config` shows only the file name.

#### Report UI: Aegis Governance, Standardised Artifact Types, Artifact Filters
- HTML report shows a "Governed by Aegis" / "Not governed by Aegis" card (with the Aegis artifact count) when `--detect-aegis` is used, and the evidence rows are merged into the Artifacts tab, tagged `aegis-governed:<kind>`.
- Artifacts tab gains a standardised **Type** column (LLM API, Agent framework, Agent, Tool, Prompt template, RAG & embeddings, Memory, MCP, Infra & config, Aegis governance), filter chips with counts, and a text search. Types are display-only, defined in `rules/artifact_types.yaml`; scanner categories and capability tags in JSON/YAML/SARIF output are unchanged.
- "About Aegis" panel (opened from the governance card): Aegis as an Agentic AI security platform with runtime enforcement, what it does, the drop-in integration for the detected framework, and links to gaincontrol.ai.
- When Aegis detection is off (no `--detect-aegis`) and an AI application is found, the report shows a short Aegis promo with a hint to re-run with `--detect-aegis`.

#### Risk Signal Data Model
- `RiskIndicator.threat_id` — new optional field (`str | None`) identifying the originating threat (e.g. `"T001"`) per risk signal. Additive / backward-compatible: `to_dict()` includes the field, consumers that don't read it are unaffected. Enables downstream reports and UIs to link each signal to its threat in the taxonomy.
- LLM synthesis prompt updated to emit `threat_id` alongside each KRI in `risk_signals` (both repo-level and per-agent). Parser in `_parse_risk_signals` extracts the field; legacy string-format signals yield `threat_id=None`.
- Hardcoded CVE/vulnerability risk signal in the orchestrator now carries `threat_id="T003"` (AI Supply Chain Compromise).

#### Risk Framework Documentation
- `docs/risk-framework.md` — generated reference documenting all 14 threats (T001–T014) and 14 controls (C001–C014) with description, rationale, key risk indicators, attack patterns, implementation guidance, common pitfalls, and sourced external references. Grounded in OWASP LLM Top 10, OWASP Agentic AI Top 10, OWASP MCP Top 10, OWASP MAESTRO, and Databricks DASF.
- `src/quin_scanner/rules/risk_taxonomy.yaml` — extended with prose fields (`description`, `why_it_matters`, `attack_patterns`, `external_refs` on threats; `description`, `why_it_matters`, `how_to_implement`, `common_pitfalls`, `external_refs` on controls). YAML is the single source of truth — the MD is generated.
- `scripts/generate_risk_framework_docs.py` — Jinja2-based generator with `--check` drift-gate flag suitable for CI. Template at `scripts/templates/risk-framework.md.j2`.
- `src/quin_scanner/risk_taxonomy.py` — loader extended to surface the new prose fields via `ExternalRef`, `Threat`, and `Control` dataclasses (all new fields default-populated so existing consumers are unaffected).
- `tests/test_risk_framework_docs.py` — drift, completeness, and referential-integrity tests: the on-disk MD must match what the generator produces, every T0NN/C0NN must have stable `t0NN`/`c0NN` anchors, every threat's `recommended_controls` must resolve to a real control, and every external ref must have a title and an http(s) URL.

#### HTML Report Deep-Links to Risk Framework
- `html_template.py` — control labels rendered inside risk signals (e.g. `C003: Access Control & Least Privilege`) are now clickable links that open `docs/risk-framework.md#c003` on GitHub. Each risk signal with a known `threat_id` renders a small `↗` icon linking to the matching `#t0NN` anchor. All external links use `target="_blank" rel="noopener"` to avoid reverse-tabnabbing. The click handler was refactored to ignore clicks on deep-link anchors so the row-toggle behavior still works for the rest of the signal.

#### Scanner Plugins (+2, now 13 total)
- `tool_definition` — extracts named tool definitions from code via `@tool`, `@function_tool`, `@register_tool`, `@kernel_function`, `@register_function` decorators, `BaseTool` / `StructuredTool` class inheritance, tool registration calls (`register_tool()`, `server.tool()`), and Markdown tool-definition tables
- `agent_instance` — extracts named agent instantiations from code (`Agent(name=...)`, `AssistantAgent`, `UserProxyAgent`, `ConversableAgent`, etc.) and YAML/JSON agent config files

#### Risk Taxonomy & Classification
- `risk_taxonomy.yaml` — structured threat catalog sourced from OWASP LLM Top 10, OWASP Agentic Top 10, OWASP MCP Top 10, MAESTRO, and Databricks DASF
- `risk_taxonomy.py` — loader and query interface for the threat taxonomy
- `classification_agent.py` — LLM Pass 1 that classifies system type (`standard_ai`, `agentic_ai`, `mcp_enabled`, `multi_agent`) and identifies relevant threats from the taxonomy
- `RiskIndicator` dataclass — pairs a key risk indicator signal with its recommended controls
- `ClassificationResult` dataclass — captures system types and relevant threat IDs
- Repo-level `risk_signals` field on `SynthesisResult` and `ScanReport`

#### External Service Detection
- `tool_services.yaml` — maps high-signal packages to service categories: web search, web browsing, code execution, database access, file system, email, and more
- `ToolUsage` now includes `tool_type` (tool_definition / external_service / skill / mcp_tool) and `service_category`

#### Signal Groups
- `signal_groups.yaml` — cross-scanner framework corroboration rules that boost confidence when multiple co-occurring signals appear (e.g. OpenClaw: `SOUL.md` + `AGENTS.md` + `openclaw.json`)

#### HTML Report Output
- `html_template.py` — self-contained HTML report template with embedded JS dashboard
- `--format html` output option via `ReportGenerator.to_html()`

#### Detection Rules (expanded)
- New entries in `code_patterns.yaml`, `dependencies.yaml`, `file_markers.yaml`, `frameworks.yaml`, and `frameworks_lookup.yaml`

### Changed
- `findings` field renamed to `artifacts` in `ScanReport` output
- `risk_signals` on `AgentProfile` changed from `list[str]` to `list[RiskIndicator]` (now includes recommended controls)
- CLI help text and option descriptions overhauled for all scan commands
- Orchestrator expanded with two-pass LLM pipeline (classification → synthesis)
- Skills scanner noise tuning, based on scans of eight public skill repositories (see `docs/skill-scanner-tuning-2026-10.md`):
  - `SK-AR-002` (act without confirmation) is now `low`.
  - `SK-EX-002` (curl/wget upload) has confidence 0.4 and skips lines whose URLs all point at `api.anthropic.com`, `api.openai.com`, `api.github.com`, `generativelanguage.googleapis.com`, `localhost` or `127.0.0.1`. Its short flags are case-sensitive and curl-only (`curl -f`, `curl -D` and `wget -T` are no longer uploads); `wget --post-data/--post-file/--body-*` and PowerShell `-Method Post`/`-InFile` are now recognised.
  - Negatable rules treat a match inside a quoted list introduced by "avoid", "don't use", "instead of" and similar guidance (`avoid override-style language ("ignore …", "disregard …")`), and a line that starts with an anti-pattern marker (`❌`, `BAD:`), as negated. "does not", "cannot" and "won't" count as negations.
  - `SK-PI-004` ignores "do not tell the user to …" / "… they need …" (the agent is told to act, not to conceal); `SK-SL-001` no longer matches across a comma.
  - `SK-EX-001` and `SK-PERM-005` ignore public keys (`~/.ssh/*.pub`, `id_rsa.pub`); `SK-EXEC-002` flags home-directory targets only for the home directory or one entry directly under it (`~`, `~/*`, `~/.ssh`), not deeper paths such as `~/.tool/cache/x`.
  - `SK-PERM-004` counts `requests` only as the Python library (`import requests`, `requests.get`), not the English word.
  - `SK-SC-005` stops reading `pip install` arguments at a bracket or sentence break (prose after `pip install -r requirements.txt)` was reported as packages) and reports each unpinned package once per file.
- `SK-SC-006` (known vulnerability) also covers npm: `package.json` `dependencies`, `devDependencies` and `optionalDependencies` pinned to an exact version (`1.2.3`, `=1.2.3`, `v1.2.3`) are looked up in OSV with ecosystem `npm` (scoped names as written). PyPI and npm share the 50-lookup cap, the `skills_osv_lookup_errors` soft-fail counter and `--no-vuln-check`.
- Scanners now share a bounded read cache (1 MB per file, 50 MB per scan, failed reads never cached), so a file read by several scanners, the skills MCP/instruction-file discovery, the model/endpoint identifiers and the file fingerprint is fetched from the repository once. GitHub-hosted scans make correspondingly fewer API calls (anthropics/skills: 1008 to 262 file reads). Coverage counters are unchanged (`file_read_attempts` still counts every scanner read); cache hits and cached bytes are reported in `metadata.read_cache`.

### Fixed
- Removed compiled Python bytecache files (`.pyc`) from repository
- Skills scanner false positives found on a scan of 68 installed personal skills (see the follow-up in `docs/skill-scanner-tuning-2026-10.md`):
  - Negatable rules (such as `SK-PI-001`) in Markdown and text skip a quoted phrase that the sentence introduces as a mention of content ("if the export contains …", "a page that says …", "such as", "e.g.", "phrases like"), e.g. `If the export contains text addressed to you — "ignore previous instructions," …`. Imperative forms (`Say "…"`), sentences with an output verb before the quote (`reply:`, `write`, `add`) and unquoted overrides still fire.
  - A sentence wrapped across two lines keeps its mention cue for the quoted-mention rule (the previous line of the same paragraph is considered), and `SK-PI-004` no longer matches across a `:` or `;` ("do not silently fetch: tell the user …" is not concealment).
  - `SK-EX-001` skips lines that define a regex or path denylist (`String.raw` templates, `new RegExp(`, `re.compile(`, `(?:` / `[^` syntax), such as a hook's `id_rsa` sensitive-path pattern. Text rules gain an optional `skip_patterns` attribute for this.
  - `SK-SC-001` no longer reports bounded ranges: a requirement with a lower and an upper bound (`requests>=2.32.4,<3.0.0`) or `~=` is not unpinned. In `package.json` an open lower bound (`>=1`) is now reported alongside `*`, `latest` and `""`; caret and tilde ranges are not. OSV lookups still cover exact pins only.

### Maintenance
- `pyproject.toml` — added `jinja2>=3.1` to the `dev` extra (used only by the risk-framework doc generator; not a runtime dependency).
- Updated dependency versions in `pyproject.toml`
- Updated scanner configuration defaults in `scanner-config.yaml`
- PyPI publish workflow switched to OIDC authentication with `contents: read` permission
- Updated project branding, repository URL, and company information in README
- Removed testing documentation and references from project files

---

## [0.1.0b1] — 2026-04-30

**Drop 1 — Scan Any Repo for AI** (the first public beta; a stable `0.1.0` has not been released yet)

### Added

#### Scan Modes
- `scan` command — scan a local folder or GitHub repo URL
- `scan-org` command — scan all repos in a GitHub org sequentially
- `scan-batch` command — scan multiple targets from a file
- `GitHubAPIAccessor` — shallow-clone any GitHub repo URL via REST API
- `GitHubMCPAccessor` — MCP-based accessor for interactive use
- `RepoAccessorFactory` — auto-selects accessor from target string (local path vs GitHub URL)
- `--github-token` flag and `GITHUB_TOKEN` env var for GitHub PAT authentication
- `--skip-archived` and `--skip-forks` flags on `scan-org`

#### Scanner Plugins (11 total)
- `dependency` — AI packages in requirements.txt, pyproject.toml, package.json, go.mod, Cargo.toml, pom.xml, build.gradle
- `code_pattern` — AI imports and API calls in .py, .js, .ts, .go, .rs, .java
- `config` — AI API keys in .env and config files
- `file_structure` — AI-related directories (prompts/, agents/, chains/, vector_store/)
- `framework` — framework config files (langgraph.json, crew.yaml, .mcp.json, dify.yaml, and 10+ more)
- `prompt_discovery` — system prompts from Python strings, YAML, .prompt, .jinja2, .mustache
- `dockerfile` — AI base images and pip installs in Dockerfile and docker-compose
- `jupyter` — AI imports and prompts in Jupyter notebooks (.ipynb)
- `ci` — AI API keys and installs in GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, Jenkins
- `iac` — AI services in Terraform (.tf) and Kubernetes/Helm YAML
- `mcp` — MCP server configs (.mcp.json, claude_desktop_config.json, cline settings, etc.)

#### Framework Detection (23+ frameworks)
- LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK
- **New**: Anthropic Agent SDK (`claude-agent-sdk`)
- **New**: Google ADK (`google-adk`)
- **New**: Databricks Agent Framework (`databricks-agents`)
- LlamaIndex, Haystack, Semantic Kernel, Dify, Flowise, PromptFlow, Vercel AI SDK, MCP

#### LLM Model Identification
- `model_identifier.py` — detects LLM model names from code, config files, and env vars
- Identifies provider (openai, anthropic, google, meta, mistral, cohere, aws, databricks)
- Detects primary/fallback routing patterns from YAML config and code structures
- `rules/models.yaml` — known model name registry across all major providers
- `ModelUsage` dataclass with provider, model_name, source, file_path, line_number, role
- `model_usages` section added to `ScanReport` output

#### LLM Providers (5 total)
- OpenAI (`openai`) — default model: `gpt-4o-mini`
- Anthropic (`anthropic`) — default model: `claude-haiku-4-5-20251001`
- Google (`google`) — default model: `gemini-2.0-flash`
- Ollama (`ollama`) — default model: `llama3.2`
- **New**: OpenAI-compatible (`openai-compatible`) — any endpoint implementing the OpenAI chat API (vLLM, LiteLLM, Azure OpenAI, AWS Bedrock via gateway, LocalAI)
- `--openai-compatible-url` flag for base URL configuration

#### Output & Configuration
- JSON and YAML output formats
- `--no-llm` flag — run all 11 scanners without LLM calls
- `--output-file` flag — write report to file instead of stdout
- `--config` flag — load settings from `scanner-config.yaml`
- `--branch` flag — specify git branch for GitHub URL scans

#### Detection Rules
- `dependencies.yaml` — 100+ AI packages across PyPI, npm, Go, crates.io, Maven
- `code_patterns.yaml` — 60+ regex patterns across Python, JS, TS, Go, Rust, Java
- `file_markers.yaml` — AI-related directory and file extension markers
- `frameworks.yaml` — 23+ framework config file signatures
- `models.yaml` — known LLM model names by provider

#### 12 Capability Tags
`llm-api` · `embeddings` · `rag` · `tool-use` · `multi-agent` · `memory` · `prompt-templates` · `fine-tuning` · `image-gen` · `voice-ai` · `code-gen` · `orchestration`

---

[Unreleased]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/compare/v1.0.0rc2...HEAD
[1.0.0rc2]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/releases/tag/v1.0.0rc2
[1.0.0rc1]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/releases/tag/v1.0.0rc1
[0.1.0b5]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/releases/tag/v0.1.0b5
[0.1.0b4]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/releases/tag/v0.1.0b4
[0.1.0b1]: https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/releases/tag/v0.1.0b1
