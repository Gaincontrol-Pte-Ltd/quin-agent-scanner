# Stability and Support Policy

> **Status:** this policy takes effect with `1.0.0`. Until then Quin is a beta and any surface below may change between releases. Items marked *(planned)* are delivered before 1.0; everything else describes today's behaviour.

Quin follows [Semantic Versioning 2.0](https://semver.org/) for the stable surfaces listed here. Everything else is internal and may change in any release.

## Stable surfaces

| Surface | What is covered |
|---|---|
| **CLI** | The commands and options listed below, their defaults and their exit codes. |
| **Report schema** | The JSON and YAML report (`quin-scanner scan -o json\|yaml`) and the JSON envelope of `quin-scanner skills scan -o json`: field names, types and meaning. See [schema/README.md](schema/README.md). |
| **SARIF and rule IDs** | SARIF output (SARIF 2.1.0) and the identifiers in it: skill rule IDs (`SK-…`) and threat IDs (`T001`–`T014`). |
| **Config, baseline and Action** | The `scanner-config.yaml` keys, the skills baseline file format, and the inputs and outputs of the GitHub Action. |

## Not covered

- The **Python import API**: `import quin_scanner` internals are private. The CLI is the supported interface.
- The **web UI** in `ui/`: experimental and not published.
- The **HTML report**: its layout and markup are for people and may change; machines should read the JSON/YAML report or SARIF.
- **Human-readable terminal output** (tables, summaries, progress on stderr). Use `-o json` or `-o sarif` for automation.
- Undocumented keys inside the open maps `metadata` and `coverage`, and the text of evidence snippets, LLM-written summaries and messages.

## What counts as a breaking change

Breaking changes need a new **major** version, and a [deprecation](#deprecation) first:

- removing or renaming a command, option or config key, or changing a default so that existing invocations behave differently;
- changing the meaning of an exit code;
- removing or renaming a report field, or changing its type or meaning;
- removing or renaming a rule ID or threat ID, or changing what it detects in kind;
- changing the baseline file format incompatibly, or its fingerprint algorithm;
- removing a GitHub Action input or output, or changing its meaning.

**Not breaking** (allowed in minor and patch releases): adding commands, options, config keys, report fields, rules, Action inputs or outputs; changing the order of list items, whitespace, evidence text or messages; fixing a bug where the old behaviour contradicted the documentation; and [detection changes](#detection-changes).

## Detection changes

Detection improves over time. A rule becoming more or less sensitive can move a skill's verdict or score, or add or remove findings. That is **not** a breaking change, but it is never silent:

- the CHANGELOG lists it under a **Detection changes** heading;
- the pull request updates the quality-corpus snapshots (`tests/corpus/expected/`, produced by `scripts/run_corpus.py --update`) so reviewers see exactly which skills and repositories moved, and CI fails if a rule or scanner change moves a snapshot without updating it, or updates it without a CHANGELOG entry;
- the [baseline](../README.md#scan-a-skill-before-installing-it) lets you accept existing findings so only new ones fail a build.

## Deprecation

A deprecated item keeps working. It is announced in the CHANGELOG and listed here, emits a warning on stderr where it is used (CLI options, config keys), and stays for **at least one minor release and 90 days** before it is removed in the next major version.

## Rule and threat IDs

IDs are identifiers, not descriptions: an ID is **never reused** for something different. A test fails if a rule ID that existed at 1.0 disappears without being listed as retired, if a retired ID is emitted again, or if a threat or control ID is removed or renamed. A rule that is removed is **retired**: its ID stays reserved and is listed in [skill-rules.md](skill-rules.md#retired-rules). Severities and confidence of a rule may be tuned in minor releases (see detection changes).

## Report schema versioning

Reports and the `skills scan` JSON envelope carry a `schema_version` of the form `MAJOR.MINOR`; `quin-scanner --version` prints the current one. JSON Schemas are published in `docs/schema/`, and CI validates real output against them and checks every schema change against a frozen 1.0 baseline. Within a major version the schema only grows: new optional fields may appear, existing ones keep their name, type and meaning. A breaking schema change needs a new major schema version and a new major tool version. Consumers should ignore fields they do not know. See [schema/README.md](schema/README.md).

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `scan` | the scan completed (findings do not change the exit code) | invalid target, or the scan failed | invalid `--skills-baseline`, invalid config file, or a command-line usage error |
| `scan-batch` | every target was scanned | at least one target failed (reports for the others are still written) | invalid config file, or usage error such as a missing targets file |
| `scan-org` | every repository was scanned | the repository list could not be fetched, or at least one repository failed | invalid config file, or usage error |
| `skills scan` | no skill at or above `--fail-on` (default `high_risk`) | at least one skill at or above `--fail-on` | error (bad target, unreadable or unsafe zip, bad config or baseline), or usage error |
| `skills baseline` | baseline written | | error, or usage error |

## Command output

Machine-readable results go to a file or to stdout; progress, warnings and errors go to stderr.

- `scan` writes one report file: to `-f/--output-file`, otherwise into `-d/--output-dir` (default `./report`) with a generated name.
- `scan-batch` and `scan-org` write one report file per target into `--output-dir`. `scan-org` also prints a JSON list to stdout with one object per scanned repository: `repo`, `is_ai_application`, `confidence`.
- `skills scan` prints to stdout (the terminal table, or JSON/SARIF with `-o`) unless `-f` is given.
- `skills baseline` writes the baseline file given with `-o`.

## Commands

<!-- cli-commands:start -->
- `quin-scanner scan`: scan one repository (local path, GitHub or Azure DevOps URL, or `owner/repo`)
- `quin-scanner scan-batch`: scan every target listed in a file
- `quin-scanner scan-org`: scan every repository of a GitHub organization or user
- `quin-scanner skills scan`: check Agent Skills on their own, before installing them
- `quin-scanner skills baseline`: accept the current skill findings so only new ones are reported
<!-- cli-commands:end -->

The command tree, every option, its default and its type are pinned by `tests/cli_snapshot.json`, and compatibility with the 1.0 baseline is checked by `tests/test_cli_snapshot.py`. Defaults that are part of the contract: `scan --output html`, `--output-dir ./report`, `--branch main`, `--min-confidence 0.0`; `skills scan --output terminal`, `--fail-on high_risk`.

## Config and baseline files

- **`scanner-config.yaml`** keys: `llm` (`provider`, `model`, `api_key_env`, `api_key`), `output` (`format`, `max_repo_risk_signals`), `vuln_check` (`enabled`, `search_provider`, `search_model`, `osv_timeout_seconds`, `web_timeout_seconds`, `web_retries`), `scanners.enabled`, `governance.detect_aegis`. An optional `config_version` key (default `1`): a file with a newer `config_version` than the installed release understands is rejected with an error that says to upgrade. Unknown keys are ignored with a warning on stderr, so a typo is visible. A missing, unreadable or invalid config file exits 2.
- **Skills baseline** (`quin-scanner skills baseline`): `version: 1`, `generated`, `entries` of `fingerprint`, `rule_id`, `skill`, `file_path`, `note`. A baseline written by any 1.x release keeps working in later 1.x releases; a baseline with a newer `version` than the tool understands is rejected with an error that says to upgrade. The fingerprint algorithm is pinned by a test, and a frozen baseline file proves old baselines keep loading.

## GitHub Action

Inputs and outputs are part of the contract; new inputs are always optional with a default.

<!-- action-inputs:start -->
| Input | Default | Meaning |
|---|---|---|
| `llm-provider` | `''` | LLM provider; only used when `llm-api-key` is set. |
| `llm-api-key` | `''` | API key; setting it enables LLM analysis, empty runs static analysis only. |
| `llm-model` | `''` | Model override for the provider. |
| `min-confidence` | `'0.0'` | Exclude artifacts below this confidence. |
| `path` | `'.'` | Directory to scan, relative to the workspace. |
| `skills-baseline` | `''` | Skills baseline file; matching skill findings are suppressed. |
| `fail-on` | `'none'` | Fail the job at or above this skill verdict: `none`, `caution` or `high_risk`. Checked after the SARIF upload. |
| `upload-sarif` | `'true'` | Upload the SARIF file to code scanning. |
| `output-report` | `'false'` | Also write the full JSON report (a second scan). |
| `version` | `''` | Empty installs the scanner from the action's own checkout (the pinned tag selects the version); a bare version or pip specifier installs from PyPI. |
| `python-version` | `'3.11'` | Python used to run the scanner. |
<!-- action-inputs:end -->

<!-- action-outputs:start -->
| Output | Meaning |
|---|---|
| `sarif-path` | Path of the SARIF file. |
| `report-path` | Path of the JSON report; empty unless `output-report` is `true`. |
| `version` | The quin-scanner version that was run. |
<!-- action-outputs:end -->

**Versions and tags.** By default the action installs the scanner from the tag you pin, so `@v0.1.0b5` runs exactly 0.1.0b5. The `beta` tag follows pre-releases; from `1.0.0` a major tag (`v1`) follows stable releases. Pin an exact tag for reproducible builds. (The `v1` tag is frozen at `v0.1.0b4`, which predates this behaviour and installs the latest PyPI release.)

## Supported platforms and Python versions

CI runs the full test suite on **Linux, macOS and Windows**, each on Python 3.11, 3.12 and 3.13, and runs the GitHub Action on all three operating systems. Known limits: authenticated `git clone` of private repositories (the `GIT_ASKPASS` helper) is not exercised by CI on Windows, and on Windows paths longer than 260 characters need long-path support enabled in the operating system. Dropping a platform or Python version is announced one minor release ahead.

## Dependencies

The LLM providers use the vendor SDKs `openai`, `anthropic` and `google-genai`. Each has a tested range in `pyproject.toml`: the **floor** is the oldest version the provider contract tests pass on (with a current `httpx`), and the **ceiling** is the next major version after the one Quin is tested with. A new major SDK version is adopted only after the contract tests (`tests/test_llm_providers.py`) pass against it and a live call has been made.

<!-- sdk-ranges:start -->
| SDK | Range |
|---|---|
| `openai` | `>=1.55.3,<3` |
| `anthropic` | `>=0.87,<1` |
| `google-genai` | `>=1.15,<3` |
<!-- sdk-ranges:end -->

CI runs the whole test suite twice: on the locked (newest tested) versions, and on the **oldest allowed runtime versions** (every direct dependency resolved to its lowest allowed version). A floor is raised when the oldest version stops passing. The other runtime dependencies (`click>=8.2`, `pyyaml`, `httpx`, `python-dotenv`) have floors only.

## Supported platforms and Python versions

CI runs Python 3.11, 3.12 and 3.13. Linux is supported today; macOS and Windows support is *(planned for 1.0)* and will be tested in CI before it is promised. Dropping a platform or Python version is announced one minor release ahead.

## Dependencies

The LLM providers use the vendor SDKs `openai`, `anthropic` and `google-genai`. Each has a version range in `pyproject.toml`: an upper bound within the major version Quin has been tested with (today only `anthropic` has one; upper bounds for `openai` and `google-genai` are *(planned)*); a new major SDK version is adopted only after the provider contract tests (`tests/test_llm_providers.py`) pass against it and a live call has been made.

## Support

The latest 1.x release is supported. Security fixes go to the latest minor release and, for 90 days after a new minor is released, to the previous minor as well. Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
