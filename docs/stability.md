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
- the pull request updates the quality-corpus snapshot so reviewers can see exactly what moved *(planned)*;
- the [baseline](../README.md#scan-a-skill-before-installing-it) lets you accept existing findings so only new ones fail a build.

## Deprecation

A deprecated item keeps working. It is announced in the CHANGELOG and listed here, emits a warning on stderr where it is used (CLI options, config keys), and stays for **at least one minor release and 90 days** before it is removed in the next major version.

## Rule and threat IDs

IDs are identifiers, not descriptions: an ID is **never reused** for something different. A rule that is removed is **retired**: its ID stays reserved and is listed in [skill-rules.md](skill-rules.md#retired-rules). Severities and confidence of a rule may be tuned in minor releases (see detection changes).

## Report schema versioning

Reports and the `skills scan` JSON envelope carry a `schema_version` of the form `MAJOR.MINOR`; `quin-scanner --version` prints the current one. JSON Schemas are published in `docs/schema/`, and CI validates real output against them and checks every schema change against a frozen 1.0 baseline. Within a major version the schema only grows: new optional fields may appear, existing ones keep their name, type and meaning. A breaking schema change needs a new major schema version and a new major tool version. Consumers should ignore fields they do not know. See [schema/README.md](schema/README.md).

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `scan` | the scan completed (findings do not change the exit code) | invalid target, or the scan failed | invalid `--skills-baseline`, or a command-line usage error |
| `scan-batch` | the batch finished; per-target errors are reported on stderr *(planned: 1 if any target failed)* | | |
| `scan-org` | the organization scan finished | the repository list could not be fetched | |
| `skills scan` | no skill at or above `--fail-on` (default `high_risk`) | at least one skill at or above `--fail-on` | error (bad target, unreadable or unsafe zip, bad config or baseline), or usage error |
| `skills baseline` | baseline written | | error, or usage error |

## Commands

<!-- cli-commands:start -->
- `quin-scanner scan`: scan one repository (local path, GitHub or Azure DevOps URL, or `owner/repo`)
- `quin-scanner scan-batch`: scan every target listed in a file
- `quin-scanner scan-org`: scan every repository of a GitHub organization or user
- `quin-scanner skills scan`: check Agent Skills on their own, before installing them
- `quin-scanner skills baseline`: accept the current skill findings so only new ones are reported
<!-- cli-commands:end -->

Defaults that are part of the contract: `scan --output html`, `--output-dir ./report`, `--branch main`, `--min-confidence 0.0`; `skills scan --output terminal`, `--fail-on high_risk`.

## Config and baseline files

- **`scanner-config.yaml`** keys: `llm` (`provider`, `model`, `api_key_env`, `api_key`), `output` (`format`, `max_repo_risk_signals`), `vuln_check` (`enabled`, `search_provider`, `search_model`, `osv_timeout_seconds`, `web_timeout_seconds`, `web_retries`), `scanners.enabled`, `governance.detect_aegis`. An optional `config_version` key *(planned)*; when absent it means `1`.
- **Skills baseline** (`quin-scanner skills baseline`): `version: 1`, `generated`, `entries` of `fingerprint`, `rule_id`, `skill`, `file_path`, `note`. A baseline written by any 1.x release keeps working in later 1.x releases; a baseline with a newer `version` than the tool understands is rejected with a clear error.

## GitHub Action

Inputs today: `llm-provider`, `llm-api-key`, `llm-model`, `min-confidence`. *(Planned for 1.0: inputs `skills-baseline`, `fail-on`, `path` and `version`; outputs `report-path` and `sarif-path`.)* Pin the action to an exact tag for reproducible builds; the `beta` tag follows pre-releases and, from 1.0.0, a major tag (`v1`) follows stable releases.

## Supported platforms and Python versions

CI runs Python 3.11, 3.12 and 3.13. Linux is supported today; macOS and Windows support is *(planned for 1.0)* and will be tested in CI before it is promised. Dropping a platform or Python version is announced one minor release ahead.

## Dependencies

The LLM providers use the vendor SDKs `openai`, `anthropic` and `google-genai`. Each has a version range in `pyproject.toml`: an upper bound within the major version Quin has been tested with (today only `anthropic` has one; upper bounds for `openai` and `google-genai` are *(planned)*); a new major SDK version is adopted only after the provider contract tests (`tests/test_llm_providers.py`) pass against it and a live call has been made.

## Support

The latest 1.x release is supported. Security fixes go to the latest minor release and, for 90 days after a new minor is released, to the previous minor as well. Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
