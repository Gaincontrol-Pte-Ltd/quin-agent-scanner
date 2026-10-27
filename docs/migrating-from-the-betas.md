# Migrating from the 0.1 betas to 1.0

This page is for anyone running `0.1.0b5` or earlier. Most setups keep working unchanged. The changes below are the ones that can make an existing pipeline, script or Action step behave differently. Each says who is affected and what to do. The full list is in the [CHANGELOG](../CHANGELOG.md).

From 1.0 the CLI, the report schema, rule IDs and the config, baseline and Action interfaces are stable and follow the [stability policy](stability.md), so this is the last migration of this kind.

## Changes that can break an existing setup

| Change | Who is affected | What to do |
|---|---|---|
| **`scan-batch` and `scan-org` exit 1 when any target fails.** They used to exit 0 even if every target failed. They still scan everything, write the reports that succeeded, and print `N of M targets failed: ...` on stderr. | CI jobs that run `scan-batch` or `scan-org` | Expect a failing job where failures were silent before. Fix the failing targets, or tolerate the exit code deliberately (`\|\| true`). |
| **`scan` and `scan-batch` reject a local path that does not exist or is not a directory** (exit 1, or a failed target in a batch). They used to scan nothing and succeed with an empty report. | Scripts with a mistyped or generated path | Correct the path. |
| **An invalid, unreadable or too-new config file exits 2** in `scan`, `scan-batch` and `scan-org`. A config with a `config_version` newer than the installed release is rejected with a message to upgrade. | Anyone passing `-c scanner-config.yaml` | Fix the file. `config_version` is optional and defaults to 1. |
| **Unknown config keys print a warning on stderr** instead of being ignored silently. | Config files with typos or leftover keys | Remove or correct the key. The warning does not change the exit code. |
| **Report file names for local paths are built from the last path component**, with anything other than letters, digits, `.`, `_` and `-` replaced by `_` (for example `my project` becomes `my_project`). | Scripts that look for a report by name | Use `-f FILE` for a fixed name, or match the new pattern `<name>_<YYYYMMDD_HHMMSS>.<format>`. |
| **JSON and YAML reports, and the `skills scan -o json` envelope, carry `schema_version`** (`"1.0"`). `quin-scanner --version` prints it. | Parsers of the report | Nothing, unless a parser rejects unknown fields. Within a major schema version the schema only grows; see [schema/README.md](schema/README.md). |
| **The GitHub Action installs the scanner from the tag you pin**, not the latest PyPI release. `@v0.1.0b5` runs 0.1.0b5; `@beta` follows the latest pre-release; from 1.0, `@v1` follows stable releases. | Workflows using `Gaincontrol-Pte-Ltd/quin-agent-scanner@...` | Pin the tag you want. Set the `version` input to install a specific release or range from PyPI instead. |
| **New Action inputs and outputs**: inputs `path`, `skills-baseline`, `fail-on`, `upload-sarif`, `output-report`, `version`, `python-version`; outputs `sarif-path`, `report-path`, `version`. Every input is optional and defaults to the old behavior (`fail-on` defaults to `none`). | Nobody, unless you want them | Opt in as needed. |
| **Dependency ranges now match what is tested**: `click>=8.2`, `openai>=1.55.3,<3`, `google-genai>=1.15,<3`, `httpx>=0.28.1`, `anthropic>=0.87,<1`. | Environments that pin an older `click`, `openai` or `httpx` alongside Quin | Upgrade those packages; older versions did not work with the current ones. |
| **Capped lists are now reproducible.** The same repository could list different agents and tools on different machines because file listing and scanner merge order were not fixed. Lists capped at 50 agents and 100 tools now keep the same items everywhere. | Anyone comparing beta output with 1.0 output of a large repository | Re-baseline any stored comparison. See [detection changes](stability.md). |

## What is not changing

- The commands (`scan`, `scan-batch`, `scan-org`, `skills scan`, `skills baseline`) and every option that existed. A test fails the build if one is removed or changes its default, type or requiredness. See the [CLI reference](cli.md).
- Exit codes of `scan` and `skills scan`: `scan` still exits 0 whatever it finds. `skills scan` still exits 1 at or above `--fail-on`.
- Rule IDs (`SK-...`) and threat and control IDs (`T001`-`T014`, `C001`-`C014`). An ID is never reused; retired rules are listed in [skill-rules.md](skill-rules.md#retired-rules).
- Skills baseline files written by a beta keep loading and suppressing findings. Newer baseline versions are rejected with an error that says to upgrade.
- The Python import API was never public and still is not. The web UI in `ui/` is experimental.

## Check your pipeline

1. Upgrade and confirm the version: `quin-scanner --version` prints the release and the report schema version.
2. Run your usual command with `--no-llm --no-vuln-check` against a repository you know and compare the report with the last one you kept. Differences in detection are described in the [stability policy](stability.md); changes to findings should be small and listed in the CHANGELOG under "Detection changes".
3. If you use `scan-batch` or `scan-org`, check the exit code of the job.
4. If you use the Action, pin a tag (or `version`) and check the new `fail-on` and `upload-sarif` inputs.
