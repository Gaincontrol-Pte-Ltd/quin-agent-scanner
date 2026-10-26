# Report schema

This describes the JSON and YAML reports (`quin-scanner scan -o json|yaml`, same structure), the JSON envelope of `skills scan -o json`, and the files around them. Stability rules are in [stability.md](../stability.md). The authoritative field-by-field reference is the JSON Schemas [`report-1.json`](report-1.json) and [`skills-scan-1.json`](skills-scan-1.json); this page explains the rules and conventions. Every report and envelope carries `schema_version` (`MAJOR.MINOR`, currently `1.0`).

## Compatibility rules

Within a major schema version:

- fields are never removed or renamed, and never change type or meaning;
- new fields may appear, so **consumers must ignore fields they do not know**;
- list order is not significant unless stated;
- a field documented as nullable stays nullable; a list stays a list (empty, never `null`).

## Conventions

- Timestamps are ISO 8601 in UTC (`2026-10-26T09:20:15+00:00`).
- Paths are repo-relative and use `/` as the separator. `line_number` is 1-based or `null`.
- `confidence` is a number from 0.0 to 1.0.
- Severities are `critical`, `high`, `medium`, `low` or `info`. Skill verdicts are `SAFE`, `CAUTION` or `HIGH_RISK`.
- `metadata` and `coverage` are **open maps**: their keys depend on the flags used and the scanners that ran (for example `skills_*` coverage keys appear only when the skills scanner ran). Keys documented here are stable; other keys are informational and may change.

## Top-level report fields

<!-- report-fields:start -->
| Field | Presence | Type | Meaning |
|---|---|---|---|
| `schema_version` | always | string | Report schema version as `MAJOR.MINOR` (currently `1.0`). |
| `repo_path` | always | string | The scanned target as given (path or `owner/repo`). |
| `scan_timestamp` | always | string | When the scan ran (UTC). |
| `is_ai_application` | always | boolean | Whether the repository looks like an AI application. |
| `confidence` | always | number | Overall detection confidence. |
| `capability_tags` | always | list of string | Capabilities detected (for example `llm-api`, `rag`, `tool-use`). |
| `framework` | always | string | Main agent framework as `"<Name> <version>"`, or `"unknown"`. |
| `summary` | always | string | Narrative summary (LLM-written when LLM analysis ran, otherwise static). |
| `agents` | always | list of object | Detected agents and their tools, skills and risk signals. |
| `tool_usages` | always | list of object | Tools, external services, skills and MCP tools in use. |
| `risk_signals` | always | list of object | Repo-level risks (threat ID, severity, controls, evidence). |
| `mcp_servers` | always | list of object | MCP servers and transports found in config. |
| `infra` | always | object or null | Infrastructure profile (Docker, CI, IaC), `null` when none found. |
| `vulnerabilities` | always | list of object | Known vulnerabilities for the detected framework version. |
| `artifacts` | always | list of object | Deduplicated scanner findings. |
| `model_usages` | always | list of object | Models used, with provider, source and role. |
| `agent_tool_relationships` | always | list of object | Agent-to-tool links found in source. |
| `inventory` | always | list of object | Every raw scanner observation. |
| `coverage` | always | object (open map) | Files and scanners covered. |
| `llm_endpoints` | always | list of object | LLM endpoint addresses (credentials redacted). |
| `metadata` | always | object (open map) | Scan duration, counts, options used, notes and errors. |
| `skills` | always | list of object | Per-skill assessments (see below). |
| `file_hashes` | always | list of object | `path` and `sha256` of source files. |
| `governance` | optional | object | Aegis governance classification; present only with `--detect-aegis`. |
<!-- report-fields:end -->

## Records

**Artifact / inventory item**: `scanner_name`, `category`, `file_path`, `line_number` (integer or null), `match_text`, `capability_tag`, `confidence`.

**Risk signal**: `signal`, `recommended_controls` (list of string), `threat_id` (a `T001`–`T014` ID or null), `severity`, `evidence_refs` (list of `file_path`, `line_number`, `scanner`, `source_url`).

**Tool usage**: `tool_name`, `tool_type` (`tool_definition`, `external_service`, `skill` or `mcp_tool`), `service_category`, `source_file`, `line_number`.

**Skill assessment** (`skills[]`): `record` (`id`, `name`, `description`, `root_path`, `skill_md_path`, `ecosystem`, `allowed_tools`, `files`, `frontmatter_valid`), `findings` (list of `rule_id`, `skill_id`, `severity`, `category`, `title`, `file_path`, `line_number`, `evidence`, `threat_id`, `confidence`, `llm_verdict`, `explanation`), `risk_score` (0–100), `verdict`, `finding_counts` (severity to count), `top_rule_ids`.

The remaining record types (`agents`, `model_usages`, `mcp_servers`, `infra`, `vulnerabilities`, `llm_endpoints`, `agent_tool_relationships`, `file_hashes`, `governance`) are documented field by field in [`report-1.json`](report-1.json).

## `skills scan -o json` envelope

`schema_version`, `target`, `scanned_at`, `skills` (list of skill assessments as above), `notes` (list of string), `coverage` (open map), and `metadata` (only when a baseline was used: `skills_baseline` with `file`, `suppressed_count`, `stale_count`).

## Skills baseline file

`version` (integer, currently `1`), `generated` (timestamp), `entries` (list of `fingerprint`, `rule_id`, `skill`, `file_path`, `note`). The fingerprint is a SHA-256 over rule, skill, file and whitespace-normalised evidence; it does not depend on line numbers.

## Config file

See [stability.md](../stability.md#config-and-baseline-files) for the keys, the optional `config_version` and how unknown keys are handled.
