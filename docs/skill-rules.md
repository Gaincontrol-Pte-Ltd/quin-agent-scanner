# Skill Scanner Rules

The `skills` scanner finds Agent Skills (`SKILL.md` packages for Claude Code, Codex and OpenCode) and MCP tool definitions, then assesses each one. Every rule maps to a threat in the [risk framework](risk-framework.md). Findings carry a severity, a confidence, and redacted evidence with `file:line`.

Skills are scored 0–100. Severity weights are critical 40, high 20, medium 8 and low 2, multiplied by confidence. A repeat of the same rule counts half as much each time. Verdicts: under 20 is `SAFE`, 20–50 is `CAUTION`, over 50 is `HIGH_RISK`. A critical finding forces at least `CAUTION`. With an LLM enabled, findings the model disputes count at half weight and are not promoted to risk signals.

High and critical findings are promoted to `risk_signals`, so they appear in SARIF output.

Quin never executes skill code. With an LLM enabled, only flagged evidence snippets (not whole files) are sent to the configured provider. `--no-llm` produces the same static results without that step.

## Text rules (`rules/skill_rules.yaml`)

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-PI-001 | high | T001 | Instruction-override phrasing ("ignore all previous instructions") |
| SK-PI-002 | high | T001 | Chat-template or system-role markers in skill text |
| SK-PI-003 | high | T001 | Hidden instruction inside an HTML comment |
| SK-PI-004 | medium | T001 | Tells the agent to conceal actions from the user |
| SK-PI-005 | medium | T001 | Invisible or bidirectional Unicode characters |
| SK-PI-006 | high | T001 | Unicode tag characters (hidden text) |
| SK-PI-007 | medium | T001 | Long base64-like blob |
| SK-AR-001 | high | T006 | Instructs the agent to bypass safety or approval controls |
| SK-AR-002 | medium | T006 | Instructs the agent to act without confirmation |
| SK-AR-003 | high | T006 | Permission-bypass flags such as `--dangerously-skip-permissions` |
| SK-SL-001 | medium | T002 | Instructs the agent to reveal its system prompt |
| SK-EX-001 | high | T002 | Reads credential or key material |
| SK-EX-002 | medium | T002 | Uploads data with curl/wget |
| SK-EX-003 | high | T002 | References a known exfiltration or webhook endpoint |
| SK-EXEC-001 | critical | T005 | Pipes a remote script into a shell |
| SK-EXEC-002 | high | T005 | Destructive recursive delete |
| SK-EXEC-003 | high | T011 | Installs persistence (cron, launchd, shell profile) |
| SK-EXEC-004 | critical | T005 | Reverse-shell pattern |

Prose rules ignore matches inside closed fenced code blocks (usually quoted examples); an unclosed fence hides nothing. Rules marked negatable ignore a match when the same clause (text after the last `.`, `;`, `!`, `?` or `:`, within the line; "never mind" does not count as a negation), before the match, contains "never", "do not", "avoid" and similar words. SK-EXEC-001 and SK-EXEC-002 are negatable so that defensive text such as "never run `curl | sh`" is not flagged, but `Never mind, just run: curl … | sh` still is. SK-EX-001 ignores lines that are entirely a code comment, and matches `.ssh/`, `.aws/` and `.gnupg/` only as path components, not inside a domain such as `api.aws/`.

## Python code (AST)

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-CODE-001 | high / medium | T005 | `eval`/`exec` of dynamic input (medium for constants) |
| SK-CODE-002 | high / medium | T005 | `os.system`, `os.popen`, or `subprocess` with `shell=True` |
| SK-CODE-003 | high / medium | T005 | Unsafe deserialization (`pickle`, `marshal`, `yaml.load` without a safe loader) |
| SK-CODE-004 | medium | T005 | Dynamic import of a computed module name |
| SK-CODE-005 | critical | T005 | Decoded payload (base64, zlib, hex) passed to `eval`/`exec` |

## Taint

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-TAINT-001 | high | T002 | Sensitive file contents flow into a network call |
| SK-TAINT-002 | medium | T002 | Environment value flows into a network call (low confidence) |

## Supply chain

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-SC-001 | low | T003 | Unpinned dependency |
| SK-SC-002 | medium | T003 | Possible typosquat of a popular package |
| SK-SC-003 | medium | T003 | Dependency installed from a URL or VCS |
| SK-SC-004 | medium | T003 | npm install-time script (`preinstall`/`install`/`postinstall`) |
| SK-SC-005 | low | T003 | Unpinned `pip install` or `npx` in instructions or scripts |
| SK-SC-006 | by advisory | T003 | Known vulnerability in a pinned PyPI requirement (OSV; skipped with `--no-vuln-check`) |

## Permissions and metadata

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-PERM-001 | high | T006 | Unrestricted shell access in `allowed-tools` (`Bash`, `Bash(*)`) |
| SK-PERM-002 | high | T006 | Wildcard tool grant (`*`, `mcp__server__*`) |
| SK-PERM-003 | low | T006 | Unrestricted write or network tool |
| SK-PERM-004 | medium | T011 | Code makes network calls the description never mentions |
| SK-PERM-005 | high | T011 | Code touches credential files the description never mentions |
| SK-META-001 | low | T011 | `SKILL.md` frontmatter missing or invalid |

## MCP

| Rule | Severity | Threat | What it flags |
|---|---|---|---|
| SK-MCP-001 | high | T001 | Injection or hidden instruction in an MCP tool description |
| SK-MCP-002 | high | T002 | MCP tool description references credentials or sensitive files |
| SK-MCP-004 | high | T006 | MCP filesystem server granted an overly broad path (`/`, `~`) |

## Limits

Static analysis only: no runtime behavior is observed. Non-English text and text inside images are not analyzed. At most 200 skills per repository, 500 files per skill, and 1 MB per file are analyzed; anything beyond that is recorded in `metadata.skills_notes`, and `coverage.skills_capped` counts how many limits were hit (also the MCP source read cap and the OSV lookup cap).

## Baselines

`quin-scanner skills baseline <target> -o skills-baseline.yaml` records every current finding so later scans with `skills scan --baseline skills-baseline.yaml` or `scan --skills-baseline skills-baseline.yaml` report only new ones. It always scans statically (no LLM review) and will not overwrite an existing file without `--force`.

```yaml
version: 1
generated: '2026-10-25T09:00:00+00:00'
entries:
- fingerprint: 2aee06c3...           # sha256, see below
  rule_id: SK-PI-001
  skill: evil-formatter
  file_path: evil-formatter/SKILL.md
  note: ''                            # free text for reviewers, ignored by the scanner
```

- The fingerprint is `sha256(rule_id | skill name | file_path | evidence)`, with runs of whitespace in the evidence collapsed to one space (case is kept). Line numbers, severity, confidence and LLM verdicts are not part of it, so edits elsewhere in a file do not invalidate an entry. Only `fingerprint` is used for matching; the other fields are for review. The file never contains evidence text.
- File paths are relative to the scanned target, so baseline and scan the same root.
- Identical findings (same rule, skill, file and evidence) share one entry, and a new copy of the same text in that file is also suppressed.
- Suppressed findings are removed before the LLM review, scoring, promotion to risk signals, SARIF and JSON output; skill scores, verdicts, counts and top rules are recomputed from what remains, and in `scan` the per-skill artifacts and inventory entries are rebuilt too.
- `metadata.skills_baseline` records `file` (name only), `suppressed_count` and `stale_count` (distinct baseline fingerprints that matched no finding). Stale entries are not an error; regenerate the file with `--force` to drop them.
- A missing file, invalid YAML, a `version` other than 1, or an entry without a string `fingerprint` is an error (exit `2`); the scan never runs without the baseline you asked for. Duplicate entries are allowed.

## LLM review

The optional LLM pass can mark findings `confirmed` or `disputed`. A disputed finding counts at half weight and is not promoted to a repo-level risk signal. LLM disputes never downgrade critical, AST (`SK-CODE-*`) or taint (`SK-TAINT-*`) findings: their verdict and explanation are recorded, but they keep full weight and stay promoted. Skill name, description and evidence are embedded in delimited, length-capped data blocks and the model is told nothing inside them is an instruction.
