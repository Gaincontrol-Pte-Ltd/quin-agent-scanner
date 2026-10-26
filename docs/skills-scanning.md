# Scanning Agent Skills

Quin checks the Agent Skills your team installs or ships, and the instruction files next to them, for prompt injection, hidden content, credential access, data exfiltration, dangerous code, risky supply-chain choices, excessive permissions and MCP tool poisoning. It never runs anything it scans.

This guide is the practical walkthrough. The full rule list is in [skill-rules.md](skill-rules.md); the evidence behind the tuning is in [skill-scanner-tuning-2026-10.md](skill-scanner-tuning-2026-10.md).

## What gets scanned

| Target | What Quin looks for |
|---|---|
| **Agent Skills** | Any folder containing `SKILL.md` (Claude Code, Codex and OpenCode layouts such as `.claude/skills`, `.codex/skills`, `.opencode/skill`), with its bundled scripts, references and dependency files. |
| **MCP tool definitions** | Tool descriptions in Python, JavaScript/TypeScript and JSON that define MCP tools, plus `mcp.json` / `.mcp.json` server scopes. Reported as one record, "MCP tool definitions". |
| **Agent instruction files** | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.roo/rules*`. Reported as one record, "Agent instruction files", with the text rules only. |

The skills scanner is on by default in `quin-scanner scan`, and there is a dedicated command for checking a skill before you install it.

## Quick start

```bash
pip install quin-scanner

# A skill folder, a downloaded zip, or a repo URL
quin-scanner skills scan ./my-skill
quin-scanner skills scan ~/Downloads/pdf-skill.zip
quin-scanner skills scan https://github.com/owner/repo/tree/main/skills/pdf
```

`skills scan` is static by default: no API key, no LLM. Zips are extracted into a temporary directory with limits on member count and size and with path-traversal, absolute-path and symlink checks; the directory is removed afterwards.

Useful options:

| Option | Meaning |
|---|---|
| `-o terminal\|json\|sarif`, `-f FILE` | Output format and destination. |
| `--fail-on caution\|high_risk` | Exit `1` when any skill reaches this verdict (default `high_risk`). |
| `--baseline FILE` | Ignore findings accepted earlier (see [Baselines](#baselines)). |
| `--no-vuln-check` | Skip OSV lookups for pinned skill dependencies (offline use). |
| `--llm-provider`, `--llm-model`, `--llm-api-key`, `--config` | Add the optional LLM review (see below). `--no-llm` always disables it. |

Exit codes: `0` nothing at or above `--fail-on`, `1` at or above it, `2` error (bad target, unreadable or unsafe zip, bad config, missing or malformed baseline).

## Reading the results

```
Skills: 3 found
  evil-formatter                 HIGH_RISK  100  (1 critical, 7 high, 1 medium)
  commit-helper                  SAFE         0  (no findings)
```

Each skill gets a score from 0 to 100 and a verdict:

| Verdict | Score | Meaning |
|---|---|---|
| `SAFE` | under 20 | Nothing that needs a decision. Low findings can still be listed. |
| `CAUTION` | 20 to 50 | Read the findings before installing. A critical finding always means at least `CAUTION`. |
| `HIGH_RISK` | over 50 | Several serious findings. Do not install without a close review. |

Every finding shows a rule id (for example `SK-PI-001`), a severity, the file and line, redacted evidence, and the threat it maps to in the [risk framework](risk-framework.md). A repeat of the same rule counts for less each time, so one noisy rule cannot dominate a score.

A verdict is a prompt for review, not proof. A static scan cannot show that a skill is safe, and some findings are expected by design: an onboarding skill that offers the official Homebrew installer will be flagged for piping a script into a shell, and a hook-testing guide that contains `rm -rf /` as test input can be flagged for it. Look at the evidence before deciding.

## Baselines

A baseline accepts today's findings so later scans only report what is new. It is the way to adopt the scanner on a repository that already has reviewed skills.

```bash
# 1. Review the current findings, then accept them
quin-scanner skills baseline ./skills -o skills-baseline.yaml

# 2. Commit the file, then scan against it
quin-scanner skills scan ./skills --baseline skills-baseline.yaml
quin-scanner scan . --skills-baseline skills-baseline.yaml
```

- The file holds one fingerprint per finding (rule, skill, file and whitespace-normalised evidence) with an empty `note` you can fill in. It stores no raw evidence and no line numbers, so edits elsewhere in a file do not invalidate an entry.
- Paths are relative to the scanned directory, so use the same root when you create and apply a baseline.
- Findings that match are removed before scoring, review and exit-code logic. New findings still count; entries that no longer match are reported as stale.
- Review a baseline like code: a skill whose findings are all baselined scores `SAFE`.

## In CI

**Whole repository (GitHub Action).** The skills scanner runs with every scan and high and critical skill findings appear as code-scanning alerts with file and line:

```yaml
- uses: Gaincontrol-Pte-Ltd/quin-agent-scanner@beta
```

**Gate on skills only.**

```yaml
jobs:
  skills:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install quin-scanner
      - run: >
          quin-scanner skills scan ./skills
          --baseline skills-baseline.yaml
          --fail-on caution -o sarif -f skills.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skills.sarif
```

Check a third-party skill before it enters the repository by running `skills scan` on its folder, zip or URL in the pull request that adds it.

## Optional LLM review

With an LLM provider configured, a second pass asks the model to confirm or dispute each finding of medium severity or above, with a one-line explanation. It is off in `skills scan` unless you pass an LLM option, and `--no-llm` always disables it.

- Only the flagged evidence snippets (redacted, at most 500 characters each) plus the skill name and a short description are sent to the provider, never whole files.
- The skill's own text is treated as untrusted data in the prompt.
- A dispute lowers a finding's weight and keeps it out of the promoted risk signals, but it never downgrades a critical, AST or taint finding.
- If the provider fails, the static results stand.

## Limits

- Static analysis only: runtime behaviour is not observed, and compiled or encrypted code is not analysed.
- Non-English text and text inside images are not analysed.
- At most 200 skills per repository, 500 files per skill and 1 MB per file; anything beyond that is counted in `skills_capped` and listed in the report notes.
- OSV lookups cover exact-pinned PyPI (`requirements*.txt`) and npm (`package.json`) dependencies, up to 50 per scan.
- Known remaining noise: vendor `curl | bash` installers, `curl -X POST` examples for other APIs, and documentation that mentions flags such as `--yolo`. A baseline handles these.
