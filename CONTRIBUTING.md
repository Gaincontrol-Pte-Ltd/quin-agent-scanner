# Contributing to Quin Agent Scanner

Thank you for your interest in contributing. This document covers how to get started, the development workflow, and what we look for in contributions.

---

## Getting Started

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager

### Set Up the Dev Environment

```bash
git clone https://github.com/quin-scanner/quin-agent-scanner
cd quin-agent-scanner
uv sync --all-extras
```

This installs all dependencies into a local `.venv`.

---

## Ways to Contribute

### Bug Reports

Open an issue with:
- Quin Scanner version (`quin-scanner --version`)
- OS and Python version
- Command you ran
- Expected vs actual output
- Minimal reproducer (a small repo or fixture that triggers the bug)

### Feature Requests

Open an issue describing:
- What you want to do that you can't do today
- Why it matters (use case)
- Any ideas on how it could work

Check the [roadmap](#project-roadmap) first — features may already be scheduled.

### Pull Requests

1. **Fork** the repo and create a branch from `main`
2. **Keep scope tight** — one feature or fix per PR
3. **Update CHANGELOG.md** under `[Unreleased]`
4. Open the PR with a clear description of what and why
5. **LLM providers and SDK bumps** — changes to `src/quin_scanner/llm/` and bumps of `anthropic`, `google-genai` or `openai` must keep `tests/test_llm_providers.py` green. These tests run the real SDKs against mocked endpoints without API keys; they are the only CI check that a provider still works after an SDK upgrade

---

## Changes to Stable Interfaces

The CLI and its exit codes, the JSON/YAML report schema, SARIF output and rule IDs, and the config, baseline and GitHub Action interfaces are covered by the [stability policy](docs/stability.md). Before changing one, check whether the change is breaking (see "What counts as a breaking change" there). Additive changes are fine. A breaking change needs a deprecation first and the maintainers' agreement, stated in the pull request description. A change that moves verdicts or findings (a detection change) goes under a **Detection changes** heading in the CHANGELOG.

---

## Releasing

Releases are tag-driven. Pushing a `v*.*.*` tag runs `.github/workflows/publish.yml`, which builds the package, publishes it to PyPI (trusted publishing, `pypi` environment) and moves a floating tag for the GitHub Action: pre-releases (`v0.1.0b5`, `v0.2.0rc1`) move `beta`; stable releases move the major tag (`v0` for 0.x, `v1` for 1.x). Pre-releases never move a major tag. A PyPI version cannot be reused, so check everything first.

1. Land the work on `main` with CI green and `CHANGELOG.md` updated under `[Unreleased]`.
2. In a release PR: move the `[Unreleased]` entries into a new `## [x.y.z] — YYYY-MM-DD` section, update the compare links at the bottom, and bump the version in `pyproject.toml`, `src/quin_scanner/__init__.py` and the `quin-scanner` entry in `uv.lock`.
3. After the PR is merged, tag the merge commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z` (PEP 440 style, e.g. `v0.1.0b5` or `v0.1.0`).
4. Watch the "Publish to PyPI" run, then check `pip install quin-scanner==X.Y.Z` in a clean environment and publish GitHub release notes from the changelog section.

---

## Adding or Changing a Skill Rule

Skill rules live in two places:

- **Text rules** (regex over skill files) are entries in `src/quin_scanner/rules/skill_rules.yaml`: `id` (`SK-<AREA>-<NNN>`), `title`, `severity`, `category`, `threat_id` (a `T0xx` in the risk taxonomy), `confidence`, `applies_to` (`markdown`, `code`, `shell`, `config`, `text` or `any`) and `pattern`. Optional switches: `skip_in_fence` (ignore fenced examples in Markdown), `negatable` (ignore defensive phrasing such as "never run …" and quoted mentions), `skip_comment_lines`, `skip_patterns` and `skip_hosts`. The header of the YAML file explains each one.
- **Code analyzers** (AST, taint, supply chain, permissions, MCP) are modules in `src/quin_scanner/scanners/skills/analyzers/`. Each takes a `SkillBundle` and returns `SkillFinding`s.

When you add or change a rule:

1. Write the failing test first: one case that must fire and one near-miss that must not (for text rules, `tests/test_skill_text_rules.py`). Prefer a short snippet of the real false positive over an invented one.
2. Document the rule in `docs/skill-rules.md`. A test fails if a rule id exists in code but not in the doc, or the other way round.
3. Check the effect on real content: `quin-scanner skills scan <folder> --no-vuln-check` on a few public skill repositories and on `tests/fixtures/skills_repo`. `evil-formatter` must stay `HIGH_RISK`; `commit-helper` and `injection-awareness` must stay `SAFE` with no findings.
4. Never weaken a rule so that an obvious true positive stops firing; tighten the context instead.
5. Run `python3 -m pytest tests/ -q` and `ruff check src/ --select F,E4,E7,E9`, and add a line under `[Unreleased]` in `CHANGELOG.md`.

---

## Adding a New Scanner Plugin

1. Create `src/quin_scanner/scanners/my_scanner.py` extending `BaseScanner`
2. Implement `name() -> str` and `scan(accessor, file_index) -> list[ScanFinding]`
3. Register it in `orchestrator.py` `_SCANNER_REGISTRY`
4. Add detection rules to the appropriate `rules/*.yaml` file if needed

```python
from quin_scanner.scanners.base import BaseScanner
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.file_index import FileIndex


class MyScanner(BaseScanner):
    def name(self) -> str:
        return "my_scanner"

    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        findings = []
        for path in file_index.glob("**/*.ext"):
            content = accessor.read_file(path)
            # detect and append ScanFinding objects
        return findings
```

## Adding Framework Detection Rules

Framework rules live in `src/quin_scanner/rules/`. Add entries to:

- `dependencies.yaml` — package names per ecosystem
- `code_patterns.yaml` — regex import/call patterns per language
- `frameworks.yaml` — config file names with confidence and capability tags

No code changes needed for most new frameworks — just YAML.

---

## Code Style

- Python 3.11+ with type hints on all public functions
- Dataclasses for data models (not Pydantic)
- `pathlib.Path` for all filesystem operations
- No hardcoded detection rules — use YAML rule files
- No docstrings on internal helpers — only on public APIs
- Keep functions small and focused; prefer composition over inheritance

---

## Commit Messages

Use the imperative mood and keep the subject under 72 characters:

```
feat: add support for Bedrock runtime scanner
fix: handle empty notebook cells in jupyter scanner
docs: update framework list in README
```

---

## Project Roadmap

Features are grouped into numbered drops.

| Drop | Theme | Status |
|---|---|---|
| v0.1.0 | Scan Any Repo for AI | 🧪 Beta (published to PyPI as 0.1.0b1 to 0.1.0b4; no stable 0.1.0 yet) |
| v0.2.0 | Understand the Risk | Planned |
| v0.3.0 | Prove Compliance | Planned |
| v0.4.0 | Automate in CI | Planned |
| v0.5.0 | Scale to the Org | Planned |
| v0.6.0 | Generate the Guardrails | Planned |
| v0.7.0 | Make It Yours | Planned |

If your contribution fits a planned drop, reference it in your PR.

---

## Questions?

Open a [GitHub Discussion](https://github.com/quin-scanner/quin-agent-scanner/discussions) or file an issue.
