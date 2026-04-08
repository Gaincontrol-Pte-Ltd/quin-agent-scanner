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

### Run Tests

```bash
uv run pytest tests/ -v
uv run pytest tests/ -v --cov=quin_scanner   # with coverage
```

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

Check the [drop plan](docs/plans/2026-03-31-quin-agent-scanner-drop-plan.md) first — features may already be scheduled.

### Pull Requests

1. **Fork** the repo and create a branch from `main`
2. **Write tests** for any new behaviour
3. **Run the full test suite** — all 289+ tests must pass
4. **Keep scope tight** — one feature or fix per PR
5. **Update CHANGELOG.md** under `[Unreleased]`
6. Open the PR with a clear description of what and why

---

## Adding a New Scanner Plugin

1. Create `src/quin_scanner/scanners/my_scanner.py` extending `BaseScanner`
2. Implement `name() -> str` and `scan(accessor, file_index) -> list[ScanFinding]`
3. Register it in `orchestrator.py` `_SCANNER_REGISTRY`
4. Add detection rules to the appropriate `rules/*.yaml` file if needed
5. Create a test fixture in `tests/fixtures/`
6. Write tests in `tests/test_scanners/test_my_scanner.py`

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
- `pytest` for all tests (not unittest)
- No docstrings on internal helpers — only on public APIs
- Keep functions small and focused; prefer composition over inheritance

---

## Commit Messages

Use the imperative mood and keep the subject under 72 characters:

```
feat: add support for Bedrock runtime scanner
fix: handle empty notebook cells in jupyter scanner
test: add fixtures for google-adk detection
docs: update framework list in README
```

---

## Project Roadmap

Features are released in numbered drops. The full plan is in [`docs/plans/2026-03-31-quin-agent-scanner-drop-plan.md`](docs/plans/2026-03-31-quin-agent-scanner-drop-plan.md).

| Drop | Theme | Status |
|---|---|---|
| v0.1.0 | Scan Any Repo for AI | ✅ Released |
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
