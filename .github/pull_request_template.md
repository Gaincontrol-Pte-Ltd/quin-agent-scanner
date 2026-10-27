## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] The title follows `type(scope): message` (for example `fix(skills): ...`)
- [ ] Tests added or updated; `python3 -m pytest tests/ -q` passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] If detection changed (scanners, rules, scoring): ran `python3 scripts/run_corpus.py --update`, reviewed the snapshot diff, and described it under `### Detection changes`
- [ ] If a stable surface changed (CLI, report schema, rule IDs, config, baseline, Action): followed [docs/stability.md](../docs/stability.md) and updated the frozen baselines deliberately
- [ ] Docs updated if behavior or options changed
