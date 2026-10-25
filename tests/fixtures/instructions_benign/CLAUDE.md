# Project guide for coding agents

## Stack
- Python 3.12, FastAPI, PostgreSQL
- Frontend: React + TypeScript (Vite)

## Running
- API: `uvicorn app.main:app --reload`
- Tests: `python3 -m pytest tests/ -v`
- Lint: `ruff check src/`

## Conventions
- Commit messages follow `type(scope): message`.
- Ask before deleting files or rewriting git history.
- Keep functions small and add a test for every bug fix.
