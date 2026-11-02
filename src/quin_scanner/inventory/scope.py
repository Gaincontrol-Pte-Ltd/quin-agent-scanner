"""Where a path lives: production, test or example code (rules/scope.yaml; first match wins)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

_RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "scope.yaml"


@lru_cache(maxsize=1)
def _rules() -> tuple[tuple[str, re.Pattern[str]], ...]:
    data = yaml.safe_load(_RULES_FILE.read_text(encoding="utf-8")) or {}
    return tuple(
        (scope, re.compile(pattern, re.IGNORECASE))
        for scope in ("test", "example")
        for pattern in data.get(scope, [])
    )


def scope_of(path: str) -> str:
    """"test", "example" or "production" for a repo-relative path."""
    normalised = path.replace("\\", "/")
    for scope, pattern in _rules():
        if pattern.search(normalised):
            return scope
    return "production"
