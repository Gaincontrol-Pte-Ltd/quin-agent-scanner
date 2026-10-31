"""The installed package must byte-compile without warnings (a SyntaxWarning is printed to every user at install time)."""
from __future__ import annotations

import warnings
from pathlib import Path

import quin_scanner


def test_every_module_compiles_without_warnings():
    root = Path(quin_scanner.__file__).parent
    problems = []
    for path in sorted(root.rglob("*.py")):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        problems += [f"{path.relative_to(root)}:{w.lineno} {w.message}" for w in caught]
    assert not problems, problems
