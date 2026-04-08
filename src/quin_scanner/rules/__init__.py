from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _rules_dir() -> Path:
    """Return the path to the bundled rules directory."""
    return Path(__file__).parent


def load_rules(filename: str) -> Any:
    """Load and parse a YAML rules file from the rules/ package directory."""
    rules_path = _rules_dir() / filename
    with rules_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)
