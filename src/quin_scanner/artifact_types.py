from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from quin_scanner.rules import load_rules


@lru_cache(maxsize=1)
def _rules() -> dict[str, Any]:
    rules = load_rules("artifact_types.yaml")
    rules["_refinements"] = [
        (r["type"], re.compile(r["pattern"])) for r in rules.get("llm_api_refinements", [])
    ]
    return rules


def artifact_type(category: str, capability_tag: str, match_text: str) -> str:
    """Return the standardised, display-only type for a scanner artifact."""
    rules = _rules()
    by_category = rules.get("by_category", {})
    if category in by_category:
        return by_category[category]
    tag = (capability_tag or "").split(":", 1)[0]
    by_tag = rules.get("by_tag", {})
    if tag in by_tag:
        return by_tag[tag]
    if tag == "llm-api":
        text = (match_text or "").strip()
        for type_name, rx in rules["_refinements"]:
            if rx.search(text):
                return type_name
        return rules.get("llm_api_default", "LLM API")
    return rules.get("default_type", "Other")


def type_order() -> list[str]:
    return list(_rules().get("order", []))


def annotate(artifacts: list[dict[str, Any]]) -> None:
    """Add an ``artifact_type`` key to each artifact dict, in place."""
    for a in artifacts:
        a["artifact_type"] = artifact_type(
            a.get("category", ""), a.get("capability_tag", ""), a.get("match_text", "")
        )
