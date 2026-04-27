"""Predicate registry for Key Risk Indicator (KRI) preconditions.

Each KRI in risk_taxonomy.yaml may declare `requires: [<predicate>, ...]` —
all listed predicates must evaluate True for the KRI to be considered a
candidate the LLM is allowed to flag.

Predicates read from a frozen EvidenceFacts bundle assembled by the
orchestrator from data it already has after the rule-based scan pass.
Adding a predicate is intentionally a code change (not a YAML/DSL change)
so callers can grep usage and reviewers can see the exact semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class EvidenceFacts:
    """Frozen snapshot of scanner evidence used for KRI precondition gating."""
    system_types: frozenset[str] = frozenset()
    capability_tags: frozenset[str] = frozenset()
    mcp_servers_count: int = 0
    agent_instances_count: int = 0
    tool_definitions_count: int = 0
    external_service_categories: frozenset[str] = frozenset()


_REGISTRY: dict[str, Callable[[EvidenceFacts], bool]] = {
    "mcp_servers_present":
        lambda f: f.mcp_servers_count > 0,
    "multi_agent_system":
        lambda f: "multi_agent" in f.system_types,
    "memory_capability_present":
        lambda f: "memory" in f.capability_tags,
}


def evaluate(predicate_name: str, facts: EvidenceFacts) -> bool:
    """Return True if the predicate holds for the given facts.

    Unknown predicate names evaluate False (fail-closed). This means a
    typo'd `requires` entry will silently drop the KRI rather than admit it
    by accident; the typo will be caught by the registry-coverage test.
    """
    fn = _REGISTRY.get(predicate_name)
    return bool(fn(facts)) if fn else False


def known_predicates() -> frozenset[str]:
    """Return the set of registered predicate names."""
    return frozenset(_REGISTRY.keys())
