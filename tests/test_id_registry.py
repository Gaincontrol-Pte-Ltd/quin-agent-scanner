"""Rule, threat and control IDs are identifiers: never removed silently, never reused.

Policy: docs/stability.md ("Rule and threat IDs"). A rule that is removed is retired: its ID moves to the
"Retired rules" table in docs/skill-rules.md and may never be emitted again.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from quin_scanner.risk_taxonomy import load_taxonomy

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "quin_scanner"
DOC = ROOT / "docs" / "skill-rules.md"
BASELINE = Path(__file__).resolve().parent / "id_baseline_1.0.json"
_ID = re.compile(r"SK-[A-Z]+-\d{3}")
_RETIRED = re.compile(r"\n## Retired rules\n(.*?)(?=\n## |\Z)", re.S)


def emitted_ids() -> set[str]:
    ids = set(_ID.findall((SRC / "rules" / "skill_rules.yaml").read_text(encoding="utf-8")))
    for path in (SRC / "scanners" / "skills").rglob("*.py"):
        ids |= set(_ID.findall(path.read_text(encoding="utf-8")))
    return ids


def retired_ids(doc_text: str) -> set[str]:
    section = _RETIRED.search(doc_text)
    return set(_ID.findall(section.group(1))) if section else set()


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def test_the_rules_doc_has_a_retired_rules_section():
    assert _RETIRED.search(DOC.read_text(encoding="utf-8"))


def test_every_baseline_rule_is_still_emitted_or_explicitly_retired():
    retired = retired_ids(DOC.read_text(encoding="utf-8"))
    missing = sorted(set(_baseline()["rules"]) - emitted_ids() - retired)
    assert not missing, (
        f"rule IDs disappeared without being retired: {missing}. Add them to the 'Retired rules' table in "
        "docs/skill-rules.md (IDs are never reused or silently removed; see docs/stability.md)."
    )


def test_a_retired_rule_is_never_emitted_again():
    reused = sorted(retired_ids(DOC.read_text(encoding="utf-8")) & emitted_ids())
    assert not reused, f"retired rule IDs are emitted again: {reused}. IDs are never reused."


def test_threat_ids_and_names_match_the_baseline():
    current = {t.id: t.name for t in load_taxonomy().threats}
    for threat_id, name in _baseline()["threats"].items():
        assert threat_id in current, f"threat {threat_id} was removed"
        assert current[threat_id] == name, (
            f"threat {threat_id} was renamed {name!r} -> {current[threat_id]!r}; an ID must keep its meaning. "
            "If this is a deliberate clarification, update tests/id_baseline_1.0.json in the same PR."
        )


def test_control_ids_and_names_match_the_baseline():
    current = {c.id: c.name for c in load_taxonomy().controls}
    for control_id, name in _baseline()["controls"].items():
        assert control_id in current, f"control {control_id} was removed"
        assert current[control_id] == name, f"control {control_id} was renamed {name!r} -> {current[control_id]!r}"


def test_retired_section_parser():
    text = (
        "## Limits\n\nSK-OLD-001 is mentioned here.\n\n## Retired rules\n\n"
        "| Rule | Retired in | Reason |\n|---|---|---|\n| SK-GONE-001 | 1.2.0 | merged |\n\n## Limits\n\nSK-X-002\n"
    )
    assert retired_ids(text) == {"SK-GONE-001"}
    assert retired_ids("## Limits\n\nnothing\n") == set()
