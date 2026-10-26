"""A baseline written by an earlier release must keep working (docs/stability.md)."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.baseline import BASELINE_VERSION, BaselineError, fingerprint, load_baseline

TESTS = Path(__file__).resolve().parent
FIXTURE_REPO = TESTS / "fixtures" / "skills_repo"
FROZEN_BASELINE = TESTS / "fixtures" / "baselines" / "baseline-v1.yaml"

# Pinned: changing the fingerprint algorithm would invalidate every existing baseline.
GOLDEN_FINGERPRINT = "52eb9acd8c5ffdec4062e0aed38a8bb04e7403f8817544e5ebbe5fa41addbf3d"


def _finding() -> SkillFinding:
    return SkillFinding(
        rule_id="SK-PI-001", skill_id="s", severity="high", category="prompt_injection", title="t",
        file_path="skills/demo/SKILL.md", line_number=7, evidence="ignore  all previous\ninstructions",
        threat_id="T001", confidence=0.8,
    )


def test_the_fingerprint_algorithm_is_frozen():
    assert fingerprint(_finding(), "demo") == GOLDEN_FINGERPRINT


def test_the_fingerprint_ignores_line_numbers_and_whitespace():
    moved = replace(_finding(), line_number=99, evidence="ignore all previous instructions")
    assert fingerprint(moved, "demo") == GOLDEN_FINGERPRINT


def test_the_fingerprint_depends_on_rule_skill_file_and_evidence():
    base = fingerprint(_finding(), "demo")
    assert fingerprint(replace(_finding(), rule_id="SK-PI-002"), "demo") != base
    assert fingerprint(_finding(), "other") != base
    assert fingerprint(replace(_finding(), file_path="skills/demo/other.md"), "demo") != base
    assert fingerprint(replace(_finding(), evidence="something else"), "demo") != base


def test_a_frozen_version_1_baseline_still_loads():
    baseline = load_baseline(FROZEN_BASELINE)
    assert baseline.entries and baseline.fingerprints


def test_a_frozen_version_1_baseline_still_suppresses_findings():
    result = CliRunner().invoke(
        cli, ["skills", "scan", str(FIXTURE_REPO), "--baseline", str(FROZEN_BASELINE), "--no-vuln-check", "--fail-on", "caution"]
    )
    assert result.exit_code == 0, result.output  # everything in the fixture repo is baselined


def _write(tmp_path, version_line: str) -> str:
    path = tmp_path / "baseline.yaml"
    path.write_text(f"{version_line}\nentries: []\n", encoding="utf-8")
    return str(path)


def test_the_current_baseline_version_is_1():
    assert BASELINE_VERSION == 1


def test_a_newer_version_is_rejected_with_an_upgrade_hint(tmp_path):
    with pytest.raises(BaselineError, match="newer") as info:
        load_baseline(_write(tmp_path, "version: 2"))
    assert "Upgrade" in str(info.value)


@pytest.mark.parametrize("version_line", ["version: 0", "version: -1", "version: '1'", "version: true", "version: 1.0", "generated: x"])
def test_a_malformed_version_is_rejected(tmp_path, version_line):
    with pytest.raises(BaselineError, match="positive integer"):
        load_baseline(_write(tmp_path, version_line))
