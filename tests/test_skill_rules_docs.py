"""Every rule id emitted by the skills scanner must be documented in docs/skill-rules.md."""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "skill-rules.md"
SKILLS_SRC = REPO_ROOT / "src" / "quin_scanner" / "scanners" / "skills"
RULES_YAML = REPO_ROOT / "src" / "quin_scanner" / "rules" / "skill_rules.yaml"
_ID = re.compile(r"SK-[A-Z]+-\d{3}")


def _emitted_ids() -> set[str]:
    ids = set(_ID.findall(RULES_YAML.read_text(encoding="utf-8")))
    for path in SKILLS_SRC.rglob("*.py"):
        ids |= set(_ID.findall(path.read_text(encoding="utf-8")))
    return ids


def test_every_emitted_rule_is_documented():
    documented = set(_ID.findall(DOC.read_text(encoding="utf-8")))
    missing = sorted(_emitted_ids() - documented)
    assert not missing, f"undocumented skill rules: {missing}"


def test_documented_rules_exist():
    documented = set(_ID.findall(DOC.read_text(encoding="utf-8")))
    stale = sorted(documented - _emitted_ids())
    assert not stale, f"docs mention rules that no longer exist: {stale}"


def test_readme_and_example_config_mention_skills():
    assert "skills" in (REPO_ROOT / "scanner-config.yaml").read_text(encoding="utf-8")
    assert "docs/skill-rules.md" in (REPO_ROOT / "README.md").read_text(encoding="utf-8")
