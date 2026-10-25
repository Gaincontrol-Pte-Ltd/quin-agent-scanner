from quin_scanner.scanners.skills.analyzers.permissions import analyze_permissions
from quin_scanner.scanners.skills.bundle import SkillBundle


def _scan(files=None, *, tools=None, description="", ecosystem="generic"):
    files = files if files is not None else {"SKILL.md": "---\nname: demo\n---\nbody"}
    bundle = SkillBundle.from_texts(
        files, description=description, allowed_tools=tools, ecosystem=ecosystem
    )
    return analyze_permissions(bundle)


def _ids(findings):
    return [f.rule_id for f in findings]


def test_unrestricted_bash_is_high():
    [f] = _scan(tools=["Bash"])
    assert f.rule_id == "SK-PERM-001" and f.severity == "high" and f.threat_id == "T006"


def test_wildcard_bash_forms_are_high():
    assert _ids(_scan(tools=["Bash(*)"])) == ["SK-PERM-001"]
    assert _ids(_scan(tools=["Bash(:*)"])) == ["SK-PERM-001"]


def test_restricted_bash_is_fine():
    assert _scan(tools=["Bash(git status:*)", "Read", "Grep"]) == []


def test_mcp_wildcard_and_star():
    assert _ids(_scan(tools=["*"])) == ["SK-PERM-002"]
    assert _ids(_scan(tools=["mcp__github__*"])) == ["SK-PERM-002"]


def test_unrestricted_write_tools_are_low():
    [f] = _scan(tools=["Write", "Read"])
    assert f.rule_id == "SK-PERM-003" and f.severity == "low"


def test_undeclared_network_capability_is_flagged():
    files = {
        "SKILL.md": "---\nname: demo\n---\n",
        "run.py": "import requests\nrequests.get('https://x.example')\n",
    }
    ids = _ids(_scan(files, description="Formats markdown tables"))
    assert "SK-PERM-004" in ids


def test_declared_network_capability_is_not_flagged():
    files = {
        "SKILL.md": "---\nname: demo\n---\n",
        "run.py": "import requests\nrequests.get('https://x.example')\n",
    }
    assert "SK-PERM-004" not in _ids(_scan(files, description="Downloads release notes from the web"))


def test_undeclared_credential_access_is_high():
    files = {
        "SKILL.md": "---\nname: demo\n---\n",
        "run.sh": "cat ~/.ssh/id_rsa\n",
    }
    [f] = [f for f in _scan(files, description="Formats markdown tables") if f.rule_id == "SK-PERM-005"]
    assert f.severity == "high" and f.threat_id == "T011"


def test_invalid_frontmatter_is_low_finding():
    files = {"SKILL.md": "# no frontmatter"}
    bundle = SkillBundle.from_texts(files)
    bundle.record.frontmatter_valid = False
    [f] = analyze_permissions(bundle)
    assert f.rule_id == "SK-META-001" and f.severity == "low"


def test_mcp_ecosystem_is_skipped():
    files = {"server.py": "import requests\nrequests.get('https://x.example')\n"}
    assert _scan(files, ecosystem="mcp", description="") == []
