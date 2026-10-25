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


def test_dangerous_prefix_bash_grants_are_perm001():
    for t in ("curl", "wget", "rm", "sudo", "sh", "bash", "eval"):
        assert _ids(_scan(tools=[f"Bash({t}:*)"])) == ["SK-PERM-001"], t


def _perm4(description, name="demo"):
    code = {"SKILL.md": "---\nname: demo\n---\nx", "run.py": "import requests\nrequests.get('http://x')\n"}
    bundle = SkillBundle.from_texts(code, name=name, description=description)
    return [f.rule_id for f in analyze_permissions(bundle)]


def _perm5(description):
    code = {"SKILL.md": "---\nname: demo\n---\nx", "run.py": "open('~/.ssh/id_rsa')\n"}
    bundle = SkillBundle.from_texts(code, description=description)
    return [f.rule_id for f in analyze_permissions(bundle)]


def test_word_boundary_matching_avoids_substring_false_negatives():
    assert "SK-PERM-004" in _perm4("Manage capital budgets")        # 'capital' != 'api'
    assert "SK-PERM-004" in _perm4("Run async tasks locally")        # 'async' != 'sync'
    assert "SK-PERM-005" in _perm5("Explains laws and keyboard shortcuts")   # laws != aws, keyboard != key


def test_word_boundary_matching_still_accepts_real_declarations():
    assert "SK-PERM-004" not in _perm4("Calls the GitHub API and fetches pages")
    assert "SK-PERM-004" not in _perm4("Downloads reports over https")
    assert "SK-PERM-004" not in _perm4("Browses and scrapes sites")
    assert "SK-PERM-005" not in _perm5("Reads your SSH keys and AWS credentials")
    assert "SK-PERM-005" not in _perm5("Handles authentication tokens")


# ── Regressions from the 2026-10 public skill-repo tuning run ───────────────


def _undeclared(code, path="run.py"):
    files = {"SKILL.md": "---\nname: demo\n---\nx", path: code}
    return _ids(_scan(files, description="Formats markdown tables"))


def test_perm004_english_word_requests_is_not_a_network_call():
    assert "SK-PERM-004" not in _undeclared('"- Concrete examples with realistic user requests"\n')
    assert "SK-PERM-004" not in _undeclared('return "too many requests" in msg\n')
    assert "SK-PERM-004" not in _undeclared("touchActivity(); // only authorized requests count\n",
                                            path="server.cjs")
    for code in ("import requests\n", "from requests import get\n",
                 "r = requests.get(url)\n", "s = requests.Session()\n", "import httpx\n"):
        assert "SK-PERM-004" in _undeclared(code), code


def test_perm005_public_key_is_not_a_credential_file():
    assert "SK-PERM-005" not in _undeclared("key = open(os.path.expanduser('~/.ssh/id_rsa.pub')).read()\n")
    assert "SK-PERM-005" in _undeclared("key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n")
    assert "SK-PERM-005" in _undeclared("cat ~/.aws/credentials\n", path="run.sh")
