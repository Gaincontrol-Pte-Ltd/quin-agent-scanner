from quin_scanner.models import Vulnerability
from quin_scanner.scanners.skills.analyzers.supply_chain import (
    analyze_supply_chain,
    edit_distance_one,
)
from quin_scanner.scanners.skills.bundle import SkillBundle


def _scan(files, **kw):
    return analyze_supply_chain(SkillBundle.from_texts(files), **kw)


def _ids(findings):
    return [f.rule_id for f in findings]


def test_edit_distance_one():
    assert edit_distance_one("requests", "reqests")      # deletion
    assert edit_distance_one("requests", "requestss")    # insertion
    assert edit_distance_one("requests", "reqeusts")     # transposition
    assert edit_distance_one("requests", "requesta")     # substitution
    assert not edit_distance_one("requests", "requests")
    assert not edit_distance_one("requests", "flask")


def test_requirements_unpinned_and_pinned():
    findings = _scan({"requirements.txt": "requests==2.31.0\nflask>=2.0\nrich\n"})
    assert _ids(findings) == ["SK-SC-001", "SK-SC-001"]
    assert [f.line_number for f in findings] == [2, 3]
    assert all(f.severity == "low" for f in findings)


def test_requirements_typosquat_and_url_dependency():
    findings = _scan(
        {"requirements.txt": "reqeusts==1.0\nmypkg @ git+https://github.com/x/y.git\n"}
    )
    ids = _ids(findings)
    assert "SK-SC-002" in ids and "SK-SC-003" in ids
    typo = next(f for f in findings if f.rule_id == "SK-SC-002")
    assert typo.severity == "medium" and typo.threat_id == "T003"


def test_known_popular_package_is_not_a_typosquat():
    assert "SK-SC-002" not in _ids(_scan({"requirements.txt": "requests==2.31.0\n"}))


def test_package_json_checks():
    pkg = (
        '{"dependencies": {"left-pad": "*", "expres": "^4.0.0", "tool": "github:x/y"},'
        ' "scripts": {"postinstall": "node setup.js"}}'
    )
    ids = _ids(_scan({"package.json": pkg}))
    assert ids.count("SK-SC-001") == 1   # left-pad "*"
    assert "SK-SC-002" in ids            # expres ~ express
    assert "SK-SC-003" in ids            # github: dependency
    assert "SK-SC-004" in ids            # postinstall script


def test_invalid_package_json_is_ignored():
    assert _scan({"package.json": "{not json"}) == []


def test_install_commands_in_markdown_and_shell():
    md = "Run `pip install requests pyyaml==6.0` then `npx -y some-tool` and `npx pinned@1.2.3`.\n"
    findings = _scan({"SKILL.md": md})
    evidence = " ".join(f.evidence for f in findings)
    assert all(f.rule_id == "SK-SC-005" for f in findings)
    assert "requests" in evidence and "some-tool" in evidence
    assert "pyyaml" not in evidence and "pinned" not in evidence


def test_pip_requirements_flag_is_not_flagged():
    assert _scan({"setup.sh": "pip install -r requirements.txt\n"}) == []


def test_osv_lookup_for_pinned_pypi_requirements():
    calls = []

    def lookup(name, version):
        calls.append((name, version))
        return [
            Vulnerability(
                cve_id="CVE-2024-0001", severity="high", cvss_score=8.1, published=None,
                summary="Bad bug", source="osv", source_url=None,
            )
        ]

    findings = _scan({"requirements.txt": "requests==2.0.0\nflask>=2\n"}, osv_lookup=lookup)
    assert calls == [("requests", "2.0.0")]
    [vuln] = [f for f in findings if f.rule_id == "SK-SC-006"]
    assert vuln.severity == "high"
    assert "CVE-2024-0001" in vuln.evidence


def test_osv_unknown_severity_becomes_medium():
    def lookup(name, version):
        return [Vulnerability(cve_id=None, severity="unknown", cvss_score=None, published=None,
                              summary="x", source="osv", source_url=None)]
    [f] = [f for f in _scan({"requirements.txt": "a-lib==1.0\n"}, osv_lookup=lookup)
           if f.rule_id == "SK-SC-006"]
    assert f.severity == "medium"


# ── Regressions from the 2026-10 public skill-repo tuning run ───────────────


def test_pip_install_args_stop_at_the_end_of_the_command_in_prose():
    md = ("Install them with its own package manager (e.g. npm install, pip install -r "
          "requirements.txt) unless told not to. Only if no real check can run here, say so.\n")
    assert _scan({"SKILL.md": md}) == []
    md2 = "Run pip install pypdf, then open the file. Use pip install rich. Done.\n"
    assert sorted(f.evidence for f in _scan({"SKILL.md": md2})) == [
        "pip install pypdf", "pip install rich"]


def test_unpinned_install_reported_once_per_package_per_file():
    md = "".join(f"Step {i}: `npx wrangler deploy`\n" for i in range(30))
    md += "`pip install azure-identity`\n`pip install azure-identity`\n"
    findings = _scan({"SKILL.md": md, "other.md": "`npx wrangler dev`\n"})
    assert sorted((f.file_path, f.evidence) for f in findings) == [
        ("SKILL.md", "npx wrangler"), ("SKILL.md", "pip install azure-identity"),
        ("other.md", "npx wrangler")]
    assert next(f for f in findings if f.evidence == "npx wrangler"
                and f.file_path == "SKILL.md").line_number == 1
