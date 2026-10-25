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

    def lookup(name, version, ecosystem):
        calls.append((name, version, ecosystem))
        return [
            Vulnerability(
                cve_id="CVE-2024-0001", severity="high", cvss_score=8.1, published=None,
                summary="Bad bug", source="osv", source_url=None,
            )
        ]

    findings = _scan({"requirements.txt": "requests==2.0.0\nflask>=2\n"}, osv_lookup=lookup)
    assert calls == [("requests", "2.0.0", "PyPI")]
    [vuln] = [f for f in findings if f.rule_id == "SK-SC-006"]
    assert vuln.severity == "high"
    assert "CVE-2024-0001" in vuln.evidence


def test_osv_unknown_severity_becomes_medium():
    def lookup(name, version, ecosystem):
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


# ── OSV lookups for npm package.json dependencies ────────────────────────────


def _vuln(cve="CVE-2024-0002", severity="critical", summary="Prototype pollution"):
    return Vulnerability(cve_id=cve, severity=severity, cvss_score=9.8, published=None,
                         summary=summary, source="osv", source_url=None)


def _recording_lookup(calls, result=None):
    def lookup(name, version, ecosystem):
        calls.append((name, version, ecosystem))
        return [_vuln()] if result is None else result
    return lookup


def test_osv_lookup_for_exact_pinned_npm_dependency():
    calls = []
    pkg = '{\n  "name": "x",\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n'
    findings = _scan({"package.json": pkg}, osv_lookup=_recording_lookup(calls))
    assert calls == [("lodash", "4.17.20", "npm")]
    [vuln] = [f for f in findings if f.rule_id == "SK-SC-006"]
    assert vuln.severity == "critical"
    assert vuln.file_path == "package.json"
    assert vuln.line_number == 4
    assert vuln.evidence.startswith("lodash@4.17.20: CVE-2024-0002 Prototype pollution")
    assert vuln.title == "Known vulnerability in lodash@4.17.20"


def test_osv_npm_scoped_package_name_is_passed_unchanged():
    calls = []
    pkg = '{"dependencies": {"@Scope/My_Pkg": "=1.0.0", "Left-Pad": "v1.3.0"}}'
    _scan({"package.json": pkg}, osv_lookup=_recording_lookup(calls, []))
    assert calls == [("@Scope/My_Pkg", "1.0.0", "npm"), ("Left-Pad", "1.3.0", "npm")]


def test_osv_npm_dev_and_optional_dependencies_are_looked_up():
    calls = []
    pkg = ('{"devDependencies": {"jest": "29.7.0"},'
           ' "optionalDependencies": {"fsevents": "2.3.3-beta.1"}}')
    _scan({"package.json": pkg}, osv_lookup=_recording_lookup(calls, []))
    assert sorted(calls) == [("fsevents", "2.3.3-beta.1", "npm"), ("jest", "29.7.0", "npm")]


def test_osv_npm_ranges_urls_and_tags_are_not_looked_up():
    calls = []
    specs = ["^1.2.3", "~1.2.3", ">=1.0.0", "*", "latest", "1.x", "1.2", "1.2.x", "",
             "1.0.0 - 2.0.0", "1.0.0 || 2.0.0", "github:x/y", "https://x.test/a.tgz",
             "git+https://x.test/r.git", "file:../lib", "npm:other@1.0.0", "next"]
    deps = ", ".join(f'"p{i}": "{s}"' for i, s in enumerate(specs))
    _scan({"package.json": f'{{"dependencies": {{{deps}}}}}'}, osv_lookup=_recording_lookup(calls))
    assert calls == []


def test_npm_pinned_dependency_without_lookup_yields_no_vuln_finding():
    assert _scan({"package.json": '{"dependencies": {"lodash": "4.17.20"}}'}) == []
