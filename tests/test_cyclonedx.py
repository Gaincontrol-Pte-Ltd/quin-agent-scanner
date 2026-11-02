"""CycloneDX AI-BOM mapping (spec: docs/superpowers/specs/2026-11-02-cyclonedx-ai-bom-design.md)."""
from __future__ import annotations

import json
import re

from quin_scanner import __version__
from quin_scanner.cyclonedx import (
    _iso_utc,
    _purl,
    _Refs,
    _repo_name,
    build_bom,
    omitted_vulnerability_count,
    to_cyclonedx,
)
from quin_scanner.models import ScanReport, Vulnerability
from quin_scanner.vuln_checker import FrameworkRef
from tests.cyclonedx_support import bom_errors


def _report(**fields) -> ScanReport:
    base = dict(
        repo_path="/home/dev/demo-repo",
        scan_timestamp="2026-11-02T10:15:30.123456+00:00",
        is_ai_application=True,
        confidence=0.9,
    )
    base.update(fields)
    return ScanReport(**base)


def _valid(bom: dict) -> dict:
    assert bom_errors(bom) == []
    return bom


class TestHeader:
    def test_header_fields(self):
        bom = _valid(build_bom(_report()))
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert bom["version"] == 1
        assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", bom["serialNumber"])

    def test_serial_number_is_new_every_time(self):
        assert build_bom(_report())["serialNumber"] != build_bom(_report())["serialNumber"]

    def test_metadata(self):
        meta = build_bom(_report())["metadata"]
        assert meta["timestamp"] == "2026-11-02T10:15:30Z"
        assert meta["tools"] == {"components": [{"type": "application", "name": "quin-scanner", "version": __version__}]}
        assert meta["component"] == {"type": "application", "bom-ref": "repo", "name": "demo-repo"}

    def test_empty_inventory_is_valid_and_has_only_the_root(self):
        bom = _valid(build_bom(_report()))
        assert "components" not in bom
        assert "services" not in bom
        assert "vulnerabilities" not in bom
        assert bom["dependencies"] == [{"ref": "repo"}]

    def test_to_cyclonedx_is_indented_json(self):
        text = to_cyclonedx(_report())
        assert text.startswith("{\n  \"bomFormat\": \"CycloneDX\"")
        assert json.loads(text)["specVersion"] == "1.6"

    def test_non_ascii_is_kept(self):
        text = to_cyclonedx(_report(repo_path="/home/dev/démo"))
        assert "démo" in text


class TestRepoName:
    def test_github_owner_and_repo(self):
        assert _repo_name("acme/agents") == "acme/agents"

    def test_local_path_uses_the_directory_name(self):
        assert _repo_name("/home/dev/demo-repo/") == "demo-repo"

    def test_windows_path(self):
        assert _repo_name("C:\\work\\demo") == "demo"

    def test_git_suffix_is_removed(self):
        assert _repo_name("/srv/demo.git") == "demo"

    def test_empty_falls_back(self):
        assert _repo_name("") == "repository"


class TestIsoUtc:
    def test_offset_datetime(self):
        assert _iso_utc("2026-11-02T12:15:30+02:00") == "2026-11-02T10:15:30Z"

    def test_z_suffix(self):
        assert _iso_utc("2024-08-15T09:00:00Z") == "2024-08-15T09:00:00Z"

    def test_bare_date(self):
        assert _iso_utc("2024-08-15") == "2024-08-15T00:00:00Z"

    def test_naive_datetime_is_utc(self):
        assert _iso_utc("2024-08-15T09:00:00") == "2024-08-15T09:00:00Z"

    def test_unparsable_and_empty(self):
        assert _iso_utc("last week") is None
        assert _iso_utc("") is None
        assert _iso_utc(None) is None


class TestRefs:
    def test_first_use_is_unchanged_and_repeats_get_a_counter(self):
        refs = _Refs()
        assert refs.take("service:mcp:fs") == "service:mcp:fs"
        assert refs.take("service:mcp:fs") == "service:mcp:fs#2"
        assert refs.take("service:mcp:fs") == "service:mcp:fs#3"

    def test_root_is_reserved(self):
        assert _Refs().take("repo") == "repo#2"


def _vuln(cve_id="CVE-2024-0001", severity="high", source="osv", **kw) -> Vulnerability:
    fields = dict(cve_id=cve_id, severity=severity, cvss_score=7.5, published="2024-08-15",
                  summary="Prompt injection in tool router", source=source,
                  source_url=f"https://osv.dev/vulnerability/{cve_id}")
    fields.update(kw)
    return Vulnerability(**fields)


class TestFramework:
    def test_framework_component(self):
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0")))
        assert bom["components"] == [{
            "type": "framework", "bom-ref": "pkg:pypi/crewai@0.80.0", "name": "crewai",
            "version": "0.80.0", "purl": "pkg:pypi/crewai@0.80.0",
        }]
        assert {"ref": "repo", "dependsOn": ["pkg:pypi/crewai@0.80.0"]} in bom["dependencies"]
        assert {"ref": "pkg:pypi/crewai@0.80.0"} in bom["dependencies"]

    def test_unresolvable_framework_gives_no_component(self):
        bom = _valid(build_bom(_report(framework="unknown")))
        assert "components" not in bom

    def test_pypi_names_are_normalised(self):
        assert _purl(FrameworkRef("X", "1.0", "PyPI", "Llama_Index.Core")) == "pkg:pypi/llama-index-core@1.0"

    def test_npm_scope_is_percent_encoded(self):
        assert _purl(FrameworkRef("Mastra", "0.10.1", "npm", "@mastra/core")) == "pkg:npm/%40mastra/core@0.10.1"

    def test_npm_without_scope(self):
        assert _purl(FrameworkRef("Vercel AI SDK", "4.0.0", "npm", "ai")) == "pkg:npm/ai@4.0.0"

    def test_unknown_ecosystem(self):
        assert _purl(FrameworkRef("X", "1.0", "Maven", "x")) is None


class TestVulnerabilities:
    def test_osv_vulnerability(self):
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[_vuln()])))
        assert bom["vulnerabilities"] == [{
            "bom-ref": "vuln:CVE-2024-0001",
            "id": "CVE-2024-0001",
            "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/CVE-2024-0001"},
            "ratings": [{"score": 7.5, "severity": "high"}],
            "description": "Prompt injection in tool router",
            "published": "2024-08-15T00:00:00Z",
            "affects": [{"ref": "pkg:pypi/crewai@0.80.0"}],
        }]

    def test_web_search_and_unidentified_entries_are_left_out(self):
        vulns = [_vuln("CVE-2024-0002", source="web:perplexity"), _vuln(None), _vuln("")]
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=vulns)))
        assert "vulnerabilities" not in bom

    def test_no_framework_component_means_no_vulnerabilities(self):
        bom = _valid(build_bom(_report(framework="unknown", vulnerabilities=[_vuln()])))
        assert "vulnerabilities" not in bom

    def test_optional_fields_are_omitted(self):
        v = _vuln(cvss_score=None, published="soon", summary="", source_url=None, severity="weird")
        out = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[v]))["vulnerabilities"][0]
        assert out["ratings"] == [{"severity": "unknown"}]
        assert out["source"] == {"name": "OSV"}
        assert "published" not in out and "description" not in out
        _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[v])))

    def test_sorted_by_severity_then_id_and_deduplicated(self):
        vulns = [_vuln("CVE-B", "medium"), _vuln("CVE-C", "critical"), _vuln("CVE-A", "medium"), _vuln("CVE-C", "critical")]
        bom = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=vulns))
        assert [v["id"] for v in bom["vulnerabilities"]] == ["CVE-C", "CVE-A", "CVE-B"]

    def test_omitted_count_counts_web_search_entries(self):
        vulns = [_vuln(), _vuln("CVE-2", source="web:gemini"), _vuln("CVE-3", source="web:openai")]
        assert omitted_vulnerability_count(_report(vulnerabilities=vulns)) == 2
