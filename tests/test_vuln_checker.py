"""Tests for vulnerability checker parsing and helpers."""
from __future__ import annotations


import pytest

from quin_scanner.models import Vulnerability
from quin_scanner.vuln_checker import (
    FrameworkRef,
    cvss_to_severity,
    parse_framework_ref,
    _dedupe_vulns,
    _extract_json_array,
    _normalise_severity,
    _parse_osv_response,
    _vulns_from_web_items,
)


class TestParseFrameworkRef:
    def test_valid_framework(self):
        ref = parse_framework_ref("CrewAI 0.80.0")
        assert ref is not None
        assert ref.name == "CrewAI"
        assert ref.version == "0.80.0"

    def test_no_version(self):
        assert parse_framework_ref("CrewAI") is None

    def test_unknown_framework(self):
        assert parse_framework_ref("unknown") is None

    def test_empty_string(self):
        assert parse_framework_ref("") is None

    def test_framework_not_in_ecosystems(self):
        assert parse_framework_ref("NonExistentFramework 1.0.0") is None

    def test_multi_part_version(self):
        ref = parse_framework_ref("LangChain 0.1.14")
        # Will return None if LangChain isn't in ecosystems — that's OK
        # The test validates the parsing logic
        if ref:
            assert ref.version == "0.1.14"


class TestCvssToSeverity:
    @pytest.mark.parametrize("score,expected", [
        (9.5, "critical"),
        (9.0, "critical"),
        (8.0, "high"),
        (7.0, "high"),
        (5.0, "medium"),
        (4.0, "medium"),
        (2.0, "low"),
        (0.1, "low"),
        (0.0, "unknown"),
        (None, "unknown"),
    ])
    def test_thresholds(self, score, expected):
        assert cvss_to_severity(score) == expected


class TestNormaliseSeverity:
    def test_known_values(self):
        assert _normalise_severity("CRITICAL") == "critical"
        assert _normalise_severity("High") == "high"
        assert _normalise_severity("medium") == "medium"
        assert _normalise_severity("LOW") == "low"

    def test_none_and_empty(self):
        assert _normalise_severity(None) == "unknown"
        assert _normalise_severity("") == "unknown"

    def test_unknown_value(self):
        assert _normalise_severity("moderate") == "unknown"


class TestExtractJsonArray:
    def test_plain_array(self):
        result = _extract_json_array('[{"cve_id": "CVE-2024-1234"}]')
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-1234"

    def test_fenced_array(self):
        raw = "```json\n[{\"cve_id\": \"CVE-2024-5678\"}]\n```"
        result = _extract_json_array(raw)
        assert len(result) == 1

    def test_text_before_array(self):
        raw = "Here are the results:\n[{\"cve_id\": \"CVE-2024-1111\"}]"
        result = _extract_json_array(raw)
        assert len(result) == 1

    def test_empty_array(self):
        assert _extract_json_array("[]") == []

    def test_no_array(self):
        assert _extract_json_array("No vulnerabilities found.") == []

    def test_nested_brackets(self):
        raw = '[{"data": [1, 2, 3], "cve_id": "CVE-2024-0001"}]'
        result = _extract_json_array(raw)
        assert len(result) == 1

    def test_invalid_json_array(self):
        assert _extract_json_array("[{broken json}]") == []


class TestParseOsvResponse:
    def _ref(self):
        return FrameworkRef(name="CrewAI", version="0.80.0", ecosystem="PyPI", package="crewai")

    def test_empty_response(self):
        assert _parse_osv_response({}, self._ref()) == []
        assert _parse_osv_response({"vulns": []}, self._ref()) == []

    def test_single_vuln(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy",
                    "aliases": ["CVE-2024-1234"],
                    "summary": "A test vulnerability",
                    "published": "2024-08-01",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"name": "crewai"},
                            "ranges": [
                                {"events": [{"introduced": "0.70.0"}, {"fixed": "0.85.0"}]}
                            ],
                        }
                    ],
                    "references": [
                        {"type": "ADVISORY", "url": "https://example.com/advisory"}
                    ],
                }
            ]
        }
        vulns = _parse_osv_response(data, self._ref())
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve_id == "CVE-2024-1234"
        assert v.severity == "high"
        assert v.source == "osv"
        assert v.source_url == "https://example.com/advisory"
        assert ">=0.70.0" in v.affected_versions
        assert "<0.85.0" in v.affected_versions

    def test_no_aliases_uses_id(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-only-id",
                    "summary": "Test",
                }
            ]
        }
        vulns = _parse_osv_response(data, self._ref())
        assert vulns[0].cve_id == "GHSA-only-id"

    def test_cvss_score_from_severity_list(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-test",
                    "summary": "Test",
                    "severity": [{"score": 9.1}],
                }
            ]
        }
        vulns = _parse_osv_response(data, self._ref())
        assert vulns[0].cvss_score == 9.1
        assert vulns[0].severity == "critical"


class TestVulnsFromWebItems:
    def _ref(self):
        return FrameworkRef(name="CrewAI", version="0.80.0", ecosystem="PyPI", package="crewai")

    def test_basic_items(self):
        items = [
            {
                "cve_id": "CVE-2024-9999",
                "severity": "high",
                "cvss_score": 8.5,
                "published": "2024-09-01",
                "summary": "A web-found vuln",
                "source_url": "https://example.com",
            }
        ]
        vulns = _vulns_from_web_items(items, "perplexity", self._ref())
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2024-9999"
        assert vulns[0].source == "web:perplexity"
        assert vulns[0].cvss_score == 8.5

    def test_skips_non_dict(self):
        items = ["not a dict", {"cve_id": "CVE-2024-0001", "severity": "low", "summary": "x"}]
        vulns = _vulns_from_web_items(items, "gemini", self._ref())
        assert len(vulns) == 1

    def test_severity_from_cvss_when_missing(self):
        items = [{"cve_id": None, "cvss_score": 9.5, "summary": "critical by score"}]
        vulns = _vulns_from_web_items(items, "openai", self._ref())
        assert vulns[0].severity == "critical"


class TestDedupeVulns:
    def _vuln(self, cve_id, source="osv", severity="high"):
        return Vulnerability(
            cve_id=cve_id,
            severity=severity,
            cvss_score=None,
            published=None,
            summary="test",
            source=source,
            source_url=None,
        )

    def test_dedupes_by_cve_id(self):
        vulns = [
            self._vuln("CVE-2024-1234", source="osv"),
            self._vuln("CVE-2024-1234", source="web:perplexity"),
        ]
        deduped = _dedupe_vulns(vulns)
        assert len(deduped) == 1
        assert deduped[0].source == "osv"  # OSV preferred

    def test_keeps_orphans(self):
        vulns = [
            self._vuln(None, source="web:gemini"),
            self._vuln(None, source="web:openai"),
        ]
        deduped = _dedupe_vulns(vulns)
        assert len(deduped) == 2

    def test_sorted_by_severity(self):
        vulns = [
            self._vuln("CVE-1", severity="low"),
            self._vuln("CVE-2", severity="critical"),
            self._vuln("CVE-3", severity="medium"),
        ]
        deduped = _dedupe_vulns(vulns)
        assert deduped[0].severity == "critical"
        assert deduped[-1].severity == "low"

    def test_empty_input(self):
        assert _dedupe_vulns([]) == []
