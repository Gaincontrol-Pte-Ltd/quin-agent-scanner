"""Tests for report generation and HTML XSS escaping."""
from __future__ import annotations

import json

import yaml

from quin_scanner.models import ScanReport, ScanFinding
from quin_scanner.report import ReportGenerator


def _minimal_report(**kwargs) -> ScanReport:
    defaults = dict(
        repo_path="/tmp/test-repo",
        scan_timestamp="2025-01-01T00:00:00Z",
        is_ai_application=True,
        confidence=0.95,
        capability_tags=["llm-api"],
    )
    defaults.update(kwargs)
    return ScanReport(**defaults)


class TestToJson:
    def test_valid_json_output(self):
        report = _minimal_report()
        result = ReportGenerator.to_json(report)
        data = json.loads(result)
        assert data["repo_path"] == "/tmp/test-repo"
        assert data["is_ai_application"] is True
        assert data["confidence"] == 0.95

    def test_round_trip(self):
        report = _minimal_report(framework="LangChain", summary="Test summary")
        result = ReportGenerator.to_json(report)
        data = json.loads(result)
        assert data["framework"] == "LangChain"
        assert data["summary"] == "Test summary"


class TestToYaml:
    def test_valid_yaml_output(self):
        report = _minimal_report()
        result = ReportGenerator.to_yaml(report)
        data = yaml.safe_load(result)
        assert data["repo_path"] == "/tmp/test-repo"
        assert data["is_ai_application"] is True


class TestToHtml:
    def test_contains_report_data(self):
        report = _minimal_report()
        html = ReportGenerator.to_html(report)
        assert "window.__REPORT_DATA__" in html
        assert "/tmp/test-repo" in html

    def test_xss_script_tag_escaped(self):
        """Ensure </script> in scan data cannot break out of the script tag."""
        report = _minimal_report(
            artifacts=[
                ScanFinding(
                    scanner_name="TestScanner",
                    category="test",
                    file_path="</script><script>alert(1)</script>",
                    line_number=1,
                    match_text="malicious",
                    capability_tag="xss",
                    confidence=1.0,
                )
            ]
        )
        html = ReportGenerator.to_html(report)
        # The raw </script> must NOT appear in the HTML output
        assert "</script><script>alert(1)</script>" not in html
        # The escaped version should be present
        assert "<\\/script>" in html

    def test_xss_in_match_text(self):
        """Ensure </script> in match_text is also escaped."""
        report = _minimal_report(
            artifacts=[
                ScanFinding(
                    scanner_name="TestScanner",
                    category="test",
                    file_path="safe.py",
                    line_number=1,
                    match_text='</script><img src=x onerror=alert(1)>',
                    capability_tag="test",
                    confidence=0.5,
                )
            ]
        )
        html = ReportGenerator.to_html(report)
        # The template has its own </script> tags but the injected one must be escaped
        assert '</script><img' not in html


class TestToString:
    def test_json_format(self):
        report = _minimal_report()
        result = ReportGenerator.to_string(report, "json")
        json.loads(result)  # should not raise

    def test_yaml_format(self):
        report = _minimal_report()
        result = ReportGenerator.to_string(report, "yaml")
        yaml.safe_load(result)  # should not raise

    def test_html_format(self):
        report = _minimal_report()
        result = ReportGenerator.to_string(report, "html")
        assert "<html" in result

    def test_sarif_format(self):
        report = _minimal_report()
        result = ReportGenerator.to_string(report, "sarif")
        data = json.loads(result)
        assert data["version"] == "2.1.0"


class TestToSarif:
    def test_valid_sarif_output(self):
        report = _minimal_report()
        result = ReportGenerator.to_sarif(report)
        data = json.loads(result)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "quin-scanner"


class TestWriteToFile:
    def test_writes_file(self, tmp_path):
        report = _minimal_report()
        out_path = str(tmp_path / "report.json")
        ReportGenerator.write_to_file(report, out_path, "json")
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["repo_path"] == "/tmp/test-repo"
