from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from quin_scanner.models import ScanReport

_LOGO_PATH = Path(__file__).parent / "logo.png"


def _logo_data_uri() -> str:
    """Return the bundled logo as a base64 data URI, or empty string if missing."""
    try:
        encoded = base64.b64encode(_LOGO_PATH.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


class ReportGenerator:
    """Serializes ScanReport to JSON, YAML, or HTML."""

    @staticmethod
    def to_json(report: ScanReport) -> str:
        return json.dumps(report.to_dict(), indent=2, default=str)

    @staticmethod
    def to_yaml(report: ScanReport) -> str:
        return yaml.dump(report.to_dict(), default_flow_style=False, allow_unicode=True)

    @staticmethod
    def to_html(report: ScanReport) -> str:
        from quin_scanner.html_template import HTML_TEMPLATE

        data_json = json.dumps(report.to_dict(), indent=2, default=str)
        # Escape </script> sequences to prevent XSS when embedding in a <script> tag
        safe_json = data_json.replace("</", "<\\/")
        rendered = HTML_TEMPLATE.replace("{{REPORT_DATA_JSON}}", safe_json)
        return rendered.replace("{{LOGO_DATA_URI}}", _logo_data_uri())

    @staticmethod
    def to_sarif(report: ScanReport) -> str:
        from quin_scanner.sarif import to_sarif as _to_sarif

        return _to_sarif(report)

    @classmethod
    def to_string(cls, report: ScanReport, fmt: str) -> str:
        """Return report as a string in the given format ('json', 'yaml', 'html', or 'sarif')."""
        if fmt == "yaml":
            return cls.to_yaml(report)
        if fmt == "html":
            return cls.to_html(report)
        if fmt == "sarif":
            return cls.to_sarif(report)
        return cls.to_json(report)

    @classmethod
    def write_to_file(cls, report: ScanReport, path: str, fmt: str) -> None:
        """Write report to a file."""
        content = cls.to_string(report, fmt)
        Path(path).write_text(content, encoding="utf-8")
