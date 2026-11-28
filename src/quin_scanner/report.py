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
    """Serializes ScanReport to JSON, YAML, HTML, SARIF or CycloneDX."""

    @staticmethod
    def to_json(report: ScanReport) -> str:
        return json.dumps(report.to_dict(), indent=2, default=str)

    @staticmethod
    def to_yaml(report: ScanReport) -> str:
        return yaml.dump(report.to_dict(), default_flow_style=False, allow_unicode=True)

    @staticmethod
    def to_html(report: ScanReport) -> str:
        from quin_scanner.html_template import HTML_TEMPLATE

        data = report.to_dict()
        data.pop("file_hashes", None)  # for matching agents to repositories, not for reading: keeps the page small
        # Display-only standardised type for the Artifacts tab (JSON/YAML/SARIF unchanged).
        from quin_scanner.artifact_types import annotate, type_order

        annotate(data["artifacts"])
        if data.get("governance"):
            annotate(data["governance"]["evidence"])
        data["artifact_type_order"] = type_order()
        data_json = json.dumps(data, indent=2, default=str)
        # Escape < > & so no `</script>` or `<!--`/`<script` sequence can reach the HTML parser from inside the
        # data block; U+2028/U+2029 are escaped for older JavaScript engines. JSON parsers read the escapes back.
        safe_json = (
            data_json.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
        )
        rendered = HTML_TEMPLATE.replace("{{REPORT_DATA_JSON}}", safe_json)
        return rendered.replace("{{LOGO_DATA_URI}}", _logo_data_uri())

    @staticmethod
    def to_sarif(report: ScanReport) -> str:
        from quin_scanner.sarif import to_sarif as _to_sarif

        return _to_sarif(report)

    @staticmethod
    def to_cyclonedx(report: ScanReport) -> str:
        from quin_scanner import cyclonedx

        try:
            return cyclonedx.to_cyclonedx(report)
        except Exception as exc:  # noqa: BLE001 - any failure means no BOM; say why
            raise RuntimeError(f"could not build the CycloneDX BOM: {exc}") from exc

    @classmethod
    def to_string(cls, report: ScanReport, fmt: str) -> str:
        """Return report as a string in the given format ('json', 'yaml', 'html', 'sarif', or 'cyclonedx')."""
        if fmt == "yaml":
            return cls.to_yaml(report)
        if fmt == "html":
            return cls.to_html(report)
        if fmt == "sarif":
            return cls.to_sarif(report)
        if fmt == "cyclonedx":
            return cls.to_cyclonedx(report)
        return cls.to_json(report)

    @classmethod
    def write_to_file(cls, report: ScanReport, path: str, fmt: str) -> None:
        """Write report to a file."""
        content = cls.to_string(report, fmt)
        # newline="\n": the same bytes on every OS (text mode would write CRLF on Windows)
        Path(path).write_text(content, encoding="utf-8", newline="\n")
