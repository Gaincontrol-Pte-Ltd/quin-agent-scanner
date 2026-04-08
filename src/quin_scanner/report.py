from __future__ import annotations

import json
from pathlib import Path

import yaml

from quin_scanner.models import ScanReport


class ReportGenerator:
    """Serializes ScanReport to JSON or YAML."""

    @staticmethod
    def to_json(report: ScanReport) -> str:
        return json.dumps(report.to_dict(), indent=2, default=str)

    @staticmethod
    def to_yaml(report: ScanReport) -> str:
        return yaml.dump(report.to_dict(), default_flow_style=False, allow_unicode=True)

    @classmethod
    def to_string(cls, report: ScanReport, fmt: str) -> str:
        """Return report as a string in the given format ('json' or 'yaml')."""
        if fmt == "yaml":
            return cls.to_yaml(report)
        return cls.to_json(report)

    @classmethod
    def write_to_file(cls, report: ScanReport, path: str, fmt: str) -> None:
        """Write report to a file."""
        content = cls.to_string(report, fmt)
        Path(path).write_text(content, encoding="utf-8")
