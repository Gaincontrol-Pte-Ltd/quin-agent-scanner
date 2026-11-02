"""CycloneDX AI-BOM mapping (spec: docs/superpowers/specs/2026-11-02-cyclonedx-ai-bom-design.md)."""
from __future__ import annotations

import json
import re

from quin_scanner import __version__
from quin_scanner.cyclonedx import _iso_utc, _Refs, _repo_name, build_bom, to_cyclonedx
from quin_scanner.models import ScanReport
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
