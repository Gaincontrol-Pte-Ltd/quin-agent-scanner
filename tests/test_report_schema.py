"""The report schema is a contract: output must validate, and the schema must stay compatible."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from quin_scanner.cli import cli
from quin_scanner.config import ScannerConfig
from quin_scanner.models import (
    AgentProfile,
    AgentToolRelationship,
    EndpointUsage,
    EvidenceRef,
    GovernanceInfo,
    InfraProfile,
    MCPServer,
    ModelUsage,
    RiskIndicator,
    ScanFinding,
    ScanReport,
    SkillAssessment,
    SkillFinding,
    SkillRecord,
    ToolUsage,
    Vulnerability,
)
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.report import ReportGenerator
from quin_scanner.schema import REPORT_SCHEMA_VERSION

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "docs" / "schema"
BASELINE_DIR = Path(__file__).resolve().parent / "schema_baseline"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "skills_repo"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


REPORT_SCHEMA = _load(SCHEMA_DIR / "report-1.json")
ENVELOPE_SCHEMA = _load(SCHEMA_DIR / "skills-scan-1.json")
REGISTRY = Registry().with_resources([(REPORT_SCHEMA["$id"], Resource.from_contents(REPORT_SCHEMA))])


def _validate_report(data: dict) -> None:
    Draft202012Validator(REPORT_SCHEMA).validate(data)


def _validate_envelope(data: dict) -> None:
    Draft202012Validator(ENVELOPE_SCHEMA, registry=REGISTRY).validate(data)


def _finding() -> ScanFinding:
    return ScanFinding("Scanner", "category", "a.py", 3, "match", "llm-api", 0.9)


def _rich_report() -> ScanReport:
    """A report with every record type populated, including nullable variants."""
    risk = RiskIndicator(
        signal="s", recommended_controls=["C001: Input Validation"], threat_id="T001",
        severity="high", evidence_refs=[EvidenceRef(file_path="a.py", line_number=3, scanner="X", source_url="")],
    )
    skill = SkillAssessment(
        record=SkillRecord(id="1", name="demo", description="d", root_path="s", skill_md_path="s/SKILL.md",
                           ecosystem="claude", allowed_tools=["Read"], files=["s/SKILL.md"]),
        findings=[SkillFinding(rule_id="SK-PI-001", skill_id="1", severity="high", category="prompt_injection",
                               title="t", file_path="s/SKILL.md", line_number=None, evidence="e",
                               threat_id="T001", confidence=0.8)],
        risk_score=14, verdict="SAFE", finding_counts={"high": 1}, top_rule_ids=["SK-PI-001"],
    )
    return ScanReport(
        repo_path="r", scan_timestamp="2026-10-26T00:00:00+00:00", is_ai_application=True, confidence=0.9,
        capability_tags=["llm-api"], artifacts=[_finding()], framework="CrewAI 0.80.0", summary="s",
        agents=[AgentProfile(name="a", agent_type="worker", goal="g", capabilities=["c"], risk_signals=[risk],
                             skills=["k"], tools=["t"], source_file="a.py")],
        tool_usages=[ToolUsage(tool_name="t", line_number=None)], risk_signals=[risk],
        mcp_servers=[MCPServer(name="n", transport="stdio", source_file="mcp.json")],
        infra=InfraProfile(platform="docker", details=["d"], source_files=["Dockerfile"]),
        vulnerabilities=[Vulnerability(cve_id=None, severity="high", cvss_score=None, published=None, summary="s",
                                       source="osv", source_url=None, affected_versions=None)],
        model_usages=[ModelUsage(provider="openai", model_name="gpt-4o", source="code", file_path="a.py",
                                 line_number=1, role="primary")],
        agent_tool_relationships=[AgentToolRelationship(agent_name="a", tool_name="t", source_file="a.py",
                                                        line_number=None, tool_source_file="", tool_line_number=None,
                                                        evidence="e")],
        inventory=[_finding().to_dict()], coverage={"files_discovered": 1},
        llm_endpoints=[EndpointUsage(url="http://x", host="x", kind="local", source="code", file_path="a.py",
                                     line_number=None, key="base_url", resolved_from="")],
        metadata={"scan_duration_seconds": 0.1}, skills=[skill],
        file_hashes=[{"path": "a.py", "sha256": "0" * 64}],
        governance=GovernanceInfo(aegis_detected=True, status="governed", evidence_kinds=["import"],
                                  packages=["aegis-core"], evidence=[_finding()]),
    )


# --- schema_version -------------------------------------------------------------------------

def test_report_carries_schema_version_first():
    data = _rich_report().to_dict()
    assert data["schema_version"] == REPORT_SCHEMA_VERSION == "1.0"
    assert next(iter(data)) == "schema_version"


def test_json_and_yaml_outputs_carry_schema_version():
    report = _rich_report()
    assert json.loads(ReportGenerator.to_json(report))["schema_version"] == "1.0"
    assert yaml.safe_load(ReportGenerator.to_yaml(report))["schema_version"] == "1.0"


def test_version_option_mentions_the_report_schema_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "quin-scanner, version " in result.output
    assert f"report schema {REPORT_SCHEMA_VERSION}" in result.output


# --- validation -----------------------------------------------------------------------------

def test_rich_report_validates_against_the_report_schema():
    _validate_report(_rich_report().to_dict())


def test_report_without_optional_governance_validates():
    report = _rich_report()
    report.governance = None
    data = report.to_dict()
    assert "governance" not in data
    _validate_report(data)


def test_real_scan_output_validates():
    config = ScannerConfig(enabled_scanners=["skills", "prompt_discovery"], no_llm=True, vuln_check_enabled=False)
    report = ScanOrchestrator().run(LocalRepoAccessor(FIXTURE), config, verbose=False)
    _validate_report(report.to_dict())


def test_json_and_yaml_files_from_the_cli_validate(tmp_path):
    for fmt, loader in (("json", json.loads), ("yaml", yaml.safe_load)):
        out = tmp_path / f"report.{fmt}"
        result = CliRunner().invoke(
            cli, ["scan", str(FIXTURE), "-o", fmt, "-f", str(out), "--no-llm", "--no-vuln-check"]
        )
        assert result.exit_code == 0, result.output
        _validate_report(loader(out.read_text(encoding="utf-8")))


def test_invalid_report_is_rejected():
    data = _rich_report().to_dict()
    del data["repo_path"]
    with pytest.raises(Exception):
        _validate_report(data)
    data = _rich_report().to_dict()
    data["skills"][0]["verdict"] = "MAYBE"
    with pytest.raises(Exception):
        _validate_report(data)


def test_skills_scan_envelope_validates(tmp_path):
    out = CliRunner().invoke(cli, ["skills", "scan", str(FIXTURE), "-o", "json", "--no-vuln-check"])
    assert out.exit_code == 1, out.output  # evil-formatter is HIGH_RISK
    envelope = json.loads(out.stdout)
    assert envelope["schema_version"] == "1.0"
    _validate_envelope(envelope)


def test_skills_scan_envelope_with_baseline_validates(tmp_path):
    baseline = tmp_path / "baseline.yaml"
    result = CliRunner().invoke(cli, ["skills", "baseline", str(FIXTURE), "-o", str(baseline), "--no-vuln-check"])
    assert result.exit_code == 0, result.output
    out = CliRunner().invoke(
        cli, ["skills", "scan", str(FIXTURE), "-o", "json", "--no-vuln-check", "--baseline", str(baseline)]
    )
    assert out.exit_code == 0, out.output
    envelope = json.loads(out.stdout)
    assert set(envelope["metadata"]["skills_baseline"]) >= {"file", "suppressed_count", "stale_count"}
    _validate_envelope(envelope)


# --- every emitted field is documented ------------------------------------------------------

def _resolve(schema: dict, root: dict) -> dict:
    while "$ref" in schema:
        node = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            node = node[part]
        schema = node
    return schema


def _object_schema(schema: dict, root: dict) -> dict:
    schema = _resolve(schema, root)
    for option in schema.get("oneOf", []):
        option = _resolve(option, root)
        if option.get("type") != "null":
            return option
    return schema


def _undocumented(instance, schema: dict, root: dict, path: str = "$") -> list[str]:
    node = _object_schema(schema, root)
    found: list[str] = []
    if isinstance(instance, dict) and "properties" in node:
        for key, value in instance.items():
            if key not in node["properties"]:
                found.append(f"{path}.{key}")
            else:
                found += _undocumented(value, node["properties"][key], root, f"{path}.{key}")
    elif isinstance(instance, list) and "items" in node:
        for index, item in enumerate(instance):
            found += _undocumented(item, node["items"], root, f"{path}[{index}]")
    return found


def test_every_emitted_field_is_documented_in_the_schema():
    assert _undocumented(_rich_report().to_dict(), REPORT_SCHEMA, REPORT_SCHEMA) == []


def test_undocumented_field_detector_catches_a_new_field():
    data = _rich_report().to_dict()
    data["artifacts"][0]["brand_new_field"] = 1
    assert _undocumented(data, REPORT_SCHEMA, REPORT_SCHEMA) == ["$.artifacts[0].brand_new_field"]


# --- compatibility with the frozen 1.0 baseline ----------------------------------------------

def _types(schema: dict, root: dict) -> set[str]:
    schema = _resolve(schema, root)
    if "oneOf" in schema:
        found: set[str] = set()
        for option in schema["oneOf"]:
            found |= _types(option, root)
        return found
    kind = schema.get("type", [])
    return {kind} if isinstance(kind, str) else set(kind)


def _flatten(schema: dict, root: dict, path: str = "$") -> dict:
    node = _object_schema(schema, root)
    flat = {path: (frozenset(_types(schema, root)), frozenset(node.get("required", [])))}
    for name, sub in node.get("properties", {}).items():
        flat.update(_flatten(sub, root, f"{path}.{name}"))
    if "items" in node:
        flat.update(_flatten(node["items"], root, f"{path}[]"))
    return flat


def breaking_changes(old: dict, new: dict) -> list[str]:
    """Differences that would break a consumer written against *old*."""
    before, after = _flatten(old, old), _flatten(new, new)
    problems = []
    for path, (types, required) in before.items():
        if path not in after:
            problems.append(f"removed: {path}")
            continue
        new_types, new_required = after[path]
        if types != new_types:
            problems.append(f"type changed at {path}: {sorted(types)} -> {sorted(new_types)}")
        if required - new_required:
            problems.append(f"no longer required at {path}: {sorted(required - new_required)}")
    return problems


def test_breaking_change_detector():
    old = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}
    assert breaking_changes(old, old) == []
    added = {**old, "properties": {**old["properties"], "c": {"type": "string"}}}
    assert breaking_changes(old, added) == []
    removed = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}
    assert breaking_changes(old, removed) == ["removed: $.b"]
    retyped = {**old, "properties": {"a": {"type": ["string", "null"]}, "b": {"type": "integer"}}}
    assert breaking_changes(old, retyped) == ["type changed at $.a: ['string'] -> ['null', 'string']"]
    relaxed = {**old, "required": []}
    assert breaking_changes(old, relaxed) == ["no longer required at $: ['a']"]


def _localize(schema: dict, report: dict) -> dict:
    """Make a schema self-contained: copy report-1's $defs in and point cross-file refs at them."""
    text = json.dumps(schema).replace("report-1.json#/", "#/")
    local = json.loads(text)
    local["$defs"] = {**report["$defs"], **local.get("$defs", {})}
    return local


@pytest.mark.parametrize("name", ["report-1", "skills-scan-1"])
def test_schemas_are_compatible_with_the_frozen_1_0_baseline(name):
    current = _load(SCHEMA_DIR / f"{name}.json")
    baseline = _load(BASELINE_DIR / {"report-1": "report-1.0.json", "skills-scan-1": "skills-scan-1.0.json"}[name])
    if name == "skills-scan-1":
        current = _localize(current, REPORT_SCHEMA)
        baseline = _localize(baseline, _load(BASELINE_DIR / "report-1.0.json"))
    assert breaking_changes(baseline, current) == []


def test_schema_ids_name_the_major_version():
    assert REPORT_SCHEMA["$id"].endswith("/report-1.json")
    assert ENVELOPE_SCHEMA["$id"].endswith("/skills-scan-1.json")
    assert REPORT_SCHEMA["properties"]["schema_version"]["pattern"] == r"^1\.[0-9]+$"
