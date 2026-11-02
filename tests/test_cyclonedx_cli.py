"""`-o cyclonedx` through the public CLI."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from quin_scanner.cli import _output_filename, cli
from quin_scanner.models import ScanReport, Vulnerability
from quin_scanner.report import ReportGenerator
from tests.cyclonedx_support import bom_errors


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "demo"
    (root / "agents").mkdir(parents=True)
    (root / "agents" / "crew.py").write_text(
        "from framework import Agent, tool\n@tool\ndef search():\n    return 1\n"
        "researcher = Agent(name='researcher', instructions='Find.', tools=[search], model='gpt-4o')\n",
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text('{"mcpServers": {"fs": {"command": "npx", "args": ["srv"]}}}', encoding="utf-8")
    return root


@pytest.fixture
def rich_repo(tmp_path):
    root = tmp_path / "rich"
    (root / "agents").mkdir(parents=True)
    (root / "agents" / "crew.py").write_text(
        "from framework import Agent, tool\n"
        "@tool\ndef search():\n    return 1\n"
        "@tool\ndef fetch():\n    return 2\n"
        "researcher = Agent(name='researcher', instructions='Find.', tools=[search, fetch], model='gpt-4o')\n"
        "writer = Agent(name='writer', instructions='Write.', tools=[fetch], model='gpt-4o-mini')\n"
        "from openai import OpenAI\n"
        "a = OpenAI(base_url=\"http://10.0.0.5:8000/v1\")\n"
        "b = OpenAI(base_url=\"https://llm.example.com/v1\")\n",
        encoding="utf-8",
    )
    (root / "agents" / "more.py").write_text(
        "from framework import Agent\n"
        "researcher = Agent(name='researcher', instructions='Find again.', model='gpt-4o')\n",
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text(
        '{"mcpServers": {"fs": {"command": "npx", "args": ["srv"]}, "git": {"command": "uvx", "args": ["git"]}}}',
        encoding="utf-8",
    )
    return root


def _run(*args):
    return CliRunner().invoke(cli, list(args))


def test_scan_writes_a_valid_bom_file(tmp_path, repo):
    out = tmp_path / "bom.cdx.json"
    result = _run("scan", str(repo), "-o", "cyclonedx", "-f", str(out), "--no-llm", "--no-vuln-check")
    assert result.exit_code == 0, result.output
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom_errors(bom) == []
    refs = {c["bom-ref"] for c in bom.get("components", [])}
    assert "agent:researcher" in refs


def test_scan_to_stdout(repo):
    result = _run("scan", str(repo), "-o", "cyclonedx", "--no-llm", "--no-vuln-check", "-d", "")
    assert result.exit_code == 0, result.output
    assert '"bomFormat": "CycloneDX"' in result.stdout


def test_auto_named_files_use_cdx_json():
    assert _output_filename("/x/demo", "cyclonedx").endswith(".cdx.json")
    assert _output_filename("/x/demo", "sarif").endswith(".sarif")


def test_scan_batch_auto_names(tmp_path, repo):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{repo}\n", encoding="utf-8")
    outdir = tmp_path / "out"
    result = _run("scan-batch", str(targets), "-o", "cyclonedx", "-d", str(outdir), "--no-llm", "--no-vuln-check")
    assert result.exit_code == 0, result.output
    files = list(outdir.glob("demo_*.cdx.json"))
    assert len(files) == 1
    assert bom_errors(json.loads(files[0].read_text(encoding="utf-8"))) == []


def test_omitted_web_vulnerabilities_note(tmp_path, repo, monkeypatch):
    from quin_scanner import orchestrator

    real_run = orchestrator.ScanOrchestrator.run

    def run_with_vulns(self, accessor, cfg, verbose=False):
        report = real_run(self, accessor, cfg, verbose=verbose)
        report.vulnerabilities = [
            Vulnerability(cve_id="CVE-1", severity="high", cvss_score=None, published=None, summary="x",
                          source="web:gemini", source_url=None),
            Vulnerability(cve_id="CVE-2", severity="high", cvss_score=None, published=None, summary="y",
                          source="web:gemini", source_url=None),
        ]
        return report

    monkeypatch.setattr(orchestrator.ScanOrchestrator, "run", run_with_vulns)
    result = CliRunner().invoke(cli, ["scan", str(repo), "-o", "cyclonedx", "-f", str(tmp_path / "b.json"),
                                      "--no-llm", "--no-vuln-check"])
    assert result.exit_code == 0, result.output
    assert "2 web-search vulnerabilities omitted from the BOM (OSV only)" in result.stderr


def test_build_failure_is_reported(tmp_path, repo, monkeypatch):
    def boom(report):
        raise ValueError("bad inventory")

    monkeypatch.setattr("quin_scanner.cyclonedx.to_cyclonedx", boom)
    out = tmp_path / "b.json"
    result = _run("scan", str(repo), "-o", "cyclonedx", "-f", str(out), "--no-llm", "--no-vuln-check")
    assert result.exit_code == 1
    assert "could not build the CycloneDX BOM: bad inventory" in result.stderr
    assert not out.exists()


def test_to_string_dispatches_cyclonedx():
    report = ScanReport(repo_path="/x/demo", scan_timestamp="2026-11-02T00:00:00+00:00", is_ai_application=False, confidence=0.0)
    assert json.loads(ReportGenerator.to_string(report, "cyclonedx"))["specVersion"] == "1.6"


def _bom_without_volatile_fields(repo, out, seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "NO_COLOR": "1"}
    subprocess.run([sys.executable, "-c", "from quin_scanner.cli import cli; cli()", "scan", str(repo), "--no-llm",
                    "--no-vuln-check", "-o", "cyclonedx", "-f", str(out)], env=env, check=True, capture_output=True)
    bom = json.loads(out.read_text(encoding="utf-8"))
    bom.pop("serialNumber")
    bom["metadata"].pop("timestamp")
    return json.dumps(bom, indent=2)


def test_bom_does_not_depend_on_the_hash_seed(tmp_path, rich_repo):
    boms = {seed: _bom_without_volatile_fields(rich_repo, tmp_path / f"b{seed}.json", seed) for seed in ("1", "2", "3")}
    assert len(set(boms.values())) == 1
    bom = json.loads(boms["1"])
    components = bom["components"]
    assert sum(c["bom-ref"].startswith("agent:") for c in components) >= 2
    assert sum(c["bom-ref"].startswith("tool:") for c in components) >= 2
    refs = [s["bom-ref"] for s in bom["services"]]
    assert len(refs) >= 2 and any(r.startswith("service:endpoint:") for r in refs)


def test_scan_batch_one_bad_bom_does_not_stop_the_run(tmp_path, repo, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text("x = 1\n", encoding="utf-8")
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{repo}\n{other}\n", encoding="utf-8")
    real = __import__("quin_scanner.cyclonedx", fromlist=["to_cyclonedx"]).to_cyclonedx

    def flaky(report):
        if report.repo_path.endswith("other"):
            raise ValueError("bad inventory")
        return real(report)

    monkeypatch.setattr("quin_scanner.cyclonedx.to_cyclonedx", flaky)
    outdir = tmp_path / "out"
    result = _run("scan-batch", str(targets), "-o", "cyclonedx", "-d", str(outdir), "--no-llm", "--no-vuln-check")
    assert result.exit_code == 1
    assert "1 of 2 targets failed" in result.stderr
    assert len(list(outdir.glob("*.cdx.json"))) == 1
