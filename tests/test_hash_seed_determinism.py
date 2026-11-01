"""Reports must not depend on Python's per-process hash randomisation (found by the rc2 UAT: the CI scanner iterated a set)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest


def _scan(repo, out, seed: str) -> dict:
    env = {**os.environ, "PYTHONHASHSEED": seed, "NO_COLOR": "1"}
    code = "from quin_scanner.cli import cli; cli()"
    subprocess.run([sys.executable, "-c", code, "scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)],
                   env=env, check=True, capture_output=True)
    return json.loads(out.read_text(encoding="utf-8"))


def _artifact_order(report: dict) -> list:
    return [(a["scanner_name"], a["file_path"], a["line_number"], a["match_text"]) for a in report["artifacts"]]


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    for name in ("test", "claude", "release", "lint", "docs", "e2e", "nightly", "deploy", "codeql", "stale", "labeler", "triage"):
        (root / ".github" / "workflows" / f"{name}.yml").write_text(
            "env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n", encoding="utf-8")
    for sub in ("a", "b", "c", "d", "e", "f"):  # several .env files, MCP configs and Kubernetes manifests, so the order has room to vary
        (root / sub).mkdir()
        (root / sub / ".env").write_text("OPENAI_API_KEY=x\nANTHROPIC_API_KEY=y\n", encoding="utf-8")
        (root / sub / ".mcp.json").write_text('{"mcpServers": {"s%s": {"command": "npx", "args": ["srv"]}}}' % sub, encoding="utf-8")
        (root / sub / "deploy.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: llm\n        image: vllm/vllm-openai\n", encoding="utf-8")
    (root / "app.py").write_text("from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8")
    return root


def test_artifact_order_does_not_depend_on_the_hash_seed(tmp_path, repo):
    orders = {seed: _artifact_order(_scan(repo, tmp_path / f"r{seed}.json", seed)) for seed in ("1", "2", "3", "4", "5")}
    assert len({json.dumps(o) for o in orders.values()}) == 1, "the artifact order changes with PYTHONHASHSEED"
    assert len(orders["1"]) > 12  # the workflow files did produce artifacts
