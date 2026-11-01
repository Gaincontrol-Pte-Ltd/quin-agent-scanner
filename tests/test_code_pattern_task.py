"""`Task(` is an orchestration signal for CrewAI-style code, not for any class whose name ends in Task (UAT, Flask's Celery example)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli


def _report(tmp_path, source: str) -> dict:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(source, encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "source",
    [
        "from celery import Task\n\nclass FlaskTask(Task):\n    def __call__(self, *args, **kwargs):\n        return self.run(*args, **kwargs)\n",
        "import asyncio\nt = asyncio.Task(coro)\n",
        "class BackgroundTask: pass\nx = BackgroundTask()\nsubtask = SubTask(1)\n",
    ],
)
def test_ordinary_task_classes_are_not_ai(tmp_path, source):
    report = _report(tmp_path, source)
    assert report["is_ai_application"] is False and report["artifacts"] == []


@pytest.mark.parametrize(
    "source",
    [
        'from crewai import Agent, Task\nt = Task(description="d", expected_output="e", agent=a)\n',
        "t = Task(\n    description='d',\n    agent=a,\n)\n",
    ],
)
def test_crewai_style_tasks_are_still_found(tmp_path, source):
    report = _report(tmp_path, source)
    assert any(a["capability_tag"] == "orchestration" for a in report["artifacts"])
