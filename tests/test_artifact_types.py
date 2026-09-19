"""Tests for the display-only standardised artifact types used by the HTML report."""
from __future__ import annotations

import json

import pytest

from quin_scanner.artifact_types import artifact_type, type_order
from quin_scanner.models import ScanReport
from quin_scanner.report import ReportGenerator


@pytest.mark.parametrize(
    "category,tag,text,expected",
    [
        ("code_pattern", "llm-api", "from langchain_openai import ChatOpenAI", "LLM API"),
        ("code_pattern", "llm-api", "from langchain_core.messages import HumanMessage", "LLM API"),
        ("code_pattern", "llm-api", "from langchain_core.tools import BaseTool", "Tool"),
        ("code_pattern", "llm-api", "from langchain.agents import AgentExecutor", "Agent framework"),
        ("code_pattern", "llm-api", "from langchain import hub", "Agent framework"),
        ("code_pattern", "llm-api", "from langchain.prompts import PromptTemplate", "Prompt template"),
        ("code_pattern", "llm-api", "from langchain.vectorstores import FAISS", "RAG & embeddings"),
        ("dependency", "llm-api", "langchain>=0.2.16", "Agent framework"),
        ("dependency", "llm-api", "langchain-core>=0.2.38", "Agent framework"),
        ("dependency", "llm-api", "langchain-openai>=0.1.24", "LLM API"),
        ("dependency", "llm-api", "openai>=1.12.0", "LLM API"),
        ("code_pattern", "prompt-templates", "PromptTemplate(", "Prompt template"),
        ("prompt", "prompt-templates", "You are an expert", "Prompt template"),
        ("dependency", "multi-agent", "crewai>=0.80", "Agent framework"),
        ("code_pattern", "tool-use", "@tool", "Tool"),
        ("agent_instance", "multi-agent", "Agent(", "Agent"),
        ("dockerfile", "llm-api", "FROM python", "Infra & config"),
        ("governance", "aegis-governed:import", "from aegis_core import x", "Aegis governance"),
        ("code_pattern", "something-new", "x", "Other"),
    ],
)
def test_artifact_type(category, tag, text, expected):
    assert artifact_type(category, tag, text) == expected


def test_every_type_is_in_display_order():
    order = set(type_order())
    for t in ("LLM API", "Agent framework", "Prompt template", "Tool", "Aegis governance"):
        assert t in order


def test_html_annotates_but_json_is_unchanged():
    from quin_scanner.models import ScanFinding
    f = ScanFinding("CodePatternScanner", "code_pattern", "a.py", 1,
                    "from langchain_core.tools import BaseTool", "llm-api", 0.9)
    report = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True,
                        confidence=0.9, artifacts=[f])
    assert "artifact_type" not in json.loads(ReportGenerator.to_json(report))["artifacts"][0]
    html = ReportGenerator.to_html(report)
    assert '"artifact_type": "Tool"' in html
