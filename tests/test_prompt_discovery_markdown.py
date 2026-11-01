"""Markdown is a prompt when it states a role or task, not when documentation happens to say "you are a" (UAT finding U8)."""
from __future__ import annotations

import pytest

from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.prompt_discovery import PromptDiscoveryScanner


def _prompts(tmp_path, text: str, name: str = "notes.md") -> list[str]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return [f.file_path for f in PromptDiscoveryScanner().scan(accessor, index) if f.category == "prompt"]


@pytest.mark.parametrize(
    "text",
    [
        "# Active Help\n\nActive Help is a framework provided by Cobra. If you are a program author you can add hints.\n",
        "# Guide\n\nWhen you are an admin of the cluster, you may need to act as the operator for a while.\n",
        "# FAQ\n\nQ: Why? A: Because you are a user and your task is to read this.\n",
        "Some text, then as an AI skeptic I disagree.\n",
    ],
)
def test_documentation_that_mentions_the_phrases_in_passing_is_not_a_prompt(tmp_path, text):
    assert _prompts(tmp_path, text) == []


@pytest.mark.parametrize(
    "text",
    [
        "You are a helpful research assistant. Answer concisely.\n",
        "# Reviewer\n\nYou are an expert code reviewer.\nYour task is to find bugs.\n",
        "> You are a travel agent.\n",
        "- Act as a senior engineer.\n",
        "# Planner\n\n## System Prompt\n\nPlan the work.\n",
        "## Instructions\n\nFollow the steps.\n",
        "Intro line.\n\n   Your role is to triage incoming issues.\n",
    ],
)
def test_markdown_that_states_a_role_or_task_is_still_a_prompt(tmp_path, text):
    assert _prompts(tmp_path, text) == ["notes.md"]
