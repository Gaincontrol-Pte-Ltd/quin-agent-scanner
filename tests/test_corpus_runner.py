"""The corpus runner: summaries, diffs, manifest validation, and the in-repo (offline) entries."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_corpus", ROOT / "scripts" / "run_corpus.py")
run_corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_corpus)  # type: ignore[union-attr]


def _skills_report(*skills):
    return {"skills": [
        {"record": {"root_path": path, "name": name, "ecosystem": "claude"}, "verdict": verdict,
         "risk_score": score, "finding_counts": counts,
         "findings": [{"rule_id": rule} for rule in rules]}
        for path, name, verdict, score, counts, rules in skills
    ]}


def test_skills_summary_is_sorted_and_counts_rules():
    data = _skills_report(
        ("skills/b", "b", "SAFE", 0, {}, []),
        ("skills/a", "a", "CAUTION", 36, {"critical": 1}, ["SK-EXEC-001", "SK-PI-001", "SK-PI-001"]),
    )
    summary = run_corpus.summarize("skills", data)
    assert [s["path"] for s in summary["skills"]] == ["skills/a", "skills/b"]
    assert summary["skills"][0]["rules"] == {"SK-EXEC-001": 1, "SK-PI-001": 2}
    assert summary["skills"][0]["verdict"] == "CAUTION" and summary["skills"][0]["score"] == 36


def test_agents_summary_picks_stable_fields():
    data = {
        "framework": "CrewAI 0.80.0", "is_ai_application": True, "confidence": 0.9512,
        "capability_tags": ["rag", "llm-api"], "agents": [{"name": "b"}, {"name": "a"}],
        "model_usages": [{"provider": "openai", "model_name": "gpt-4o"}, {"provider": "openai", "model_name": "gpt-4o"}],
        "mcp_servers": [{"name": "fs"}], "tool_usages": [{}, {}],
        "risk_signals": [{"threat_id": "T001"}, {"threat_id": "T001"}, {"threat_id": None}],
        "artifacts": [{}, {}, {}],
    }
    summary = run_corpus.summarize("agents", data)
    assert summary == {
        "framework": "CrewAI 0.80.0", "is_ai_application": True, "confidence": 0.95,
        "capability_tags": ["llm-api", "rag"], "agents": ["a", "b"], "models": ["openai:gpt-4o"],
        "mcp_servers": ["fs"], "tools": 2, "risk_signals": {"T001": 2, "none": 1}, "artifacts": 3,
    }


def test_identical_summaries_have_no_diff():
    summary = run_corpus.summarize("skills", _skills_report(("s/a", "a", "SAFE", 0, {}, [])))
    assert run_corpus.diff("skills", summary, summary) == []


def test_skills_diff_reports_verdict_score_rule_and_membership_changes():
    old = run_corpus.summarize("skills", _skills_report(
        ("s/a", "a", "SAFE", 2, {"low": 1}, ["SK-SC-001"]),
        ("s/gone", "gone", "SAFE", 0, {}, []),
    ))
    new = run_corpus.summarize("skills", _skills_report(
        ("s/a", "a", "CAUTION", 36, {"critical": 1, "low": 1}, ["SK-SC-001", "SK-EXEC-001"]),
        ("s/new", "new", "SAFE", 0, {}, []),
    ))
    lines = run_corpus.diff("skills", old, new)
    text = "\n".join(lines)
    assert "s/a: verdict SAFE -> CAUTION" in text
    assert "s/a: score 2 -> 36" in text
    assert "s/a: rule SK-EXEC-001 0 -> 1" in text
    assert "removed skill s/gone" in text
    assert "new skill s/new" in text


def test_agents_diff_names_the_changed_fields():
    old = {"framework": "unknown", "is_ai_application": False, "tools": 1}
    new = {"framework": "CrewAI 0.80.0", "is_ai_application": True, "tools": 1}
    lines = run_corpus.diff("agents", old, new)
    assert "framework: 'unknown' -> 'CrewAI 0.80.0'" in lines
    assert "is_ai_application: False -> True" in lines
    assert not any("tools" in line for line in lines)


def test_manifest_validation(tmp_path):
    def write(text):
        path = tmp_path / "manifest.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    ok = write("entries:\n  - name: a\n    kind: skills\n    source: {path: tests/fixtures/skills_repo}\n")
    assert run_corpus.load_manifest(ok)[0]["name"] == "a"
    with pytest.raises(run_corpus.CorpusError, match="duplicate"):
        run_corpus.load_manifest(write("entries:\n  - {name: a, kind: skills, source: {path: x}}\n  - {name: a, kind: skills, source: {path: y}}\n"))
    with pytest.raises(run_corpus.CorpusError, match="kind"):
        run_corpus.load_manifest(write("entries:\n  - {name: a, kind: other, source: {path: x}}\n"))
    with pytest.raises(run_corpus.CorpusError, match="source"):
        run_corpus.load_manifest(write("entries:\n  - {name: a, kind: skills, source: {repo: https://github.com/o/r}}\n"))


def test_every_network_entry_is_pinned_to_a_full_commit_sha():
    for entry in run_corpus.load_manifest():
        source = entry["source"]
        if "repo" in source:
            assert len(source["commit"]) == 40 and set(source["commit"]) <= set("0123456789abcdef"), entry["name"]


def test_every_entry_has_an_expected_snapshot():
    for entry in run_corpus.load_manifest():
        assert (run_corpus.EXPECTED / f"{entry['name']}.json").is_file(), entry["name"]


def test_the_in_repo_entries_match_their_snapshots():
    # No network: runs on every OS in the normal suite, so a rule change that moves a fixture verdict fails here.
    assert run_corpus.main(["--check", "--local-only"]) == 0


def test_update_is_idempotent_for_the_in_repo_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(run_corpus, "EXPECTED", tmp_path)
    assert run_corpus.main(["--update", "--local-only"]) == 0
    first = {p.name: p.read_text(encoding="utf-8") for p in tmp_path.glob("*.json")}
    assert first, "no snapshots were written"
    assert run_corpus.main(["--update", "--local-only"]) == 0
    assert {p.name: p.read_text(encoding="utf-8") for p in tmp_path.glob("*.json")} == first
    assert run_corpus.main(["--check", "--local-only"]) == 0
    assert all(json.loads(text) for text in first.values())


def test_skills_diff_reports_severity_changes_even_when_rule_counts_are_equal():
    # A rule whose severity was changed (same findings, different weight) must be visible in the diff.
    old = run_corpus.summarize("skills", _skills_report(("s/a", "a", "CAUTION", 36, {"critical": 1}, ["SK-EXEC-001"])))
    new = run_corpus.summarize("skills", _skills_report(("s/a", "a", "SAFE", 4, {"low": 1}, ["SK-EXEC-001"])))
    text = "\n".join(run_corpus.diff("skills", old, new))
    assert "s/a: severity critical 1 -> 0" in text
    assert "s/a: severity low 0 -> 1" in text
    assert "s/a: verdict CAUTION -> SAFE" in text
