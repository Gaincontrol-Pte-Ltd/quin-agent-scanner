#!/usr/bin/env python3
"""Run the quality corpus: pinned public repositories plus in-repo fixtures vs. expected snapshots.

  python3 scripts/run_corpus.py --check                 # every entry; exit 1 if any result differs
  python3 scripts/run_corpus.py --check --local-only    # in-repo fixtures only (no network)
  python3 scripts/run_corpus.py --update [--only NAME]  # rewrite snapshots after a deliberate change
  python3 scripts/run_corpus.py --check --latest        # upstream HEAD instead of the pinned commit (drift)

Exit codes: 0 all match, 1 something differs, 2 infrastructure error (fetch or scan failed).
The scan uses the public CLI (no LLM, no vulnerability lookup), so the corpus also exercises the CLI contract.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "corpus"
MANIFEST = CORPUS / "manifest.yaml"
EXPECTED = CORPUS / "expected"
DEFAULT_CACHE = ROOT / ".corpus-cache"
CLI = [sys.executable, "-c", "from quin_scanner.cli import cli; cli()"]
_FETCH_ATTEMPTS = 3


class CorpusError(RuntimeError):
    """The corpus itself could not be run (bad manifest, fetch failure, scan failure)."""


def load_manifest(path: Path = MANIFEST) -> list[dict]:
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))["entries"]
    names = [entry["name"] for entry in entries]
    if len(set(names)) != len(names):
        raise CorpusError("duplicate entry names in the manifest")
    for entry in entries:
        if entry.get("kind") not in ("skills", "agents"):
            raise CorpusError(f"{entry.get('name')}: kind must be 'skills' or 'agents'")
        source = entry.get("source") or {}
        if "path" not in source and not ("repo" in source and "commit" in source):
            raise CorpusError(f"{entry['name']}: source needs 'path', or 'repo' and 'commit'")
    return entries


def _git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise CorpusError(f"git {' '.join(args)} failed: {result.stderr.strip()[:300]}")
    return result.stdout.strip()


def fetch(entry: dict, cache: Path, latest: bool) -> tuple[Path, str]:
    """Return (directory to scan, commit label). In-repo entries need no fetch."""
    source = entry["source"]
    if "path" in source:
        return ROOT / source["path"], "in-repo"
    subpaths = source.get("paths") or ([source["subpath"]] if source.get("subpath") else [])
    ref = "HEAD" if latest else source["commit"]
    dest = cache / f"{entry['name']}-{'latest' if latest else ref[:12]}"
    marker = dest / ".corpus-commit"
    if not latest and marker.exists():
        return _scan_root(dest, source), marker.read_text(encoding="utf-8").strip()
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    last: Exception | None = None
    for attempt in range(_FETCH_ATTEMPTS):
        try:
            _git(["init", "-q"], dest)
            _git(["remote", "add", "origin", source["repo"]], dest)
            if subpaths:
                _git(["sparse-checkout", "set", "--cone", *subpaths], dest)
            _git(["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", ref], dest)
            _git(["checkout", "-q", "FETCH_HEAD"], dest)
            commit = _git(["rev-parse", "HEAD"], dest)
            marker.write_text(commit + "\n", encoding="utf-8")
            return _scan_root(dest, source), commit
        except (CorpusError, subprocess.TimeoutExpired) as exc:
            last = exc
            shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir(parents=True)
            time.sleep(2 * (attempt + 1))
    raise CorpusError(f"{entry['name']}: could not fetch {source['repo']}@{ref}: {last}")


def _scan_root(dest: Path, source: dict) -> Path:
    if source.get("subpath") and not source.get("paths"):
        return dest / source["subpath"]
    return dest


def scan(entry: dict, target: Path) -> dict:
    """Run the public CLI and return the parsed JSON report."""
    with tempfile.TemporaryDirectory(prefix="quin-corpus-") as work:
        out = Path(work) / "out.json"
        if entry["kind"] == "skills":
            args, ok = ["skills", "scan", str(target), "-o", "json", "-f", str(out), "--no-vuln-check"], {0, 1}
        else:
            args, ok = ["scan", str(target), "-o", "json", "-f", str(out), "--no-llm", "--no-vuln-check"], {0}
        env = {**os.environ, "PYTHONUTF8": "1", "NO_COLOR": "1"}
        result = subprocess.run([*CLI, *args], capture_output=True, text=True, env=env, timeout=1800)
        if result.returncode not in ok or not out.is_file():
            raise CorpusError(f"{entry['name']}: scan failed (exit {result.returncode}): {result.stderr.strip()[-400:]}")
        return json.loads(out.read_text(encoding="utf-8"))


def summarize(kind: str, data: dict) -> dict:
    """The deterministic part of a result that the corpus pins."""
    if kind == "skills":
        skills = []
        for assessment in data["skills"]:
            record = assessment["record"]
            rules = Counter(finding["rule_id"] for finding in assessment["findings"])
            skills.append({
                "path": record["root_path"] or ".",
                "name": record["name"],
                "ecosystem": record["ecosystem"],
                "verdict": assessment["verdict"],
                "score": assessment["risk_score"],
                "severity": dict(sorted(assessment["finding_counts"].items())),
                "rules": dict(sorted(rules.items())),
            })
        skills.sort(key=lambda item: (item["path"], item["name"]))
        return {"skills": skills}
    return {
        "framework": data["framework"],
        "is_ai_application": data["is_ai_application"],
        "confidence": round(data["confidence"], 2),
        "capability_tags": sorted(data["capability_tags"]),
        "agents": sorted(agent["name"] for agent in data["agents"]),
        "models": sorted({f"{m['provider']}:{m['model_name']}" for m in data["model_usages"]}),
        "mcp_servers": sorted(server["name"] for server in data["mcp_servers"]),
        "tools": len(data["tool_usages"]),
        "risk_signals": dict(sorted(Counter(signal["threat_id"] or "none" for signal in data["risk_signals"]).items())),
        "artifacts": len(data["artifacts"]),
    }


def diff(kind: str, old: dict, new: dict) -> list[str]:
    """Human-readable differences between two summaries (empty when identical)."""
    lines: list[str] = []
    if kind == "skills":
        before = {s["path"]: s for s in old.get("skills", [])}
        after = {s["path"]: s for s in new.get("skills", [])}
        lines += [f"removed skill {path}" for path in sorted(before.keys() - after.keys())]
        lines += [f"new skill {path} ({after[path]['verdict']} {after[path]['score']})" for path in sorted(after.keys() - before.keys())]
        for path in sorted(before.keys() & after.keys()):
            a, b = before[path], after[path]
            for field in ("ecosystem", "verdict", "score", "name"):
                if a[field] != b[field]:
                    lines.append(f"{path}: {field} {a[field]} -> {b[field]}")
            for rule in sorted(a["rules"].keys() | b["rules"].keys()):
                if a["rules"].get(rule, 0) != b["rules"].get(rule, 0):
                    lines.append(f"{path}: rule {rule} {a['rules'].get(rule, 0)} -> {b['rules'].get(rule, 0)}")
        return lines
    for key in sorted(old.keys() | new.keys()):
        if old.get(key) != new.get(key):
            lines.append(f"{key}: {old.get(key)!r} -> {new.get(key)!r}")
    return lines


def _dump(summary: dict) -> str:
    return json.dumps(summary, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="compare with the committed snapshots")
    mode.add_argument("--update", action="store_true", help="rewrite the snapshots")
    parser.add_argument("--only", action="append", default=[], help="run only this entry (repeatable)")
    parser.add_argument("--local-only", action="store_true", help="in-repo entries only (no network)")
    parser.add_argument("--latest", action="store_true", help="fetch upstream HEAD instead of the pinned commit")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="where fetched repositories are kept")
    args = parser.parse_args(argv)

    entries = load_manifest()
    if args.only:
        unknown = set(args.only) - {e["name"] for e in entries}
        if unknown:
            print(f"unknown entries: {sorted(unknown)}", file=sys.stderr)
            return 2
        entries = [e for e in entries if e["name"] in args.only]
    if args.local_only:
        entries = [e for e in entries if "path" in e["source"]]

    EXPECTED.mkdir(parents=True, exist_ok=True)
    changed = 0
    for entry in entries:
        name = entry["name"]
        try:
            target, commit = fetch(entry, args.cache, args.latest)
            summary = summarize(entry["kind"], scan(entry, target))
        except (CorpusError, subprocess.TimeoutExpired) as exc:
            print(f"ERROR {name}: {exc}", file=sys.stderr)
            return 2
        path = EXPECTED / f"{name}.json"
        if args.update:
            path.write_text(_dump(summary), encoding="utf-8")
            print(f"updated {name} ({commit[:12]})")
            continue
        if not path.is_file():
            print(f"CHANGED {name}: no snapshot (run --update)")
            changed += 1
            continue
        lines = diff(entry["kind"], json.loads(path.read_text(encoding="utf-8")), summary)
        if lines:
            changed += 1
            print(f"CHANGED {name} ({commit[:12]}):")
            for line in lines:
                print(f"  {line}")
        else:
            print(f"ok      {name} ({commit[:12]})")
    if changed:
        print(
            f"\n{changed} corpus entr{'y' if changed == 1 else 'ies'} changed. If this is the intended effect of your change, "
            "run `python3 scripts/run_corpus.py --update`, commit the snapshots, and describe the change under "
            "'Detection changes' in CHANGELOG.md.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
