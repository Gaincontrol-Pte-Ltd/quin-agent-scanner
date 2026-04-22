#!/usr/bin/env python3
"""Generate docs/risk-framework.md from src/quin_scanner/rules/risk_taxonomy.yaml.

Usage:
    python scripts/generate_risk_framework_docs.py           # write file
    python scripts/generate_risk_framework_docs.py --check   # drift gate

--check exits non-zero if the on-disk Markdown does not match what would be
generated from the current YAML. CI should run this on every PR.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the in-repo package importable without installing.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jinja2 import Environment, FileSystemLoader, StrictUndefined  # noqa: E402

from quin_scanner.risk_taxonomy import load_taxonomy  # noqa: E402

TEMPLATE_DIR = REPO_ROOT / "scripts" / "templates"
TEMPLATE_NAME = "risk-framework.md.j2"
OUTPUT = REPO_ROOT / "docs" / "risk-framework.md"


def render() -> str:
    tax = load_taxonomy()

    by_control_id = {c.id: c for c in tax.controls}
    by_threat_id = {t.id: t for t in tax.threats}

    def control_name(cid: str) -> str:
        c = by_control_id.get(cid)
        return c.name if c else cid

    def threat_name(tid: str) -> str:
        t = by_threat_id.get(tid)
        return t.name if t else tid

    def threats_for_control(cid: str) -> list[str]:
        return [t.id for t in tax.threats if cid in t.recommended_controls]

    def _rel(local: str) -> str:
        # Make docs/X.md relative to docs/risk-framework.md
        if local.startswith("docs/"):
            return local[len("docs/"):]
        return local

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    template = env.get_template(TEMPLATE_NAME)
    rendered = template.render(
        threats=tax.threats,
        controls=tax.controls,
        control_name=control_name,
        threat_name=threat_name,
        threats_for_control=threats_for_control,
        _rel=_rel,
    )
    # Normalize to a single trailing newline for stable output.
    return rendered.rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the on-disk file differs from the generated output.",
    )
    args = ap.parse_args()

    generated = render()

    if args.check:
        if not OUTPUT.exists():
            print(f"[drift] {OUTPUT} does not exist. Run this script without --check.", file=sys.stderr)
            return 1
        current = OUTPUT.read_text(encoding="utf-8")
        if current != generated:
            print(
                f"[drift] {OUTPUT} is out of sync with the taxonomy YAML.\n"
                f"        Run: python scripts/generate_risk_framework_docs.py",
                file=sys.stderr,
            )
            return 1
        print(f"[ok] {OUTPUT} is in sync with the taxonomy YAML.")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"[ok] wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
