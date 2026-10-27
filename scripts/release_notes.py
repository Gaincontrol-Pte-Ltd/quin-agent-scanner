#!/usr/bin/env python3
"""Print one version's section of CHANGELOG.md, for use as GitHub Release notes.

  python3 scripts/release_notes.py v1.0.0 [--changelog CHANGELOG.md]

Exit codes: 0 notes printed, 1 the version has no (or an empty) section.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]", re.MULTILINE)
# Keep a Changelog ends the file with `---` and `[1.0.0]: https://...` link references.
_TRAILER = re.compile(r"\n---\s*\n+(?:\[[^\]]+\]:.*\n?)+\s*\Z|\n(?:\[[^\]]+\]:.*\n?)+\s*\Z")


class ReleaseNotesError(Exception):
    pass


def extract(text: str, version: str) -> str:
    version = version.removeprefix("v")
    headings = list(_HEADING.finditer(text))
    for i, heading in enumerate(headings):
        if heading.group("version") != version:
            continue
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        body = text[heading.end():end]
        body = body.split("\n", 1)[1] if "\n" in body else ""
        body = _TRAILER.sub("", body.rstrip() + "\n").strip()
        body = re.sub(r"\n---\s*$", "", body).strip()
        if not body:
            raise ReleaseNotesError(f"CHANGELOG section for {version} is empty")
        return body
    raise ReleaseNotesError(f"CHANGELOG has no section for {version}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version")
    parser.add_argument("--changelog", type=Path, default=ROOT / "CHANGELOG.md")
    args = parser.parse_args(argv)
    try:
        print(extract(args.changelog.read_text(encoding="utf-8"), args.version))
    except ReleaseNotesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
