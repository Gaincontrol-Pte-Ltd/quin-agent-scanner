#!/usr/bin/env python3
"""Check that a release tag matches the code it would publish. PyPI versions cannot be re-published.

  python3 scripts/check_release_version.py v1.0.0 [--root .]

Checks: the tag is a release tag; pyproject.toml and quin_scanner.__version__ both equal it; CHANGELOG.md has a
section for it; a stable 1.x release carries the Production/Stable classifier.
Exit codes: 0 consistent, 1 a mismatch (every problem is listed).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_TAG = re.compile(r"^v(?P<version>(?P<major>\d+)\.\d+\.\d+(?P<pre>(?:a|b|rc)\d+)?)$")
_PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
_MODULE_VERSION = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)
_STABLE_CLASSIFIER = "Development Status :: 5 - Production/Stable"


def problems(tag: str, root: Path) -> list[str]:
    match = _TAG.match(tag)
    if not match:
        return [f"{tag!r} is not a release tag (expected vX.Y.Z or vX.Y.ZrcN)"]
    version = match.group("version")
    found: list[str] = []

    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    declared = _PYPROJECT_VERSION.search(pyproject)
    if not declared or declared.group(1) != version:
        found.append(f"pyproject.toml version is {declared.group(1) if declared else 'missing'}, the tag says {version}")

    module = (root / "src" / "quin_scanner" / "__init__.py").read_text(encoding="utf-8")
    reported = _MODULE_VERSION.search(module)
    if not reported or reported.group(1) != version:
        found.append(
            f"quin_scanner.__version__ is {reported.group(1) if reported else 'missing'}, the tag says {version}"
        )

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\]", changelog, re.MULTILINE):
        found.append(f"CHANGELOG.md has no '## [{version}]' section")

    if int(match.group("major")) >= 1 and not match.group("pre") and _STABLE_CLASSIFIER not in pyproject:
        found.append(f"a stable release needs the classifier '{_STABLE_CLASSIFIER}' in pyproject.toml")

    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("tag")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    found = problems(args.tag, args.root)
    for line in found:
        print(f"error: {line}", file=sys.stderr)
    if not found:
        print(f"{args.tag}: pyproject.toml, __version__ and CHANGELOG.md agree")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
