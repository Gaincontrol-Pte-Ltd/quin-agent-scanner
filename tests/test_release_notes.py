"""scripts/release_notes.py: the GitHub Release body comes from the CHANGELOG."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)  # type: ignore[union-attr]

CHANGELOG = """# Changelog

---

## [Unreleased]

### Added

- Something pending.

## [1.0.0] — 2026-11-20

### Added

- The big one.

### Fixed

- A bug.

## [0.1.0b5] — 2026-10-26

- Older.

---

[Unreleased]: https://example.com/compare/v1.0.0...HEAD
[1.0.0]: https://example.com/releases/tag/v1.0.0
[0.1.0b5]: https://example.com/releases/tag/v0.1.0b5
"""


def test_returns_the_body_of_the_version_without_its_heading():
    body = release_notes.extract(CHANGELOG, "1.0.0")
    assert body.startswith("### Added")
    assert "The big one." in body and "A bug." in body
    assert "Older." not in body and "Something pending." not in body
    assert "## [1.0.0]" not in body


def test_accepts_a_leading_v():
    assert release_notes.extract(CHANGELOG, "v1.0.0") == release_notes.extract(CHANGELOG, "1.0.0")


def test_last_section_stops_before_the_link_references():
    body = release_notes.extract(CHANGELOG, "0.1.0b5")
    assert body == "- Older."


def test_missing_version_is_an_error():
    with pytest.raises(release_notes.ReleaseNotesError, match="2.0.0"):
        release_notes.extract(CHANGELOG, "2.0.0")


def test_empty_section_is_an_error():
    with pytest.raises(release_notes.ReleaseNotesError, match="empty"):
        release_notes.extract("## [1.0.0] — x\n\n## [0.9.0] — y\n\n- a\n", "1.0.0")


def test_the_real_changelog_has_notes_for_the_latest_release():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert release_notes.extract(text, "0.1.0b5")
