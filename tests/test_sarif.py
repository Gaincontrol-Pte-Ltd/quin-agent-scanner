"""Tests for SARIF report generation."""
from __future__ import annotations

from quin_scanner.sarif import _severity_to_level, _slugify


class TestSeverityToLevel:
    def test_critical_maps_to_error(self):
        assert _severity_to_level("critical") == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_level("high") == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_level("medium") == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_level("low") == "note"

    def test_info_maps_to_note(self):
        assert _severity_to_level("info") == "note"


class TestSlugify:
    def test_slugifies_multiword_text(self):
        assert _slugify("Excessive Agent Permissions Detected Here Now") == "excessive-agent-permissions-detected-here-now"

    def test_truncates_to_six_words(self):
        assert _slugify("one two three four five six seven eight") == "one-two-three-four-five-six"

    def test_strips_punctuation(self):
        assert _slugify("Agent has, unrestricted (network) access!") == "agent-has-unrestricted-network-access"

    def test_empty_text_falls_back(self):
        assert _slugify("") == "risk-signal"

    def test_punctuation_only_falls_back(self):
        assert _slugify("!!!") == "risk-signal"
