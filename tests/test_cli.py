"""Tests for CLI output-format wiring."""
from __future__ import annotations

from quin_scanner.cli import _OUTPUT_CHOICES, _output_filename


class TestOutputChoices:
    def test_sarif_is_a_valid_output_choice(self):
        assert "sarif" in _OUTPUT_CHOICES.choices


class TestOutputFilename:
    def test_sarif_extension(self):
        assert _output_filename("owner/repo", "sarif") == _output_filename("owner/repo", "sarif")
        name = _output_filename("owner/repo", "sarif")
        assert name.startswith("repo_")
        assert name.endswith(".sarif")
