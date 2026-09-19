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


class TestFlagsRecordedInReport:
    def _run(self, tmp_path, *extra, fmt="json"):
        import json

        from click.testing import CliRunner

        from quin_scanner.cli import cli
        (tmp_path / "repo").mkdir()
        (tmp_path / "repo" / "a.py").write_text("import openai\n")
        out = tmp_path / f"out.{fmt}"
        res = CliRunner().invoke(cli, ["scan", str(tmp_path / "repo"), "-o", fmt, "-f", str(out), *extra])
        assert res.exit_code == 0, res.output
        return json.loads(out.read_text()) if fmt == "json" else out.read_text()

    def test_flags_listed(self, tmp_path):
        r = self._run(tmp_path, "--no-llm", "--no-vuln-check", "--detect-aegis", "--min-confidence", "0.5")
        assert r["metadata"]["scan_options"]["flags"] == [
            "--no-llm", "--no-vuln-check", "--detect-aegis", "--min-confidence 0.5",
        ]

    def test_defaults_are_empty_list(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VULN_SEARCH_PROVIDER", raising=False)
        r = self._run(tmp_path, "--no-llm", "--no-vuln-check")
        assert r["metadata"]["scan_options"]["flags"] == ["--no-llm", "--no-vuln-check"]

    def test_secrets_never_listed(self, tmp_path):
        r = self._run(tmp_path, "--no-llm", "--no-vuln-check", "--llm-api-key", "sk-SECRET",
                      "--github-token", "ghp_SECRET", "--openai-compatible-url", "http://u:pw@host/v1")
        blob = str(r["metadata"]["scan_options"])
        assert "SECRET" not in blob and "pw" not in blob and "host" not in blob
        assert "--openai-compatible-url" in r["metadata"]["scan_options"]["flags"]

    def test_config_file_shows_basename_only(self, tmp_path):
        cfg = tmp_path / "secret-dir" / "my-config.yaml"
        cfg.parent.mkdir()
        cfg.write_text("llm:\n  provider: openai\ngovernance:\n  detect_aegis: true\n")
        r = self._run(tmp_path, "--no-llm", "--no-vuln-check", "-c", str(cfg))
        flags = r["metadata"]["scan_options"]["flags"]
        assert "--config my-config.yaml" in flags and "--detect-aegis" in flags
        assert "secret-dir" not in str(flags)

    def test_html_shows_scan_options_strip(self, tmp_path):
        html = self._run(tmp_path, "--no-llm", "--no-vuln-check", fmt="html")
        assert 'id="scan-options"' in html and '"scan_options"' in html and "--no-llm" in html
