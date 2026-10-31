"""Config file contract: optional config_version (default 1), clear errors, warnings for unknown keys."""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.config import SUPPORTED_CONFIG_VERSION, ConfigError, ScannerConfig

ROOT = Path(__file__).resolve().parent.parent
FULL_CONFIG = """
config_version: 1
llm:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key_env: SOME_KEY_VAR
output:
  format: json
  max_repo_risk_signals: 5
vuln_check:
  enabled: false
  search_provider: none
  search_model: x
  osv_timeout_seconds: 5
  web_timeout_seconds: 5
  web_retries: 0
scanners:
  enabled: [dependency, skills]
governance:
  detect_zino: true
"""


def _config(tmp_path, text: str) -> str:
    path = tmp_path / "scanner-config.yaml"
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return str(path)


def test_supported_config_version_is_1():
    assert SUPPORTED_CONFIG_VERSION == 1


def test_a_config_without_a_version_is_version_1(tmp_path):
    cfg = ScannerConfig.load_from_file(_config(tmp_path, "llm:\n  provider: ollama\n"))
    assert cfg.llm_provider == "ollama"


def test_an_explicit_version_1_is_accepted(tmp_path):
    ScannerConfig.load_from_file(_config(tmp_path, "config_version: 1\n"))


@pytest.mark.parametrize("value", ["0", "-1", "'1'", "true", "1.5", "[1]"])
def test_a_malformed_config_version_is_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="config_version"):
        ScannerConfig.load_from_file(_config(tmp_path, f"config_version: {value}\n"))


def test_a_newer_config_version_says_to_upgrade(tmp_path):
    with pytest.raises(ConfigError, match="newer") as info:
        ScannerConfig.load_from_file(_config(tmp_path, "config_version: 2\n"))
    assert "Upgrade" in str(info.value)


def test_an_empty_file_is_an_empty_config(tmp_path):
    ScannerConfig.load_from_file(_config(tmp_path, ""))


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "llm: [1, 2]\n"])
def test_a_config_that_is_not_a_mapping_is_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        ScannerConfig.load_from_file(_config(tmp_path, text))


def test_a_missing_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        ScannerConfig.load_from_file(str(tmp_path / "nope.yaml"))


def test_invalid_yaml_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        ScannerConfig.load_from_file(_config(tmp_path, "llm: [unclosed\n"))


def test_unknown_keys_warn_on_stderr_and_are_ignored(tmp_path, capsys):
    cfg = ScannerConfig.load_from_file(_config(tmp_path, """
        llm:
          provider: ollama
          modle: typo
        vuln_chek:
          enabled: false
    """))
    err = capsys.readouterr().err
    assert "unknown key 'vuln_chek'" in err
    assert "unknown key 'llm.modle'" in err
    assert cfg.llm_provider == "ollama"


def test_every_documented_key_is_known_and_does_not_warn(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SOME_KEY_VAR", "k")
    cfg = ScannerConfig.load_from_file(_config(tmp_path, FULL_CONFIG))
    assert capsys.readouterr().err == ""
    assert cfg.detect_zino is True and cfg.vuln_check_enabled is False


def test_the_repo_example_config_loads_without_warnings(capsys):
    ScannerConfig.load_from_file(str(ROOT / "scanner-config.yaml"))
    assert capsys.readouterr().err == ""


def test_the_readme_config_example_loads_without_warnings(tmp_path, capsys):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```", readme, re.S)
    block = next(b for b in blocks if "scanners:" in b and "llm:" in b)
    ScannerConfig.load_from_file(_config(tmp_path, block))
    assert capsys.readouterr().err == ""


# --- the CLI maps config errors to exit code 2 -----------------------------------------------

@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    (path / "a.py").write_text("x = 1\n")
    return path


def test_scan_with_a_bad_config_exits_2(tmp_path, repo):
    bad = _config(tmp_path, "config_version: 9\n")
    result = CliRunner().invoke(cli, ["scan", str(repo), "-c", bad, "--no-llm", "-d", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "Error:" in result.stderr and "config_version" in result.stderr


def test_scan_with_a_missing_config_exits_2(tmp_path, repo):
    result = CliRunner().invoke(cli, ["scan", str(repo), "-c", str(tmp_path / "nope.yaml"), "-d", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "not found" in result.stderr


def test_scan_batch_with_a_bad_config_exits_2(tmp_path, repo):
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{repo}\n")
    bad = _config(tmp_path, "config_version: 9\n")
    result = CliRunner().invoke(cli, ["scan-batch", str(targets), "-c", bad, "-d", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "Error:" in result.stderr


def test_scan_org_validates_the_config_before_listing_repositories(tmp_path, monkeypatch):
    class Boom:
        def __init__(self, token=None):
            pass

        def list_repos_for(self, *args, **kwargs):
            raise AssertionError("repositories were listed before the config was validated")

    monkeypatch.setattr("quin_scanner.github_client.GitHubClient", Boom)
    bad = _config(tmp_path, "config_version: 9\n")
    result = CliRunner().invoke(cli, ["scan-org", "acme", "-c", bad, "--output-dir", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "Error:" in result.stderr


def test_skills_scan_with_a_bad_config_exits_2(tmp_path, repo):
    bad = _config(tmp_path, "config_version: 9\n")
    result = CliRunner().invoke(cli, ["skills", "scan", str(repo), "-c", bad])
    assert result.exit_code == 2
