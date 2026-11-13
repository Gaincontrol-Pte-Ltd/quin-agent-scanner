"""`-o` is the format and `-f` the file; when `-o` is given a file name, the error says so (#104)."""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli


def _err(args):
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 2, result.output
    return result.stderr


@pytest.mark.parametrize("value, suggestion", [
    ("report.html", "-o html -f report.html"),
    ("out/x.sarif", "-o sarif -f out/x.sarif"),
    ("r.YML", "-o yaml -f r.YML"),
    ("reports/latest", "-f reports/latest"),
])
def test_scan_points_a_file_name_to_dash_f(tmp_path, value, suggestion):
    err = _err(["scan", str(tmp_path), "--no-llm", "-o", value])
    assert "is not one of" in err
    assert "-o sets the report format" in err
    assert suggestion in err


def test_scan_without_a_known_extension_does_not_guess_a_format(tmp_path):
    err = _err(["scan", str(tmp_path), "--no-llm", "-o", "reports/latest"])
    assert "-o json" not in err and "-o html -f" not in err


def test_a_plain_wrong_format_gets_no_file_hint(tmp_path):
    err = _err(["scan", str(tmp_path), "--no-llm", "-o", "xml"])
    assert "is not one of" in err
    assert "-o sets the report format" not in err


@pytest.mark.parametrize("command", ["scan-batch", "scan-org"])
def test_batch_commands_point_to_the_output_dir(tmp_path, command):
    target = str(tmp_path) if command == "scan-batch" else "some-org"
    err = _err([command, target, "--no-llm", "-o", "results.json"])
    assert "-o sets the report format" in err
    assert "-o json -d DIR" in err
    assert "-f" not in err.split("is not one of")[1]


def test_skills_scan_hint_only_suggests_formats_it_supports(tmp_path):
    err = _err(["skills", "scan", str(tmp_path), "-o", "skills.sarif"])
    assert "-o sarif -f skills.sarif" in err
    err = _err(["skills", "scan", str(tmp_path), "-o", "skills.html"])
    assert "-f skills.html" in err and "-o html" not in err


def test_skills_baseline_dash_o_is_still_the_file(tmp_path):
    (tmp_path / "s" / "demo").mkdir(parents=True)
    (tmp_path / "s" / "demo" / "SKILL.md").write_text("---\nname: demo\ndescription: Demo.\n---\n\nText.\n", encoding="utf-8")
    out = tmp_path / "baseline.yaml"
    result = CliRunner().invoke(cli, ["skills", "baseline", str(tmp_path / "s"), "-o", str(out), "--no-vuln-check"])
    assert result.exit_code == 0, result.output
    assert out.is_file()


def test_valid_formats_still_work(tmp_path):
    (tmp_path / "main.py").write_text("print(1)\n", encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
