"""scripts/check_release_version.py: a tag that does not match the code must not publish."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_release_version", ROOT / "scripts" / "check_release_version.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)  # type: ignore[union-attr]

BETA = '"Development Status :: 4 - Beta"'
STABLE = '"Development Status :: 5 - Production/Stable"'


def make_repo(tmp_path, *, version, module_version=None, classifier=BETA, changelog_version=None):
    (tmp_path / "src" / "quin_scanner").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nversion = "{version}"\nclassifiers = [{classifier}]\n', encoding="utf-8"
    )
    (tmp_path / "src" / "quin_scanner" / "__init__.py").write_text(
        f'__version__ = "{module_version or version}"\n', encoding="utf-8"
    )
    # The em dash matches the real CHANGELOG; written as UTF-8 so the test does not depend on the platform encoding.
    (tmp_path / "CHANGELOG.md").write_text(
        f"## [Unreleased]\n\n## [{changelog_version or version}] — 2026-11-04\n\nText.\n", encoding="utf-8"
    )
    return tmp_path


def test_a_consistent_release_candidate_passes(tmp_path):
    assert check.problems("v1.0.0rc3", make_repo(tmp_path, version="1.0.0rc3")) == []


def test_a_consistent_stable_release_passes(tmp_path):
    assert check.problems("v1.0.0", make_repo(tmp_path, version="1.0.0", classifier=STABLE)) == []


def test_pyproject_behind_the_tag_is_reported(tmp_path):
    found = check.problems("v1.0.0rc3", make_repo(tmp_path, version="1.0.0rc2", changelog_version="1.0.0rc3"))
    assert any("pyproject.toml version is 1.0.0rc2" in line for line in found)


def test_module_version_behind_the_tag_is_reported(tmp_path):
    found = check.problems("v1.0.0rc3", make_repo(tmp_path, version="1.0.0rc3", module_version="1.0.0rc2"))
    assert any("__version__ is 1.0.0rc2" in line for line in found)


def test_a_missing_changelog_section_is_reported(tmp_path):
    found = check.problems("v1.0.0rc3", make_repo(tmp_path, version="1.0.0rc3", changelog_version="1.0.0rc2"))
    assert any("no '## [1.0.0rc3]' section" in line for line in found)


def test_a_stable_release_still_marked_beta_is_reported(tmp_path):
    found = check.problems("v1.0.0", make_repo(tmp_path, version="1.0.0", classifier=BETA))
    assert any("Production/Stable" in line for line in found)


@pytest.mark.parametrize("tag", ["1.0.0", "v1.0", "v1.0.0-rc1", "beta", "v1.0.0rc"])
def test_a_tag_that_is_not_a_release_tag_is_rejected(tmp_path, tag):
    assert check.problems(tag, make_repo(tmp_path, version="1.0.0")) != []


def test_the_exit_code_follows_the_result(tmp_path, capsys):
    root = make_repo(tmp_path, version="1.0.0rc3", module_version="1.0.0rc2")
    assert check.main(["v1.0.0rc3", "--root", str(root)]) == 1
    assert "error:" in capsys.readouterr().err
    assert check.main(["v1.0.0rc3", "--root", str(make_repo(tmp_path / "ok", version="1.0.0rc3"))]) == 0


def test_this_repository_reports_the_version_it_declares():
    """The version lives in pyproject.toml and in quin_scanner/__init__.py; they must not drift apart."""
    import quin_scanner

    declared = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE).group(1)
    assert quin_scanner.__version__ == declared
