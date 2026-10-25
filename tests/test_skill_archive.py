"""Tests for safe zip extraction used by `quin-scanner skills scan <file.zip>`."""
from __future__ import annotations

import stat
import zipfile

import pytest

from quin_scanner.scanners.skills import archive
from quin_scanner.scanners.skills.archive import ArchiveError, extract_zip, extracted_zip


def _zip(path, members):
    """members: list of (name, data) or (ZipInfo, data)."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


def _symlink_info(name):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


class TestExtractedZip:
    def test_happy_path_extracts_and_cleans_up(self, tmp_path):
        z = _zip(tmp_path / "s.zip", [("my-skill/SKILL.md", "---\nname: x\n---\nhi\n"),
                                      ("my-skill/scripts/a.py", "print(1)\n")])
        with extracted_zip(z) as root:
            assert (root / "my-skill" / "SKILL.md").read_text().startswith("---")
            assert (root / "my-skill" / "scripts" / "a.py").is_file()
            kept = root
        assert not kept.exists()

    def test_cleans_up_when_body_raises(self, tmp_path):
        z = _zip(tmp_path / "s.zip", [("SKILL.md", "x")])
        with pytest.raises(RuntimeError):
            with extracted_zip(z) as root:
                kept = root
                raise RuntimeError("boom")
        assert not kept.exists()

    def test_directory_entries_are_fine(self, tmp_path):
        z = _zip(tmp_path / "s.zip", [("d/", ""), ("d/SKILL.md", "x")])
        with extracted_zip(z) as root:
            assert (root / "d" / "SKILL.md").is_file()


class TestRejections:
    @pytest.mark.parametrize("name", [
        "../evil.txt", "a/../../evil.txt", "/abs/evil.txt", "..\\evil.txt", "C:/evil.txt", "C:\\evil.txt",
    ])
    def test_traversal_and_absolute_rejected(self, tmp_path, name):
        z = _zip(tmp_path / "s.zip", [("ok/SKILL.md", "x"), (name, "pwned")])
        dest = tmp_path / "out" / "inner"
        dest.mkdir(parents=True)
        with pytest.raises(ArchiveError):
            extract_zip(z, dest)
        # Validation runs before anything is written.
        assert list(dest.iterdir()) == []
        assert not (tmp_path / "out" / "evil.txt").exists()
        assert not (tmp_path / "evil.txt").exists()

    def test_symlink_rejected(self, tmp_path):
        z = _zip(tmp_path / "s.zip", [("SKILL.md", "x"), (_symlink_info("link"), "/etc/passwd")])
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveError, match="symlink"):
            extract_zip(z, dest)
        assert list(dest.iterdir()) == []

    def test_total_size_limit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 100)
        z = _zip(tmp_path / "s.zip", [("SKILL.md", "x" * 60), ("b.txt", "y" * 60)])
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveError, match="size"):
            extract_zip(z, dest)
        assert list(dest.iterdir()) == []

    def test_default_limits_match_spec(self):
        assert archive.MAX_MEMBERS == 5000
        assert archive.MAX_TOTAL_BYTES == 200 * 1024 * 1024

    def test_member_count_limit(self, tmp_path):
        z = _zip(tmp_path / "s.zip", [(f"f{i}.txt", "") for i in range(archive.MAX_MEMBERS + 1)])
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveError, match="members"):
            extract_zip(z, dest)
        assert list(dest.iterdir()) == []

    def test_not_a_zip(self, tmp_path):
        bad = tmp_path / "s.zip"
        bad.write_text("not a zip")
        with pytest.raises(ArchiveError):
            with extracted_zip(bad):
                pass

    def test_missing_file(self, tmp_path):
        with pytest.raises(ArchiveError):
            with extracted_zip(tmp_path / "nope.zip"):
                pass
