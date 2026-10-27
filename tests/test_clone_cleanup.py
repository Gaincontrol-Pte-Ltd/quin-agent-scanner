"""Temp clones contain read-only git files; removing them must work on Windows; askpass helper details."""
from __future__ import annotations

import os
import stat
import sys

import pytest

from quin_scanner.repo_accessor import _write_askpass_script, remove_tree


def _readonly_tree(root):
    objects = root / ".git" / "objects" / "47"
    objects.mkdir(parents=True)
    packed = objects / "643d4d"
    packed.write_text("object")
    os.chmod(packed, stat.S_IREAD)  # git writes object files read-only; Windows refuses to delete them
    return root


def test_remove_tree_removes_read_only_files(tmp_path):
    root = _readonly_tree(tmp_path / "clone")
    remove_tree(root)
    assert not root.exists()


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_remove_tree_removes_a_tree_with_a_read_only_directory(tmp_path):
    root = tmp_path / "clone"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "file.txt").write_text("x")
    os.chmod(root / "sub", stat.S_IRUSR | stat.S_IXUSR)  # cannot unlink files inside
    remove_tree(root)
    assert not root.exists()


def test_remove_tree_on_a_missing_path_is_a_no_op(tmp_path):
    remove_tree(tmp_path / "missing")


def test_askpass_script_content_has_no_carriage_returns(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    path = _write_askpass_script("s3cret-token")
    try:
        data = open(path, "rb").read()
        assert data == b"#!/bin/sh\necho s3cret-token\n"
        assert b"\r" not in data
        if sys.platform != "win32":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
    finally:
        os.unlink(path)
