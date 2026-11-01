"""Ctrl-C stops a scan promptly and leaves nothing behind (UAT finding U4)."""
from __future__ import annotations

import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from quin_scanner import orchestrator
from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanInterrupted, ScanOrchestrator, _ReadTrackingAccessor
from quin_scanner.repo_accessor import GitCloneAccessor, LocalRepoAccessor
from quin_scanner.scanners.base import BaseScanner


STARTED = threading.Event()


class SlowScanner(BaseScanner):
    """Reads a file in a loop for about 20 seconds, as a scanner working through a big repository would."""

    def name(self) -> str:
        return "SlowScanner"

    def scan(self, accessor, file_index):
        STARTED.set()
        for _ in range(400):
            try:
                accessor.read_file("a.txt")
            except Exception:  # noqa: BLE001  (like the many scanners that skip unreadable files)
                pass
            time.sleep(0.05)
        return []


def test_an_interrupt_during_the_scanner_phase_stops_the_scan_promptly(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    monkeypatch.setitem(orchestrator._SCANNER_REGISTRY, "slow", SlowScanner)
    STARTED.clear()

    def interrupted_wait(futures):
        # What the main thread sees when the user presses Ctrl-C while it waits for the scanners.
        assert STARTED.wait(10), "the scanner never started"
        raise KeyboardInterrupt
        yield  # pragma: no cover  (makes this a generator like as_completed)

    monkeypatch.setattr(orchestrator, "as_completed", interrupted_wait)
    config = ScannerConfig(enabled_scanners=["slow"], no_llm=True, vuln_check_enabled=False)
    before = threading.active_count()
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        ScanOrchestrator().run(LocalRepoAccessor(tmp_path), config, verbose=False)
    elapsed = time.monotonic() - started
    assert elapsed < 5, f"the interrupt took {elapsed:.1f}s to take effect (the scanner alone runs for ~20s)"
    time.sleep(0.2)
    assert threading.active_count() <= before, "scanner threads were left running"


def test_cancelling_makes_reads_raise_something_scanners_cannot_swallow(tmp_path):
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    tracked = _ReadTrackingAccessor(LocalRepoAccessor(tmp_path))
    assert tracked.read_file("a.txt") == "x"
    tracked.cancelled.set()
    with pytest.raises(ScanInterrupted):
        tracked.read_file("a.txt")
    assert not issubclass(ScanInterrupted, Exception)  # `except Exception: continue` must not hide it


def test_an_interrupted_clone_removes_its_temporary_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    class Stderr:
        def read(self, n):
            raise KeyboardInterrupt

    class FakeGit:
        stderr = Stderr()
        stdout = None
        returncode = None
        killed = False

        def kill(self):
            FakeGit.killed = True

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return None

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeGit())
    accessor = GitCloneAccessor("https://example.invalid/o/r", branch="main")
    with pytest.raises(KeyboardInterrupt):
        accessor.setup(verbose=False)
    assert FakeGit.killed, "the git process was not stopped"
    assert not [p for p in Path(tmp_path).iterdir() if p.name.startswith("quin_scanner_")], "the partial clone was left behind"
