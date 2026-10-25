import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import _SCANNER_REGISTRY, ScanOrchestrator, _ReadTrackingAccessor
from quin_scanner.repo_accessor import LocalRepoAccessor

FIXTURES = Path(__file__).parent / "fixtures" / "skills_repo"


class _CountingAccessor:
    """In-memory backing accessor that counts read_file calls per path."""

    def __init__(self, files: dict[str, str], fail: set[str] | None = None) -> None:
        self.files = dict(files)
        self.fail = set(fail or ())
        self.reads: Counter[str] = Counter()
        self._lock = threading.Lock()

    def read_file(self, path: str) -> str:
        with self._lock:
            self.reads[path] += 1
        if path in self.fail or path not in self.files:
            raise OSError(f"cannot read {path}")
        return self.files[path]

    def repo_identifier(self) -> str:
        return "mem://repo"


class _CountingLocalAccessor(LocalRepoAccessor):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.reads: Counter[str] = Counter()
        self._lock = threading.Lock()

    def read_file(self, path: str) -> str:
        with self._lock:
            self.reads[path] += 1
        return super().read_file(path)


def test_second_read_hits_backing_accessor_once():
    backing = _CountingAccessor({"a.py": "print(1)"})
    tracked = _ReadTrackingAccessor(backing)
    assert tracked.read_file("a.py") == "print(1)"
    assert tracked.read_file("a.py") == "print(1)"
    assert backing.reads["a.py"] == 1
    assert tracked.coverage() == {"file_read_attempts": 2, "files_read": 1, "files_failed_to_read": 0}
    assert tracked.cache_stats() == {"hits": 1, "bytes_cached": len("print(1)")}


def test_attribute_passthrough_still_works():
    tracked = _ReadTrackingAccessor(_CountingAccessor({}))
    assert tracked.repo_identifier() == "mem://repo"


def test_oversize_file_is_not_cached():
    big = "x" * 101
    backing = _CountingAccessor({"big.txt": big, "small.txt": "y"})
    tracked = _ReadTrackingAccessor(backing, max_file_bytes=100, max_total_bytes=10_000)
    for _ in range(3):
        assert tracked.read_file("big.txt") == big
        assert tracked.read_file("small.txt") == "y"
    assert backing.reads == {"big.txt": 3, "small.txt": 1}
    assert tracked.coverage()["file_read_attempts"] == 6
    assert tracked.cache_stats() == {"hits": 2, "bytes_cached": 1}


def test_file_size_is_measured_in_utf8_bytes():
    text = "é" * 60   # 60 characters, 120 bytes
    backing = _CountingAccessor({"u.txt": text})
    tracked = _ReadTrackingAccessor(backing, max_file_bytes=100, max_total_bytes=10_000)
    tracked.read_file("u.txt")
    tracked.read_file("u.txt")
    assert backing.reads["u.txt"] == 2


def test_total_budget_stops_caching_without_evicting():
    files = {f"f{i}": "z" * 40 for i in range(4)}
    backing = _CountingAccessor(files)
    tracked = _ReadTrackingAccessor(backing, max_file_bytes=100, max_total_bytes=100)
    for _ in range(2):
        for p in files:
            assert tracked.read_file(p) == files[p]
    # f0 and f1 fit (80 bytes); f2 would exceed the 100-byte budget and so would f3.
    assert backing.reads == {"f0": 1, "f1": 1, "f2": 2, "f3": 2}
    assert tracked.cache_stats() == {"hits": 2, "bytes_cached": 80}


def test_failed_read_is_not_cached_and_is_counted():
    backing = _CountingAccessor({}, fail={"bad.py"})
    tracked = _ReadTrackingAccessor(backing)
    for _ in range(2):
        with pytest.raises(OSError):
            tracked.read_file("bad.py")
    assert backing.reads["bad.py"] == 2
    assert tracked.coverage() == {"file_read_attempts": 2, "files_read": 0, "files_failed_to_read": 1}
    assert tracked.cache_stats()["hits"] == 0


def test_successful_read_after_failure_works_and_is_then_cached():
    backing = _CountingAccessor({"flaky.py": "ok"}, fail={"flaky.py"})
    tracked = _ReadTrackingAccessor(backing)
    with pytest.raises(OSError):
        tracked.read_file("flaky.py")
    backing.fail.clear()
    assert tracked.read_file("flaky.py") == "ok"
    assert tracked.read_file("flaky.py") == "ok"
    assert backing.reads["flaky.py"] == 2
    assert tracked.coverage() == {"file_read_attempts": 3, "files_read": 1, "files_failed_to_read": 0}


def test_concurrent_reads_are_consistent():
    files = {f"p{i}.py": f"content {i}\n" * 50 for i in range(5)}
    backing = _CountingAccessor(files, fail={"missing.py"})
    tracked = _ReadTrackingAccessor(backing)
    paths = [*files, "missing.py"] * 200

    def read(path: str) -> str | None:
        try:
            return tracked.read_file(path)
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(read, paths))

    for path, result in zip(paths, results):
        assert result == files.get(path)
    cov = tracked.coverage()
    assert cov == {"file_read_attempts": len(paths), "files_read": 5, "files_failed_to_read": 1}
    stats = tracked.cache_stats()
    assert stats["bytes_cached"] == sum(len(v) for v in files.values())
    backing_ok_reads = sum(n for p, n in backing.reads.items() if p != "missing.py")
    assert backing_ok_reads == 5                 # concurrent first reads wait for the one in flight
    assert stats["hits"] == 5 * 200 - 5
    assert backing.reads["missing.py"] == 200


def test_scan_reads_each_file_from_backing_accessor_at_most_once():
    accessor = _CountingLocalAccessor(FIXTURES)
    config = ScannerConfig(
        enabled_scanners=list(_SCANNER_REGISTRY),
        no_llm=True,
        vuln_check_enabled=False,
    )
    report = ScanOrchestrator().run(accessor, config, verbose=False)
    assert accessor.reads, "expected the scan to read files"
    assert max(accessor.reads.values()) == 1
    assert report.metadata["read_cache"]["hits"] > 0
    assert report.coverage["file_read_attempts"] > report.coverage["files_read"]


def test_untracked_view_shares_cache_without_touching_coverage():
    backing = _CountingAccessor({"a.py": "x"})
    tracked = _ReadTrackingAccessor(backing)
    view = tracked.untracked()
    assert view.read_file("a.py") == "x"
    assert tracked.coverage() == {"file_read_attempts": 0, "files_read": 0, "files_failed_to_read": 0}
    assert tracked.read_file("a.py") == "x"
    assert backing.reads["a.py"] == 1
    assert view.repo_identifier() == "mem://repo"
    assert tracked.coverage() == {"file_read_attempts": 1, "files_read": 1, "files_failed_to_read": 0}


def test_overlapping_first_reads_wait_for_the_reader_in_flight():
    started = threading.Event()
    release = threading.Event()

    class _Slow(_CountingAccessor):
        def read_file(self, path: str) -> str:
            started.set()
            assert release.wait(5)
            return super().read_file(path)

    backing = _Slow({"a.py": "slow"})
    tracked = _ReadTrackingAccessor(backing)
    with ThreadPoolExecutor(max_workers=8) as pool:
        first = pool.submit(tracked.read_file, "a.py")
        assert started.wait(5)
        others = [pool.submit(tracked.read_file, "a.py") for _ in range(7)]
        release.set()
        assert first.result(5) == "slow"
        assert [f.result(5) for f in others] == ["slow"] * 7
    assert backing.reads["a.py"] == 1
    assert tracked.coverage()["file_read_attempts"] == 8
