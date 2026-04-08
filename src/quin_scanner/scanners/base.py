from __future__ import annotations

from abc import ABC, abstractmethod

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.repo_accessor import RepoAccessor


class BaseScanner(ABC):
    """All scanner plugins implement this interface."""

    @abstractmethod
    def name(self) -> str:
        """Return the scanner's display name."""
        ...

    @abstractmethod
    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        """Scan the repo and return findings."""
        ...
