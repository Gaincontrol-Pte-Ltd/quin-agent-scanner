from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

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


@runtime_checkable
class EvidenceProducer(Protocol):
    """A scanner that also hands typed evidence (AgentSite, ToolSite) to the inventory after scan()."""

    def evidence(self) -> list: ...
