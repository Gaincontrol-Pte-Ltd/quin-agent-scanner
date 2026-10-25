"""Skills-only scan of a target (directory, .zip or repo URL), shared by `quin-scanner skills scan`."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quin_scanner.config import ScannerConfig
from quin_scanner.file_index import FileIndex
from quin_scanner.models import SkillAssessment
from quin_scanner.repo_accessor import LocalRepoAccessor, RepoAccessor, RepoAccessorFactory
from quin_scanner.scanners.skills.archive import ArchiveError, extracted_zip
from quin_scanner.scanners.skills.baseline import Baseline, BaselineResult, apply_baseline
from quin_scanner.scanners.skills.llm_review import review_skills
from quin_scanner.scanners.skills.scanner import SkillScanner


@dataclass
class SkillScanResult:
    assessments: list[SkillAssessment] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    baseline: BaselineResult | None = None


def run_skill_scan(
    accessor: RepoAccessor, config: ScannerConfig, baseline: Baseline | None = None
) -> SkillScanResult:
    """Run only SkillScanner on *accessor*, then the optional LLM review unless ``config.no_llm``.

    A *baseline* is applied before the LLM review, so suppressed findings are never reviewed,
    scored or promoted. The LLM review fails soft: provider errors are recorded in ``notes``
    and static results stand.
    """
    file_index = FileIndex(accessor)
    file_index.build()
    scanner = SkillScanner(vuln_check_enabled=config.vuln_check_enabled)
    scanner.scan(accessor, file_index)
    notes = list(scanner.notes)
    baseline_result = apply_baseline(scanner.assessments, baseline) if baseline is not None else None
    if not config.no_llm and scanner.assessments:
        try:
            provider = config.provider_factory()
        except Exception as exc:
            notes.append(f"SkillReview: provider unavailable: {type(exc).__name__}: {exc}")
        else:
            notes.extend(review_skills(scanner.assessments, provider))
    return SkillScanResult(
        assessments=list(scanner.assessments),
        notes=notes,
        coverage={**file_index.coverage(), **scanner.coverage()},
        baseline=baseline_result,
    )


@contextmanager
def open_skill_target(
    target: str,
    *,
    github_token: str | None = None,
    azure_token: str | None = None,
    branch: str = "main",
) -> Iterator[RepoAccessor]:
    """Yield an accessor for a local directory, a .zip file (extracted safely) or a repo URL.

    Raises ValueError (ArchiveError for archives) for a target that cannot be scanned.
    Temp directories and clones are always cleaned up.
    """
    path = Path(target)
    if target.lower().endswith(".zip") or path.is_file():
        if not path.is_file():
            raise ArchiveError(f"zip file not found: {target}")
        with extracted_zip(path) as root:
            yield LocalRepoAccessor(root)
        return

    accessor = RepoAccessorFactory.create(
        target, github_token=github_token, branch=branch, azure_token=azure_token
    )
    try:
        if isinstance(accessor, LocalRepoAccessor) and not accessor.root.is_dir():
            raise ValueError(f"not a directory: {target}")
        yield accessor
    finally:
        accessor.cleanup()
