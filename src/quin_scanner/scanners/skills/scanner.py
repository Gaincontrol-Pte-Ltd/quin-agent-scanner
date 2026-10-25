from __future__ import annotations

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding, SkillAssessment, SkillFinding, SkillRecord, Vulnerability
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner
from quin_scanner.scanners.skills.analyzers.code_ast import analyze_python
from quin_scanner.scanners.skills.analyzers.mcp_poisoning import analyze_mcp
from quin_scanner.scanners.skills.analyzers.permissions import analyze_permissions
from quin_scanner.scanners.skills.analyzers.supply_chain import OsvLookup, analyze_supply_chain
from quin_scanner.scanners.skills.analyzers.taint import analyze_taint
from quin_scanner.scanners.skills.analyzers.text_rules import analyze_text
from quin_scanner.scanners.skills.bundle import SkillBundle, load_bundle
from quin_scanner.scanners.skills.discovery import discover_mcp_sources, discover_skills
from quin_scanner.scanners.skills.scoring import build_assessment

MAX_SKILLS = 200
MAX_OSV_LOOKUPS = 50
_SUMMARY_CONFIDENCE = 0.45   # below the orchestrator's AI-detection threshold (0.5)
_PROMOTE_SEVERITIES = {"critical", "high"}


class SkillScanner(BaseScanner):
    """Discovers Agent Skills / MCP tool sources and assesses their security risk."""

    def __init__(self, vuln_check_enabled: bool = False, osv_lookup: OsvLookup | None = None) -> None:
        self.vuln_check_enabled = vuln_check_enabled
        self._osv_lookup = osv_lookup
        self.assessments: list[SkillAssessment] = []
        self.notes: list[str] = []
        self._files_skipped = 0
        self._analyzer_errors = 0
        self._osv_calls = 0
        self._osv_errors = 0
        self._capped = 0
        self._osv_cap_noted = False

    def name(self) -> str:
        return "SkillScanner"

    def coverage(self) -> dict[str, int]:
        return {
            "skills_found": sum(1 for a in self.assessments if a.record.ecosystem != "mcp"),
            "skills_files_skipped": self._files_skipped,
            "skills_analyzer_errors": self._analyzer_errors,
            "skills_osv_lookup_errors": self._osv_errors,
            "skills_capped": self._capped,
        }

    # ── OSV ──────────────────────────────────────────────────────────────────
    def _query_osv(self, package: str, version: str) -> list[Vulnerability]:
        if self._osv_calls >= MAX_OSV_LOOKUPS:
            if not self._osv_cap_noted:
                self._osv_cap_noted = True
                self._capped += 1
                self.notes.append(f"osv lookup cap reached: at most {MAX_OSV_LOOKUPS} lookups per scan")
            return []
        self._osv_calls += 1
        try:
            from quin_scanner import vuln_checker

            ref = vuln_checker.FrameworkRef(
                name=package, version=version, ecosystem="PyPI", package=package
            )
            return vuln_checker.query_osv(ref)
        except Exception as exc:
            self._osv_errors += 1
            self.notes.append(f"osv lookup failed for {package}=={version}: {type(exc).__name__}")
            return []

    # ── Scan ─────────────────────────────────────────────────────────────────
    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]:
        self.assessments = []
        self.notes = []
        self._files_skipped = self._analyzer_errors = self._osv_calls = self._osv_errors = 0
        self._capped = 0
        self._osv_cap_noted = False

        records = discover_skills(accessor, file_index)
        if len(records) > MAX_SKILLS:
            self.notes.append(f"skill cap reached: analysed {MAX_SKILLS} of {len(records)} skills")
            records = records[:MAX_SKILLS]
            self._capped += 1
        mcp_stats: dict = {}
        mcp = discover_mcp_sources(accessor, file_index, stats=mcp_stats)
        if mcp_stats.get("read_cap_hit"):
            self._capped += 1
            self.notes.append("MCP discovery read cap reached: some source files were not inspected")
        if mcp is not None:
            records.append(mcp)

        osv = self._osv_lookup or (self._query_osv if self.vuln_check_enabled else None)
        for record in records:
            bundle = load_bundle(record, accessor)
            self._files_skipped += len(bundle.skipped)
            if bundle.capped:
                self._capped += 1
            for item in bundle.skipped:
                self.notes.append(f"{record.name}: skipped {item}")
            self.assessments.append(build_assessment(record, self._analyze(bundle, osv)))
        return self._scan_findings()

    def _analyze(self, bundle: SkillBundle, osv: OsvLookup | None) -> list[SkillFinding]:
        if bundle.record.ecosystem == "mcp":
            analyzers = [("analyze_mcp", analyze_mcp)]
        else:
            analyzers = [
                ("analyze_text", analyze_text),
                ("analyze_python", analyze_python),
                ("analyze_taint", analyze_taint),
                ("analyze_supply_chain", lambda b: analyze_supply_chain(b, osv)),
                ("analyze_permissions", analyze_permissions),
                ("analyze_mcp", analyze_mcp),
            ]
        findings: list[SkillFinding] = []
        for label, analyzer in analyzers:
            try:
                findings.extend(analyzer(bundle))
            except Exception as exc:
                self._analyzer_errors += 1
                self.notes.append(
                    f"{bundle.record.name}: {label} failed: {type(exc).__name__}: {exc}"
                )
        return findings

    def _scan_findings(self) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        for a in self.assessments:
            rec = a.record
            out.append(ScanFinding(
                scanner_name=self.name(),
                category="skill",
                file_path=rec.skill_md_path or rec.root_path,
                line_number=None,
                match_text=f"{rec.name} [{a.verdict} {a.risk_score}]",
                capability_tag="agent-skills",
                confidence=_SUMMARY_CONFIDENCE,
            ))
            for f in a.findings:
                if f.severity not in _PROMOTE_SEVERITIES:
                    continue
                out.append(ScanFinding(
                    scanner_name=self.name(),
                    category="skill_risk",
                    file_path=f.file_path,
                    line_number=f.line_number,
                    match_text=f"{f.rule_id}: {f.title}",
                    capability_tag=f"skill-risk:{f.rule_id}",
                    confidence=min(f.confidence, _SUMMARY_CONFIDENCE),
                ))
        return out
