from __future__ import annotations

import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime, timezone

from quin_scanner.config import ScannerConfig
from quin_scanner.file_index import FileIndex
from quin_scanner.llm.synthesis_agent import SynthesisAgent
from quin_scanner.models import (
    InfraProfile,
    MCPServer,
    ScanFinding,
    ScanReport,
    SynthesisResult,
)
from quin_scanner.repo_accessor import RepoAccessor
from quin_scanner.scanners.base import BaseScanner
from quin_scanner.scanners.ci_scanner import CIScanner
from quin_scanner.scanners.code_pattern import CodePatternScanner
from quin_scanner.scanners.config_scanner import ConfigScanner
from quin_scanner.scanners.dependency import DependencyScanner
from quin_scanner.scanners.dockerfile import DockerfileScanner
from quin_scanner.scanners.file_structure import FileStructureScanner
from quin_scanner.scanners.framework import FrameworkMarkerScanner
from quin_scanner.scanners.iac import IaCScanner
from quin_scanner.scanners.jupyter import JupyterScanner
from quin_scanner.scanners.mcp_scanner import MCPScanner
from quin_scanner.scanners.prompt_discovery import PromptDiscoveryScanner
from quin_scanner.scanners.agent_instance_scanner import AgentInstanceScanner
from quin_scanner.scanners.tool_definition_scanner import ToolDefinitionScanner

_print_lock = threading.Lock()

_SNIPPET_CAP = 500      # max characters per match_text snippet
_TOP_N_DEFAULT = 5      # top findings per scanner
_TOP_N_PROMPT = 10      # higher cap for PromptDiscoveryScanner


def _log(msg: str) -> None:
    with _print_lock:
        print(msg, file=sys.stderr, flush=True)


def _progress_bar(label: str, current: int, total: int) -> None:
    """Render an in-place progress bar on stderr."""
    width = 25
    filled = int(current / total * width) if total else width
    bar = "█" * filled + "░" * (width - filled)
    pct = int(current / total * 100) if total else 100
    line = f"\r  {label}  [{bar}] {pct:3d}%  ({current}/{total})"
    with _print_lock:
        sys.stderr.write(line)
        sys.stderr.flush()
        if current == total:
            sys.stderr.write("\n")
            sys.stderr.flush()

_SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "dependency": DependencyScanner,
    "config": ConfigScanner,
    "code_pattern": CodePatternScanner,
    "file_structure": FileStructureScanner,
    "framework": FrameworkMarkerScanner,
    "prompt_discovery": PromptDiscoveryScanner,
    "dockerfile": DockerfileScanner,
    "jupyter": JupyterScanner,
    "iac": IaCScanner,
    "ci": CIScanner,
    "mcp": MCPScanner,
    "agent_instance": AgentInstanceScanner,
    "tool_definition": ToolDefinitionScanner,
}

_CONFIDENCE_THRESHOLD = 0.5

# Test file path patterns — model usages from these are filtered out of the main list
_TEST_PATH_PATTERNS = re.compile(
    r"(^|[\\/])(test_|tests[\\/]|test[\\/]|__tests__[\\/]|fixtures[\\/]"
    r"|conftest\.py$|\.spec\.|_test\.|\.test\.)",
    re.IGNORECASE,
)

# Placeholder model name patterns to reject entirely
_PLACEHOLDER_PREFIXES = ("your_", "test-", "mock-", "fake-", "dummy-", "example-")
_PLACEHOLDER_EXACT = frozenset({
    "model_id", "model_name", "model", "<model>", "your-model-here",
    "your-model", "placeholder", "model_id_here", "model-id",
})


def _is_test_path(file_path: str) -> bool:
    return bool(_TEST_PATH_PATTERNS.search(file_path))


def _is_placeholder_model(model_name: str) -> bool:
    lower = model_name.lower()
    if lower in _PLACEHOLDER_EXACT:
        return True
    if any(lower.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        return True
    # Template values like YOUR_VALUE_HERE
    if lower.startswith("your_") or lower.startswith("your-"):
        return True
    # Contains spaces (not a valid model ID)
    if " " in model_name:
        return True
    # Very short names (already caught by ModelIdentifier but belt-and-suspenders)
    if len(model_name) < 3:
        return True
    return False


def _pre_summarise(findings: list[ScanFinding]) -> list[dict]:
    """Group findings by scanner, select top-N by confidence, truncate snippets."""
    by_scanner: dict[str, list[ScanFinding]] = {}
    for f in findings:
        by_scanner.setdefault(f.scanner_name, []).append(f)

    summaries: list[dict] = []
    for scanner_name, scanner_findings in by_scanner.items():
        cap = _TOP_N_PROMPT if scanner_name == "PromptDiscoveryScanner" else _TOP_N_DEFAULT
        sorted_findings = sorted(scanner_findings, key=lambda f: f.confidence, reverse=True)
        top = sorted_findings[:cap]
        summaries.append({
            "scanner": scanner_name,
            "finding_count": len(scanner_findings),
            "top_findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "text": f.match_text[:_SNIPPET_CAP],
                    "tag": f.capability_tag,
                    "confidence": f.confidence,
                }
                for f in top
            ],
        })
    return summaries


def _extract_mcp_servers(findings: list[ScanFinding]) -> list[MCPServer]:
    """Extract MCPServer entries from MCPScanner findings (no LLM)."""
    servers: list[MCPServer] = []
    for f in findings:
        if f.scanner_name != "MCPScanner":
            continue
        text = f.match_text.lower()
        if text.startswith("stdio") or "stdio" in text:
            transport = "stdio"
        elif text.startswith("http"):
            transport = "http"
        elif "sse" in text:
            transport = "sse"
        else:
            transport = "unknown"
        # Use raw match_text as server name (strip transport prefix if present)
        name = f.match_text.split(":")[-1].strip() if ":" in f.match_text else f.match_text
        servers.append(MCPServer(name=name, transport=transport, source_file=f.file_path))
    return servers


def _extract_infra(findings: list[ScanFinding]) -> InfraProfile | None:
    """Extract InfraProfile from IaCScanner findings (no LLM)."""
    iac_findings = [f for f in findings if f.scanner_name == "IaCScanner"]
    if not iac_findings:
        return None

    source_files = [f.file_path for f in iac_findings]
    details = [f.match_text[:200] for f in iac_findings]

    # Determine platform from file paths
    all_paths = " ".join(source_files).lower()
    if ".tf" in all_paths or "terraform" in all_paths:
        platform = "terraform"
    elif "k8s" in all_paths or "kubernetes" in all_paths or "deployment.yaml" in all_paths or "deployment.yml" in all_paths:
        platform = "kubernetes"
    elif "docker-compose" in all_paths:
        platform = "docker-compose"
    else:
        platform = "iac"

    return InfraProfile(platform=platform, details=details, source_files=source_files)


def _load_frameworks_lookup() -> dict:
    """Load frameworks_lookup.yaml once."""
    import yaml
    rules_dir = Path(__file__).parent / "rules"
    path = rules_dir / "frameworks_lookup.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


_FRAMEWORKS_LOOKUP: dict | None = None


def _detect_framework(findings: list) -> str:
    """Rule-based framework detection from scanner findings.

    Priority: file markers > package names. Returns 'unknown' if no match.
    """
    global _FRAMEWORKS_LOOKUP
    if _FRAMEWORKS_LOOKUP is None:
        _FRAMEWORKS_LOOKUP = _load_frameworks_lookup()

    file_markers = _FRAMEWORKS_LOOKUP.get("file_markers", {})
    packages = _FRAMEWORKS_LOOKUP.get("packages", {})

    # Pass 1: file markers (highest priority) — skip markers found in example/demo/test dirs
    _SECONDARY_DIR_SEGMENTS = frozenset({
        "examples", "example", "demos", "demo", "docs", "doc",
        "test", "tests", "sample", "samples", "notebooks",
    })
    for f in findings:
        if f.scanner_name == "FrameworkMarkerScanner":
            path_parts = set(Path(f.file_path).parts[:-1])
            if path_parts & _SECONDARY_DIR_SEGMENTS:
                continue  # skip — marker is from a secondary directory, not the primary framework
            fname = Path(f.file_path).name.lower()
            for marker, framework in file_markers.items():
                if fname == marker.lower():
                    return framework

    # Pass 2: package names from DependencyScanner — iterate packages in YAML priority
    # order (most specific first), then search all dep findings for each package.
    # This ensures higher-priority entries win regardless of findings order.
    dep_texts = [
        f.match_text.lower().strip()
        for f in findings
        if f.scanner_name == "DependencyScanner"
    ]
    for pkg, framework in packages.items():
        pkg_lower = pkg.lower()
        for text in dep_texts:
            if (
                text == pkg_lower
                or text.startswith(pkg_lower + "=")
                or text.startswith(pkg_lower + ">")
                or text.startswith(pkg_lower + "<")
                or text.startswith(pkg_lower + "~")
                or text.startswith(pkg_lower + "[")
            ):
                return framework

    # Pass 3: code pattern imports — fallback for frameworks not detectable via deps/files
    # (e.g. Vercel AI SDK repos that use `ai` / `@ai-sdk/*` imports)
    _CODE_PATTERN_FRAMEWORK_MAP = [
        # Vercel AI SDK — high-signal imports that uniquely identify the framework
        (re.compile(r"from\s+['\"]@ai-sdk/", re.IGNORECASE), "Vercel AI SDK"),
        (re.compile(r"from\s+['\"]ai['\"]", re.IGNORECASE), "Vercel AI SDK"),
        # AutoGen — fallback if dependency names weren't in requirements.txt
        (re.compile(r"from\s+autogen_agentchat", re.IGNORECASE), "AutoGen"),
        (re.compile(r"from\s+autogen_ext", re.IGNORECASE), "AutoGen"),
        (re.compile(r"from\s+autogen_core", re.IGNORECASE), "AutoGen"),
    ]
    code_texts = [
        f.match_text
        for f in findings
        if f.scanner_name == "CodePatternScanner"
    ]
    for pattern, framework in _CODE_PATTERN_FRAMEWORK_MAP:
        for text in code_texts:
            if pattern.search(text):
                return framework

    return "unknown"


def _sanitise_model_usages(
    usages: list,
) -> tuple[list, int]:
    """Clean model usages: reject placeholders, filter test files, deduplicate.

    Returns (cleaned_usages, test_model_count).
    """
    from quin_scanner.models import ModelUsage

    production: list[ModelUsage] = []
    test_count = 0

    for u in usages:
        if _is_placeholder_model(u.model_name):
            continue
        if _is_test_path(u.file_path):
            test_count += 1
            continue
        production.append(u)

    # Deduplicate: keep best entry per model_name (prefer known provider over unknown)
    best: dict[str, ModelUsage] = {}
    for u in production:
        key = u.model_name.lower()
        existing = best.get(key)
        if existing is None:
            best[key] = u
        elif existing.provider == "unknown" and u.provider != "unknown":
            # Prefer the entry with a known provider
            best[key] = u

    return list(best.values()), test_count


class ScanOrchestrator:
    """Ties together repo access, file indexing, scanners, LLM synthesis, and reporting."""

    def run(self, accessor: RepoAccessor, config: ScannerConfig, verbose: bool = True) -> ScanReport:
        scan_start = time.monotonic()

        # 1. Build file index
        if verbose:
            _log("Indexing files...")
        file_index = FileIndex(accessor)
        file_index.build()
        if verbose:
            file_count = len(file_index.all_files())
            _log(f"  {file_count} file{'s' if file_count != 1 else ''} indexed\n")

        # 2. Run enabled scanner plugins in parallel
        scanners: list[BaseScanner] = []
        for name in config.enabled_scanners:
            scanner_cls = _SCANNER_REGISTRY.get(name)
            if scanner_cls is not None:
                scanners.append(scanner_cls())

        if verbose:
            _log(f"Running {len(scanners)} scanners in parallel...")

        all_findings: list[ScanFinding] = []
        findings_by_scanner: dict[str, int] = {}
        completed_results: list[tuple[str, list[ScanFinding]]] = []

        def _run_scanner(scanner: BaseScanner) -> tuple[str, list[ScanFinding]]:
            return scanner.name(), scanner.scan(accessor, file_index)

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(_run_scanner, s): s for s in scanners}
            for future in as_completed(futures):
                scanner_name, findings = future.result()
                all_findings.extend(findings)
                if findings:
                    findings_by_scanner[scanner_name] = len(findings)
                completed_results.append((scanner_name, findings))
                if verbose:
                    _progress_bar("Scanners   ", len(completed_results), len(scanners))

        # Print per-scanner summary after progress bar completes
        if verbose:
            for name, findings in completed_results:
                n = len(findings)
                label = "finding" if n == 1 else "findings"
                _log(f"  [ ✓ ] {name:<30} {n} {label}")
            _log("")

        # 2b. Deduplicate findings by (file_path, line_number, capability_tag)
        all_findings = self._deduplicate(all_findings)

        # 3. Compute aggregate metrics
        is_ai = any(f.confidence >= _CONFIDENCE_THRESHOLD for f in all_findings)
        confidence = self._aggregate_confidence(all_findings)
        capability_tags = sorted(
            {f.capability_tag for f in all_findings if f.capability_tag}
        )

        # 4. Direct extraction — no LLM needed
        mcp_servers = _extract_mcp_servers(all_findings)
        infra = _extract_infra(all_findings)

        # 5. Identify model usage
        if verbose:
            _log("\nIdentifying model usage...")
        from quin_scanner.model_identifier import ModelIdentifier
        identifier = ModelIdentifier()
        model_usages = identifier.identify(accessor, file_index)
        if verbose:
            n = len(model_usages)
            _log(f"  {n} model{'s' if n != 1 else ''} found")

        # 5b. Sanitise model usages: reject placeholders, filter test files, deduplicate
        model_usages, test_model_count = _sanitise_model_usages(model_usages)

        # 5c. Rule-based framework candidate (passed to synthesis as anchor)
        framework_candidate = _detect_framework(all_findings)
        if verbose and test_model_count:
            _log(f"  {test_model_count} test-file model reference{'s' if test_model_count != 1 else ''} excluded")

        # 6. LLM synthesis
        synthesis: SynthesisResult | None = None
        llm_errors: list[str] = []
        if not config.no_llm:
            summaries = _pre_summarise(all_findings)
            provider = config.provider_factory()
            agent = SynthesisAgent(provider)
            if verbose:
                _log("\nRunning synthesis analysis...")

            # Extract structured hints from new scanners for the evidence bundle.
            # Cap at 30 each — large repos (199+ tools) cause synthesis JSON truncation.
            _EVIDENCE_CAP = 30
            agent_instances = [
                {
                    "name": f.match_text,
                    "source_file": f.file_path,
                    "line": f.line_number,
                    "confidence": f.confidence,
                }
                for f in all_findings if f.scanner_name == "AgentInstanceScanner"
            ][:_EVIDENCE_CAP]
            tool_definitions = [
                {
                    "name": f.match_text.split(" (")[0],
                    "decorator": f.match_text.split(" (")[1].rstrip(")") if " (" in f.match_text else "",
                    "source_file": f.file_path,
                    "line": f.line_number,
                }
                for f in all_findings if f.scanner_name == "ToolDefinitionScanner"
            ][:_EVIDENCE_CAP]

            _synthesis_step = [0]
            _SYNTHESIS_STEPS = 3  # building evidence, calling LLM, parsing result

            def _synthesis_progress(_msg: str) -> None:
                _synthesis_step[0] += 1
                _progress_bar("Synthesis  ", _synthesis_step[0], _SYNTHESIS_STEPS)

            try:
                synthesis = agent.synthesize(
                    scanner_summaries=summaries,
                    model_usages=model_usages,
                    capability_tags=capability_tags,
                    on_progress=_synthesis_progress if verbose else None,
                    framework_candidate=framework_candidate,
                    agent_instances=agent_instances or None,
                    tool_definitions=tool_definitions or None,
                )
                # Apply LLM confidence adjustment
                if synthesis.confidence_adjustment:
                    confidence = round(
                        min(0.99, max(0.0, confidence + synthesis.confidence_adjustment)), 4
                    )
                # LLM may override is_ai if it has strong signal
                if synthesis.is_ai_application:
                    is_ai = True
                if verbose:
                    n_agents = len(synthesis.agents)
                    _log(f"  framework: {synthesis.framework}  |  {n_agents} agent{'s' if n_agents != 1 else ''} identified")
            except Exception as e:
                err = f"SynthesisAgent: {type(e).__name__}: {e}"
                llm_errors.append(err)
                if verbose:
                    _log(f"\n  [!] LLM synthesis failed: {e}")
                    _log("      Run with --no-llm to skip synthesis, or check your --llm-provider / API key.")

        scan_duration = round(time.monotonic() - scan_start, 3)

        if verbose:
            status = "AI application detected" if is_ai else "No AI application detected"
            _log(f"\n{status}  |  confidence: {confidence}  |  {len(all_findings)} findings  |  {scan_duration}s\n")

        metadata: dict = {
            "scan_duration_seconds": scan_duration,
            "file_count": len(file_index.all_files()),
            "finding_count": len(all_findings),
            "findings_by_scanner": findings_by_scanner,
            "test_model_usages_count": test_model_count,
        }
        if llm_errors:
            metadata["llm_errors"] = llm_errors
        if config.no_llm:
            metadata["analysis"] = "static-only"

        # ── Deterministic post-processing ──────────────────────────────────────
        # Apply after synthesis so these rules fill gaps when the LLM left fields
        # empty or returned 'unknown'. Never overwrite non-empty synthesis output.

        # Rule 1: framework — use rule-based candidate when synthesis returned unknown
        pp_framework = (synthesis.framework if synthesis else "unknown") or "unknown"
        if pp_framework == "unknown" and framework_candidate != "unknown":
            pp_framework = framework_candidate

        # Rule 2: agents — fall back to AgentInstanceScanner findings when empty
        pp_agents = synthesis.agents if synthesis else []
        if not pp_agents:
            all_agent_instances = [
                f for f in all_findings if f.scanner_name == "AgentInstanceScanner"
            ]
            if all_agent_instances:
                from quin_scanner.models import AgentProfile
                pp_agents = [
                    AgentProfile(
                        name=f.match_text,
                        agent_type="unknown",
                        goal="",
                        source_file=f.file_path,
                    )
                    for f in all_agent_instances[:50]
                ]

        # Rule 3: tool_usages — fall back to ToolDefinitionScanner findings when empty
        pp_tool_usages = synthesis.tool_usages if synthesis else []
        if not pp_tool_usages:
            all_tool_defs = [
                f for f in all_findings if f.scanner_name == "ToolDefinitionScanner"
            ]
            if all_tool_defs:
                from quin_scanner.models import ToolUsage
                pp_tool_usages = [
                    ToolUsage(
                        tool_name=f.match_text.split(" (")[0],
                        source_file=f.file_path,
                        line_number=f.line_number,
                    )
                    for f in all_tool_defs[:100]
                ]

        # Rule 4: deduplicate tool_usages by (name, source_file, line_number)
        _seen_tools: set[tuple] = set()
        _deduped_tools: list = []
        for _t in pp_tool_usages:
            _key = (_t.tool_name, _t.source_file, _t.line_number)
            if _key not in _seen_tools:
                _seen_tools.add(_key)
                _deduped_tools.append(_t)
        pp_tool_usages = _deduped_tools

        # Rule 5: summary — generate a deterministic fallback when synthesis returned empty
        pp_summary = (synthesis.summary if synthesis else "") or ""
        if not pp_summary:
            tags_str = ", ".join(capability_tags) if capability_tags else "AI"
            if pp_framework != "unknown":
                pp_summary = (
                    f"{pp_framework} repository detected as an AI application "
                    f"with capabilities: {tags_str}."
                )
            elif is_ai:
                pp_summary = f"AI application with detected capabilities: {tags_str}."
        # ── End post-processing ────────────────────────────────────────────────

        return ScanReport(
            repo_path=accessor.repo_identifier(),
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            is_ai_application=is_ai,
            confidence=confidence,
            capability_tags=capability_tags,
            framework=pp_framework,
            summary=pp_summary,
            agents=pp_agents,
            tool_usages=pp_tool_usages,
            mcp_servers=mcp_servers,
            infra=infra,
            findings=all_findings,
            model_usages=model_usages,
            metadata=metadata,
        )

    @staticmethod
    def _deduplicate(findings: list[ScanFinding]) -> list[ScanFinding]:
        """Deduplicate findings by (file_path, line_number, capability_tag).

        When multiple scanners report the same signal at the same location,
        keep only the finding with the highest confidence.
        """
        best: dict[tuple, ScanFinding] = {}
        for f in findings:
            key = (f.file_path, f.line_number, f.capability_tag)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f
        return list(best.values())

    @staticmethod
    def _aggregate_confidence(findings: list[ScanFinding]) -> float:
        """Compute aggregate confidence from a list of findings.

        Uses the highest single-finding confidence as the base, then applies a
        small corroboration boost for each additional independent scanner that
        confirms AI presence. Capped at 0.99 to avoid expressing false certainty.

        Examples:
            1 finding  @ 0.95              → 0.95
            2 scanners @ 0.95, 0.90        → min(0.99, 0.95 + 0.03) = 0.98
            5+ scanners                    → capped at 0.99
        """
        if not findings:
            return 0.0
        max_conf = max(f.confidence for f in findings)
        distinct_scanners = len({f.scanner_name for f in findings})
        # 0.03 boost per additional corroborating scanner, max 3 boosts
        corroboration = 0.03 * min(distinct_scanners - 1, 3)
        return round(min(0.99, max_conf + corroboration), 4)
