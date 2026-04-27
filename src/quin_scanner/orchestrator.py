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
from quin_scanner.llm.classification_agent import ClassificationAgent
from quin_scanner.llm.synthesis_agent import SynthesisAgent
from quin_scanner.rules.kri_predicates import CLOUD_LLM_PROVIDERS, EvidenceFacts
from quin_scanner.models import (
    ClassificationResult,
    InfraProfile,
    MCPServer,
    RiskIndicator,
    ScanFinding,
    ScanReport,
    SynthesisResult,
    Vulnerability,
)
from quin_scanner.vuln_checker import VulnChecker
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


def _progress_bar_pct(label: str, pct: int, *, done: bool = False) -> None:
    """Render an in-place percentage progress bar on stderr (no fraction suffix)."""
    width = 25
    pct = max(0, min(100, pct))
    filled = int(pct / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    line = f"\r  {label}  [{bar}] {pct:3d}%"
    with _print_lock:
        sys.stderr.write(line)
        sys.stderr.flush()
        if done:
            sys.stderr.write("\n")
            sys.stderr.flush()


def _run_with_animated_progress(
    label: str,
    func,
    *,
    expected_seconds: float,
    verbose: bool,
    tick_seconds: float = 0.15,
):
    """Run *func* in a background thread while animating a time-based
    percentage bar on the main thread.

    The bar fills based on elapsed / expected_seconds, capped at 95% until
    the underlying call actually completes — then snaps to 100%. If the call
    finishes quickly, the bar jumps to 100% right away. If it takes longer
    than expected, the bar holds at 95% so it never looks stuck past done.
    """
    holder: dict = {}

    def _target() -> None:
        try:
            holder["value"] = func()
        except Exception as exc:  # noqa: BLE001
            holder["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()

    if not verbose:
        thread.join()
        if "error" in holder:
            raise holder["error"]
        return holder.get("value")

    start = time.monotonic()
    expected = max(0.1, float(expected_seconds))
    _progress_bar_pct(label, 0)
    while thread.is_alive():
        elapsed = time.monotonic() - start
        pct = min(int(elapsed / expected * 100), 95)
        _progress_bar_pct(label, pct)
        thread.join(timeout=tick_seconds)
    _progress_bar_pct(label, 100, done=True)

    if "error" in holder:
        raise holder["error"]
    return holder.get("value")

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
            "artifact_count": len(scanner_findings),
            "top_artifacts": [
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


def _load_signal_groups() -> list[dict]:
    """Load signal_groups.yaml once."""
    import yaml
    rules_dir = Path(__file__).parent / "rules"
    path = rules_dir / "signal_groups.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("signal_groups", [])


_SIGNAL_GROUPS: list[dict] | None = None


def _get_signal_groups() -> list[dict]:
    """Return cached signal groups."""
    global _SIGNAL_GROUPS
    if _SIGNAL_GROUPS is None:
        _SIGNAL_GROUPS = _load_signal_groups()
    return _SIGNAL_GROUPS


def _apply_signal_group_boost(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Match findings against signal groups and emit synthetic boosted findings.

    For each signal group, count how many of its defined signals have matching
    findings. If the count meets the group's min_signals threshold, append a
    synthetic finding with boosted confidence and the union of matched capability
    tags. Original findings are not removed.
    """
    groups = _get_signal_groups()
    if not groups:
        return findings

    # Build lookup structures from existing findings
    filenames_found: dict[str, ScanFinding] = {}
    dep_packages_found: dict[str, ScanFinding] = {}
    for f in findings:
        fname = Path(f.file_path).name
        filenames_found.setdefault(fname, f)
        if f.scanner_name == "DependencyScanner":
            pkg = re.split(r"[=><~!\[;,\s]", f.match_text.strip().lower(), maxsplit=1)[0]
            if pkg:
                dep_packages_found.setdefault(pkg, f)

    synthetic: list[ScanFinding] = []

    for group in groups:
        framework = group.get("framework", "unknown")
        signals = group.get("signals", [])
        boost = group.get("boost", {})
        min_signals = boost.get("min_signals", 2)
        boosted_confidence = boost.get("boosted_confidence", 0.9)
        max_confidence = boost.get("max_confidence", 0.95)

        matched_signals: list[dict] = []
        matched_findings: list[ScanFinding] = []

        for signal in signals:
            sig_type = signal.get("type")
            pattern = signal.get("pattern", "")

            if sig_type == "file" and pattern in filenames_found:
                matched_signals.append(signal)
                matched_findings.append(filenames_found[pattern])
            elif sig_type == "dependency" and pattern.lower() in dep_packages_found:
                matched_signals.append(signal)
                matched_findings.append(dep_packages_found[pattern.lower()])

        if len(matched_signals) >= min_signals:
            # Compute confidence: boosted_confidence for min_signals, max_confidence for more
            if len(matched_signals) > min_signals:
                confidence = max_confidence
            else:
                confidence = boosted_confidence

            # Union of all matched signals' capability tags
            all_tags: set[str] = set()
            for sig in matched_signals:
                for tag in sig.get("capability_tags", []):
                    all_tags.add(tag)

            # Use the first matched finding's file_path as representative
            rep_path = matched_findings[0].file_path if matched_findings else ""
            signal_names = [s.get("pattern", "") for s in matched_signals]

            synthetic.append(ScanFinding(
                scanner_name="SignalGroupDetector",
                category="framework_detection",
                file_path=rep_path,
                line_number=None,
                match_text=f"{framework} framework detected ({len(matched_signals)} corroborating signals: {', '.join(signal_names)})",
                capability_tag=sorted(all_tags)[0] if all_tags else "llm-api",
                confidence=confidence,
            ))

    findings.extend(synthetic)
    return findings


def _load_tool_services() -> dict[str, list[str]]:
    """Load tool_services.yaml once — maps service categories to package names."""
    import yaml
    rules_dir = Path(__file__).parent / "rules"
    path = rules_dir / "tool_services.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


_TOOL_SERVICES: dict[str, list[str]] | None = None
_TOOL_SERVICE_LOOKUP: dict[str, str] | None = None


def _build_service_lookup() -> dict[str, str]:
    """Build a reverse lookup: package_name -> service_category (cached)."""
    global _TOOL_SERVICES, _TOOL_SERVICE_LOOKUP
    if _TOOL_SERVICE_LOOKUP is not None:
        return _TOOL_SERVICE_LOOKUP
    if _TOOL_SERVICES is None:
        _TOOL_SERVICES = _load_tool_services()
    lookup: dict[str, str] = {}
    for category, packages in _TOOL_SERVICES.items():
        for pkg in packages:
            lookup[pkg.lower()] = category
    _TOOL_SERVICE_LOOKUP = lookup
    return lookup


def _extract_tool_services(findings: list[ScanFinding]) -> list:
    """Match DependencyScanner findings against tool_services.yaml to identify external services."""
    from quin_scanner.models import ToolUsage

    lookup = _build_service_lookup()
    services: list[ToolUsage] = []
    seen: set[str] = set()

    for f in findings:
        if f.scanner_name != "DependencyScanner":
            continue
        # Normalise: "faiss-cpu==1.7.4" → "faiss-cpu"
        raw = f.match_text.strip().lower()
        pkg_name = re.split(r"[=><~!\[;,\s]", raw, maxsplit=1)[0]
        if not pkg_name:
            continue
        category = lookup.get(pkg_name)
        if category and pkg_name not in seen:
            seen.add(pkg_name)
            services.append(ToolUsage(
                tool_name=pkg_name,
                tool_type="external_service",
                service_category=category,
                source_file=f.file_path,
                line_number=f.line_number,
            ))
    return services


# Model name patterns for the hallucination filter.
# Only include prefixes specific enough to avoid false positives on tool names.
_MODEL_NAME_PREFIXES = (
    "gpt-", "gpt4",
    "claude-", "claude3", "claude4",
    "dall-e", "dalle",
    "llama-", "llama2", "llama3", "llama4",
    "gemini-", "gemma-",
    "mistral-", "mixtral-",
    "command-r",  # Cohere (not generic "command-")
    "text-embedding-", "text-davinci-",
    "whisper-",
    "stable-diffusion",
    "qwen-", "deepseek-",
)


def _looks_like_model_name(name: str) -> bool:
    """Return True if the name looks like an LLM model identifier."""
    lower = name.lower().strip()
    return any(lower.startswith(p) for p in _MODEL_NAME_PREFIXES)


def _filter_hallucinated_tools(
    tool_usages: list,
    model_usages: list,
    dep_findings: list[ScanFinding],
) -> list:
    """Remove tool_usages that are actually model names or raw dependency package names."""
    model_names = {m.model_name.lower() for m in model_usages}
    # Collect raw dependency package names (normalised)
    dep_names: set[str] = set()
    for f in dep_findings:
        raw = f.match_text.strip().lower()
        pkg = re.split(r"[=><~!\[;,\s]", raw, maxsplit=1)[0]
        if pkg:
            dep_names.add(pkg)

    filtered = []
    for t in tool_usages:
        name_lower = t.tool_name.lower().strip()
        # Skip model names
        if name_lower in model_names:
            continue
        if _looks_like_model_name(name_lower):
            continue
        # Skip raw dependency names unless they're already typed as external_service
        if name_lower in dep_names and t.tool_type != "external_service":
            continue
        filtered.append(t)
    return filtered


# Directories that indicate a file is a skill / playbook / instruction set
_SKILL_DIR_NAMES = frozenset({"skills", "playbooks", "recipes", "instructions", "agents"})


def _classify_tool_usages(
    tool_usages: list,
    mcp_servers: list,
) -> None:
    """Classify tool_usages in-place as skill / mcp_tool based on heuristics.

    - Skill: source_file is a .md file inside a skill-like directory
    - MCP tool: tool_name matches an MCP server name
    - Everything else keeps its existing tool_type
    """
    mcp_names = {s.name.lower() for s in mcp_servers}

    for t in tool_usages:
        # Don't reclassify external_service entries
        if t.tool_type == "external_service":
            continue

        # Skill heuristic: markdown file in a skill-like directory
        if t.source_file and t.source_file.lower().endswith(".md"):
            path_parts = {p.lower() for p in Path(t.source_file).parts[:-1]}
            if path_parts & _SKILL_DIR_NAMES:
                t.tool_type = "skill"
                continue

        # MCP heuristic: tool_name matches an MCP server name
        if t.tool_name.lower() in mcp_names:
            t.tool_type = "mcp_tool"
            continue


def _load_frameworks_lookup() -> dict:
    """Load frameworks_lookup.yaml once."""
    import yaml
    rules_dir = Path(__file__).parent / "rules"
    path = rules_dir / "frameworks_lookup.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


_FRAMEWORKS_LOOKUP: dict | None = None
_FRAMEWORK_TO_PACKAGES: dict[str, list[str]] | None = None


def _detect_framework(findings: list) -> str:
    """Rule-based framework detection from scanner findings.

    Priority: file markers > code pattern imports > package names.
    Code pattern imports rank above packages because internal imports (e.g.
    ``from metagpt.xxx``) reveal what the repo IS, while dependency listings
    may include other frameworks used as optional integrations.
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

    # Pass 2: code pattern imports — internal imports reveal what the repo IS
    # (e.g. a MetaGPT repo has hundreds of `from metagpt.xxx` imports)
    _CODE_PATTERN_FRAMEWORK_MAP = [
        # MetaGPT — self-imports (from metagpt.xxx)
        (re.compile(r"from\s+metagpt\b", re.IGNORECASE), "MetaGPT"),
        (re.compile(r"import\s+metagpt\b", re.IGNORECASE), "MetaGPT"),
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

    # Pass 3: package names from DependencyScanner — iterate packages in YAML priority
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

    return "unknown"


def _get_framework_to_packages() -> dict[str, list[str]]:
    """Build and cache reverse map: framework name -> list of package names."""
    global _FRAMEWORK_TO_PACKAGES, _FRAMEWORKS_LOOKUP
    if _FRAMEWORK_TO_PACKAGES is not None:
        return _FRAMEWORK_TO_PACKAGES
    if _FRAMEWORKS_LOOKUP is None:
        _FRAMEWORKS_LOOKUP = _load_frameworks_lookup()
    reverse: dict[str, list[str]] = {}
    for pkg, fw in _FRAMEWORKS_LOOKUP.get("packages", {}).items():
        reverse.setdefault(fw, []).append(pkg.lower())
    _FRAMEWORK_TO_PACKAGES = reverse
    return _FRAMEWORK_TO_PACKAGES


# Matches version specifiers where the operator indicates a lower bound or exact pin.
# Skips versions after < / <= / != (upper bounds / exclusions).
_VERSION_RE = re.compile(
    r"(?:>=|==|~=|~|\^|=)\s*(\d+(?:\.\d+)*)"
    r"|(?<![<!=])(?:^|[\s,\"])\s*(\d+\.\d+(?:\.\d+)*)"
)


def _parse_version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _extract_framework_version(
    framework: str, findings: list,
) -> str | None:
    """Extract the highest base version of the framework from dependency findings.

    Returns the version string (e.g. "0.80.0") or None if not found.
    """
    if framework == "unknown":
        return None

    pkg_names = _get_framework_to_packages().get(framework, [])
    if not pkg_names:
        return None

    versions: list[str] = []
    for f in findings:
        if f.scanner_name != "DependencyScanner":
            continue
        text = f.match_text.lower().strip()
        for pkg in pkg_names:
            if not (
                text == pkg
                or text.startswith(pkg + "=")
                or text.startswith(pkg + ">")
                or text.startswith(pkg + "<")
                or text.startswith(pkg + "~")
                or text.startswith(pkg + "[")
                or text.startswith(pkg + "^")
                or text.startswith('"' + pkg + '"')
                or text.startswith(pkg + " ")
            ):
                continue
            for m in _VERSION_RE.finditer(f.match_text):
                ver = m.group(1) or m.group(2)
                if ver:
                    versions.append(ver)

    if not versions:
        return None
    return max(versions, key=_parse_version_tuple)


def _dedup_repo_signals(repo_signals: list, agents: list) -> list:
    """Drop repo-level risk signals that are already attributed to a specific agent.

    Dedup key: (lowercased+stripped signal text, threat_id). The synthesis prompt
    instructs the LLM not to duplicate per-agent KRIs at repo level; this is the
    deterministic backstop in case it does.
    """
    agent_keys: set[tuple[str, str]] = set()
    for a in agents:
        for s in getattr(a, "risk_signals", []) or []:
            sig = (getattr(s, "signal", "") or "").strip().lower()
            tid = (getattr(s, "threat_id", "") or "").strip().upper()
            if sig:
                agent_keys.add((sig, tid))

    deduped: list = []
    for s in repo_signals:
        sig = (getattr(s, "signal", "") or "").strip().lower()
        tid = (getattr(s, "threat_id", "") or "").strip().upper()
        if (sig, tid) in agent_keys:
            continue
        deduped.append(s)
    return deduped


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
                label = "artifact" if n == 1 else "artifacts"
                _log(f"  [ ✓ ] {name:<30} {n} {label}")
            _log("")

        # 2b. Deduplicate findings by (file_path, line_number, capability_tag)
        all_findings = self._deduplicate(all_findings)

        # 2c. Apply signal group corroboration boost
        all_findings = _apply_signal_group_boost(all_findings)

        # 3. Compute aggregate metrics
        is_ai = any(f.confidence >= _CONFIDENCE_THRESHOLD for f in all_findings)
        confidence = self._aggregate_confidence(all_findings)
        capability_tags = sorted(
            {f.capability_tag for f in all_findings if f.capability_tag}
        )

        # 4. Direct extraction — no LLM needed
        mcp_servers = _extract_mcp_servers(all_findings)
        infra = _extract_infra(all_findings)
        tool_services = _extract_tool_services(all_findings)

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

        # 6. LLM synthesis (two-pass: classification → synthesis)
        synthesis: SynthesisResult | None = None
        classification: ClassificationResult | None = None
        llm_errors: list[str] = []
        if not config.no_llm:
            summaries = _pre_summarise(all_findings)
            provider = config.provider_factory()
            if verbose:
                _log("\nRunning risk classification (pass 1)...")

            # Pass 1: Classification — system type + relevant threats
            classification_agent = ClassificationAgent(provider)
            try:
                classification = classification_agent.classify(
                    scanner_summaries=summaries,
                    capability_tags=capability_tags,
                    on_progress=lambda msg: _log(f"  {msg}") if verbose else None,
                )
                if verbose:
                    types_str = ", ".join(classification.system_types)
                    n_threats = len(classification.relevant_threats)
                    _log(f"  system types: {types_str}  |  {n_threats} threat{'s' if n_threats != 1 else ''} relevant")
            except Exception as e:
                err = f"ClassificationAgent: {type(e).__name__}: {e}"
                llm_errors.append(err)
                if verbose:
                    _log(f"  [!] Classification failed: {e} — continuing without threat filtering")

            # Pass 2: Synthesis — full report with filtered KRIs
            agent = SynthesisAgent(provider)
            if verbose:
                _log("\nRunning synthesis analysis (pass 2)...")

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

            # Build external services evidence for the synthesis prompt
            external_services = [
                {
                    "name": t.tool_name,
                    "category": t.service_category,
                    "source_file": t.source_file,
                    "line": t.line_number,
                }
                for t in tool_services
            ][:_EVIDENCE_CAP]

            evidence_facts = EvidenceFacts(
                system_types=frozenset(classification.system_types if classification else []),
                capability_tags=frozenset(capability_tags),
                mcp_servers_count=len(mcp_servers),
                agent_instances_count=len(agent_instances),
                tool_definitions_count=len(tool_definitions),
                external_service_categories=frozenset(
                    s["category"] for s in external_services if s.get("category")
                ),
                cloud_llm_count=sum(
                    1 for m in model_usages
                    if (m.provider or "").lower() in CLOUD_LLM_PROVIDERS
                ),
            )

            try:
                synthesis = agent.synthesize(
                    scanner_summaries=summaries,
                    model_usages=model_usages,
                    capability_tags=capability_tags,
                    on_progress=_synthesis_progress if verbose else None,
                    framework_candidate=framework_candidate,
                    agent_instances=agent_instances or None,
                    tool_definitions=tool_definitions or None,
                    external_services=external_services or None,
                    classification=classification,
                    evidence_facts=evidence_facts,
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
                    n_risks = len(synthesis.risk_signals)
                    agent_risks = sum(len(a.risk_signals) for a in synthesis.agents)
                    _log(f"  framework: {synthesis.framework}  |  {n_agents} agent{'s' if n_agents != 1 else ''} identified")
                    _log(f"  risks: {n_risks} system-wide, {agent_risks} agent-specific")
            except Exception as e:
                err = f"SynthesisAgent: {type(e).__name__}: {e}"
                llm_errors.append(err)
                if verbose:
                    _log(f"\n  [!] LLM synthesis failed: {e}")
                    _log("      Run with --no-llm to skip synthesis, or check your --llm-provider / API key.")

        scan_duration = round(time.monotonic() - scan_start, 3)

        if verbose:
            status = "AI application detected" if is_ai else "No AI application detected"
            _log(f"\n{status}  |  confidence: {confidence}  |  {len(all_findings)} artifacts  |  {scan_duration}s\n")

        metadata: dict = {
            "scan_duration_seconds": scan_duration,
            "file_count": len(file_index.all_files()),
            "artifact_count": len(all_findings),
            "artifacts_by_scanner": findings_by_scanner,
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

        # Rule 1b: append framework version from dependency manifests
        fw_version = _extract_framework_version(pp_framework, all_findings)
        if fw_version:
            pp_framework = f"{pp_framework} {fw_version}"

        # Rule 1c: check detected framework+version against OSV.dev and
        # (optionally) an LLM web search for CVEs / advisories. Failures
        # degrade gracefully (warning only).
        pp_vulnerabilities: list[Vulnerability] = []
        if config.vuln_check_enabled and fw_version:
            if verbose:
                has_web = bool(config.vuln_search_provider)
                sources = "OSV.dev + web search" if has_web else "OSV.dev"
                _log(f"\nChecking vulnerabilities ({sources}) for {pp_framework}...")
            # Rough expected wall-clock: OSV is typically fast (<1s); web
            # search usually 2–4s. Use half the configured timeouts so the
            # bar fills at a realistic pace for typical responses.
            expected_seconds = config.vuln_osv_timeout / 2
            if config.vuln_search_provider:
                expected_seconds += config.vuln_web_timeout / 2
            try:
                pp_vulnerabilities = _run_with_animated_progress(
                    "Vuln check ",
                    lambda: VulnChecker(config).check(pp_framework),
                    expected_seconds=expected_seconds,
                    verbose=verbose,
                ) or []
                if verbose:
                    n = len(pp_vulnerabilities)
                    _log(f"  {n} vulnerabilit{'y' if n == 1 else 'ies'} found")
            except Exception as _exc:  # noqa: BLE001
                _log(f"vuln check failed for {pp_framework}: {_exc}")

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

        # Rule 3a: classify tool_usages as skill / mcp_tool / tool_definition
        _classify_tool_usages(pp_tool_usages, mcp_servers)

        # Rule 3a-ii: cross-check AgentProfile tools[] / skills[] against classification
        _classified_skills = {t.tool_name.lower() for t in pp_tool_usages if t.tool_type == "skill"}
        _classified_tools = {t.tool_name.lower() for t in pp_tool_usages if t.tool_type in ("tool_definition", "external_service")}
        for _agent in pp_agents:
            _new_tools: list[str] = []
            for t in _agent.tools:
                if t.lower() in _classified_skills:
                    if t not in _agent.skills:
                        _agent.skills.append(t)
                else:
                    _new_tools.append(t)
            _agent.tools = _new_tools
            _new_skills: list[str] = []
            for s in _agent.skills:
                if s.lower() in _classified_tools:
                    if s not in _agent.tools:
                        _agent.tools.append(s)
                else:
                    _new_skills.append(s)
            _agent.skills = _new_skills

        # Rule 3b: filter hallucinated tools — remove model names and raw deps
        dep_findings = [f for f in all_findings if f.scanner_name == "DependencyScanner"]
        pp_tool_usages = _filter_hallucinated_tools(pp_tool_usages, model_usages, dep_findings)

        # Rule 3b-ii: filter agent-level tools[] for the same hallucinated names
        model_names_lower = {m.model_name.lower() for m in model_usages}
        dep_names_lower: set[str] = set()
        for _f in dep_findings:
            _raw = _f.match_text.strip().lower()
            _pkg = re.split(r"[=><~!\[;,\s]", _raw, maxsplit=1)[0]
            if _pkg:
                dep_names_lower.add(_pkg)
        for _agent in pp_agents:
            _agent.tools = [
                t for t in _agent.tools
                if t.lower() not in model_names_lower
                and not _looks_like_model_name(t)
                and t.lower() not in dep_names_lower
            ]

        # Rule 3c: merge external service tools (from tool_services.yaml)
        pp_tool_usages.extend(tool_services)

        # Rule 4: deduplicate tool_usages
        # First pass: by tool_name — prefer external_service over tool_definition
        # (avoids duplicates when synthesis returns a tool that's also a service dep)
        _best_by_name: dict[str, object] = {}
        for _t in pp_tool_usages:
            _name_key = _t.tool_name.lower()
            _existing = _best_by_name.get(_name_key)
            if _existing is None:
                _best_by_name[_name_key] = _t
            elif _t.tool_type == "external_service" and _existing.tool_type != "external_service":
                _best_by_name[_name_key] = _t
        # Second pass: by (name, source_file, line_number) for remaining dups
        _seen_tools: set[tuple] = set()
        _deduped_tools: list = []
        for _t in _best_by_name.values():
            _key = (_t.tool_name.lower(), _t.source_file, _t.line_number)
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

        # Repo-level risk signals from synthesis, with dedup against per-agent signals.
        pp_risk_signals = _dedup_repo_signals(
            list(synthesis.risk_signals) if synthesis else [],
            pp_agents,
        )

        # Promote critical / high vulnerabilities into the repo-level risk signals
        # so they surface in the main risk narrative alongside other findings.
        for _v in pp_vulnerabilities:
            if _v.severity in ("critical", "high"):
                _cve = _v.cve_id or "CVE-unknown"
                _sum = (_v.summary or "")[:160]
                pp_risk_signals.append(RiskIndicator(
                    signal=f"{_v.severity.upper()} vulnerability {_cve}: {_sum}",
                    recommended_controls=["C002: Patch & Dependency Hygiene"],
                    threat_id="T003",
                ))

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
            risk_signals=pp_risk_signals,
            mcp_servers=mcp_servers,
            infra=infra,
            vulnerabilities=pp_vulnerabilities,
            artifacts=all_findings,
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
