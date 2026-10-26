from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from dotenv import find_dotenv, load_dotenv

from quin_scanner import __version__
from quin_scanner.config import ConfigError, ScannerConfig
from quin_scanner.models import ScanReport
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor, RepoAccessorFactory
from quin_scanner.report import ReportGenerator
from quin_scanner.schema import REPORT_SCHEMA_VERSION
from quin_scanner.scanners.skills.baseline import BaselineError

load_dotenv(find_dotenv(usecwd=True))


def _output_filename(target: str, fmt: str) -> str:
    """Build an output filename: <repo-name>_<YYYYMMDD_HHMMSS>.<fmt>"""
    # The last path component of the target, whichever separator it uses ("/" in URLs and POSIX paths,
    # "\\" in Windows paths), reduced to characters that are valid in a file name on every OS.
    clean = re.sub(r"[\\/]+$", "", target).removesuffix(".git")
    name = re.split(r"[\\/]", clean)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "report"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{name}_{ts}.{fmt}"

def _flags_used(
    cfg: ScannerConfig,
    *,
    config: str | None = None,
    branch: str | None = None,
    min_confidence: float = 0.0,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    vuln_search_provider: str | None = None,
    openai_compatible_url: str | None = None,
) -> list[str]:
    """CLI flags in effect for this scan, for display in the report.

    Secrets (API keys, tokens) are never listed, and the value of
    --openai-compatible-url is omitted because URLs can embed credentials.
    """
    flags: list[str] = []
    if config:
        flags.append(f"--config {Path(config).name}")
    if cfg.no_llm:
        flags.append("--no-llm")
    else:
        if llm_provider:
            flags.append(f"--llm-provider {llm_provider}")
        if llm_model:
            flags.append(f"--llm-model {llm_model}")
    if openai_compatible_url:
        flags.append("--openai-compatible-url")
    if not cfg.vuln_check_enabled:
        flags.append("--no-vuln-check")
    elif vuln_search_provider:
        flags.append(f"--vuln-search-provider {vuln_search_provider}")
    if cfg.detect_aegis:
        flags.append("--detect-aegis")
    if cfg.skills_baseline_path:
        flags.append(f"--skills-baseline {Path(cfg.skills_baseline_path).name}")
    if branch and branch != "main":
        flags.append(f"--branch {branch}")
    if min_confidence > 0.0:
        flags.append(f"--min-confidence {min_confidence:g}")
    return flags


def _record_flags(report, flags: list[str]) -> None:
    report.metadata["scan_options"] = {"flags": flags}


def skill_summary_lines(report) -> list[str]:
    """Human-readable per-skill verdict lines, highest risk first. Empty when no skills.

    The MCP tool-definition and agent-instruction-file pseudo-records are not skills:
    each gets its own trailing ``<name>: <verdict> <score>`` line.
    A skills baseline, when one was applied, adds a final ``Baseline: ...`` line.
    """
    from quin_scanner.scanners.skills.baseline import baseline_summary
    from quin_scanner.scanners.skills.discovery import is_pseudo_record

    skills = [a for a in report.skills if not is_pseudo_record(a.record)]
    pseudo = [a for a in report.skills if is_pseudo_record(a.record)]
    lines: list[str] = []
    if skills:
        lines.append(f"Skills: {len(skills)} found")
        for a in sorted(skills, key=lambda s: -s.risk_score):
            counts = ", ".join(f"{n} {sev}" for sev, n in a.finding_counts.items()) or "no findings"
            lines.append(f"  {a.record.name:<30} {a.verdict:<10} {a.risk_score:>3}  ({counts})")
    for a in pseudo:
        lines.append(f"{a.record.name}: {a.verdict} {a.risk_score}")
    if report.metadata.get("skills_baseline"):
        lines.append(baseline_summary(report.metadata["skills_baseline"]))
    return lines


def _open_target(target: str, **kwargs):
    """RepoAccessorFactory.create, but a local path that is missing or not a directory is an error.

    The factory routes anything that starts with "/" or "." to a local accessor, so a typo in a path
    used to scan nothing and succeed with an empty report.
    """
    accessor = RepoAccessorFactory.create(target, **kwargs)
    if isinstance(accessor, LocalRepoAccessor):
        if not accessor.repo_path.exists():
            raise ValueError(f"Local path does not exist: {target!r}")
        if not accessor.repo_path.is_dir():
            raise ValueError(f"Local path is not a directory: {target!r}")
    return accessor


def _build_config(
    *,
    config: str | None,
    llm_provider: str | None,
    llm_model: str | None,
    llm_api_key: str | None,
    output_format: str | None,
    no_llm: bool,
    github_token: str | None,
    openai_compatible_url: str | None,
) -> ScannerConfig:
    """ScannerConfig from a config file (with CLI overrides) or from CLI options alone."""
    if config:
        cfg = ScannerConfig.load_from_file(config)
        if no_llm:
            cfg.no_llm = True
        if github_token:
            cfg.github_token = github_token
        if openai_compatible_url:
            cfg.openai_compatible_url = openai_compatible_url
        return cfg
    return ScannerConfig.load_from_args(
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
        output_format=output_format,
        no_llm=no_llm,
        github_token=github_token,
        openai_compatible_url=openai_compatible_url,
    )


def _warn_if_no_llm_key(cfg: ScannerConfig) -> None:
    """Early check: warn if LLM analysis is enabled but no API key is available."""
    if not cfg.no_llm and not cfg.llm_api_key and cfg.llm_provider != "ollama" and not cfg.openai_compatible_url:
        click.echo(
            f"Warning: No API key found for provider '{cfg.llm_provider}'. "
            "LLM analysis will likely fail.\n"
            "  Hint: set the appropriate env var in .env, or run with --no-llm for static-only scanning.",
            err=True,
        )


_OUTPUT_CHOICES = click.Choice(["json", "yaml", "html", "sarif"])


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="quin-scanner", message=f"%(prog)s, version %(version)s (report schema {REPORT_SCHEMA_VERSION})")
def cli() -> None:
    """Quin Scanner — detect GenAI and Agentic AI applications in repositories.

    Scans local directories, GitHub repos, or entire GitHub organizations to
    identify LLM usage, AI agent frameworks, model configurations, prompt
    templates, and tool definitions.

    \b
    Targets accepted by the scan command:
      - Local path:          /path/to/repo
      - GitHub URL:          https://github.com/owner/repo
      - GitHub shorthand:    owner/repo
      - Azure DevOps URL:    https://dev.azure.com/org/project/_git/repo

    \b
    Examples:
      quin-scanner scan ./my-project
      quin-scanner scan owner/repo --no-llm
      quin-scanner scan https://github.com/owner/repo -o yaml -d reports/
      quin-scanner scan https://dev.azure.com/org/project/_git/repo --azure-token $AZURE_DEVOPS_TOKEN
      quin-scanner scan-batch targets.txt -d reports/
      quin-scanner scan-org my-org --skip-archived --skip-forks
      quin-scanner skills scan ./my-skill.zip
      quin-scanner skills baseline ./skills -o skills-baseline.yaml

    \b
    Environment variables:
      GITHUB_TOKEN          GitHub personal access token
      AZURE_DEVOPS_TOKEN    Azure DevOps personal access token
      OPENAI_API_KEY        OpenAI API key (for LLM analysis)
      ANTHROPIC_API_KEY     Anthropic API key (for LLM analysis)
      GOOGLE_API_KEY        Google GenAI API key (for LLM analysis)
    """


@cli.command()
@click.argument("target")
@click.option("--output", "-o", default="html", type=_OUTPUT_CHOICES, show_default=True, help="Output format")
@click.option("--output-file", "-f", default=None, help="Write output to a specific file")
@click.option("--output-dir", "-d", default="./report", show_default=True, help="Write output to this directory (auto-names the file)")
@click.option(
    "--llm-provider", default=None,
    help="LLM provider for agent intent analysis (openai|anthropic|google|ollama|openai-compatible)",
)
@click.option("--llm-model", default=None, help="Override the default model for the provider")
@click.option("--llm-api-key", default=None, help="API key (overrides env var)")
@click.option("--config", "-c", default=None, help="Path to a scanner-config.yaml file")
@click.option("--branch", default="main", show_default=True, help="Branch to scan (for GitHub targets)")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM analysis entirely (faster, no API key needed)")
@click.option(
    "--min-confidence", default=0.0, show_default=True, type=float,
    help="Exclude artifacts below this confidence threshold (0.0–1.0)",
)
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN", help="GitHub PAT (overrides GITHUB_TOKEN env var)")
@click.option("--azure-token", default=None, envvar="AZURE_DEVOPS_TOKEN", help="Azure DevOps PAT (overrides AZURE_DEVOPS_TOKEN env var)")
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, etc.)")
@click.option("--no-vuln-check", is_flag=True, default=False, help="Skip vulnerability lookup (OSV + web search)")
@click.option(
    "--vuln-search-provider", default=None, envvar="VULN_SEARCH_PROVIDER",
    type=click.Choice(["perplexity", "gemini", "openai", "anthropic", "none"]),
    help="LLM provider for web-based vulnerability search (reuses that provider's API key env var)",
)
@click.option(
    "--detect-aegis", is_flag=True, default=False,
    help="Detect Aegis SDK usage and classify the agent as governed (off by default)",
)
@click.option(
    "--skills-baseline", default=None, metavar="FILE",
    help="Suppress skill findings listed in this baseline (from 'quin-scanner skills baseline')",
)
def scan(
    target: str,
    output: str,
    output_file: str | None,
    output_dir: str,
    llm_provider: str | None,
    llm_model: str | None,
    llm_api_key: str | None,
    config: str | None,
    branch: str,
    no_llm: bool,
    min_confidence: float,
    github_token: str | None,
    azure_token: str | None,
    openai_compatible_url: str | None,
    no_vuln_check: bool,
    vuln_search_provider: str | None,
    detect_aegis: bool,
    skills_baseline: str | None,
) -> None:
    """Scan a single repository for GenAI/Agentic AI indicators.

    TARGET can be a local path, a GitHub URL, or owner/repo shorthand.

    \b
    Exit codes:
      0  the scan completed (findings do not change the exit code)
      1  invalid target, or the scan failed
      2  invalid --skills-baseline, invalid config file, or a command-line usage error

    \b
    Examples:
      quin-scanner scan ./my-project
      quin-scanner scan owner/repo --no-llm -o yaml
      quin-scanner scan owner/repo --min-confidence 0.7 -d reports/
      quin-scanner scan ./my-agent --detect-aegis --no-llm
      quin-scanner scan ./my-agent --skills-baseline skills-baseline.yaml
      quin-scanner scan owner/repo --llm-provider anthropic --llm-model claude-sonnet-4-20250514
    """
    try:
        cfg = _build_config(
            config=config, llm_provider=llm_provider, llm_model=llm_model, llm_api_key=llm_api_key,
            output_format=output, no_llm=no_llm, github_token=github_token,
            openai_compatible_url=openai_compatible_url,
        )
    except ConfigError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    # CLI overrides for vulnerability checking
    if detect_aegis:
        cfg.detect_aegis = True
    if skills_baseline:
        cfg.skills_baseline_path = skills_baseline
    if no_vuln_check:
        cfg.vuln_check_enabled = False
    if vuln_search_provider:
        cfg.vuln_search_provider = None if vuln_search_provider == "none" else vuln_search_provider

    _warn_if_no_llm_key(cfg)

    # Create accessor
    try:
        accessor = _open_target(
            target, github_token=cfg.github_token, branch=branch, azure_token=azure_token
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Run scan
    try:
        report = ScanOrchestrator().run(accessor, cfg, verbose=sys.stderr.isatty())
        _record_flags(report, _flags_used(
            cfg, config=config, branch=branch, min_confidence=min_confidence,
            llm_provider=llm_provider, llm_model=llm_model,
            vuln_search_provider=vuln_search_provider, openai_compatible_url=openai_compatible_url,
        ))

        # Apply confidence filter if requested
        if min_confidence > 0.0:
            report.artifacts = [f for f in report.artifacts if f.confidence >= min_confidence]

        # Output
        rendered = ReportGenerator.to_string(report, output)
        if output_file:
            ReportGenerator.write_to_file(report, output_file, output)
            click.echo(f"Report written to {output_file}", err=True)
        elif output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            out_path = Path(output_dir) / _output_filename(target, output)
            ReportGenerator.write_to_file(report, str(out_path), output)
            click.echo(f"Report written to {out_path}", err=True)
        else:
            click.echo(rendered)

        for line in skill_summary_lines(report):
            click.echo(line, err=True)
    except BaselineError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(1)
    finally:
        accessor.cleanup()


@cli.command("scan-batch")
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--output", "-o", default="html", type=_OUTPUT_CHOICES, show_default=True, help="Output format")
@click.option("--output-dir", "-d", default="./report", show_default=True, help="Directory for per-repo output files")
@click.option(
    "--llm-provider", default=None,
    help="LLM provider for agent intent analysis (openai|anthropic|google|ollama|openai-compatible)",
)
@click.option("--llm-model", default=None, help="Override the default model for the provider")
@click.option("--llm-api-key", default=None, help="API key (overrides env var)")
@click.option("--config", "-c", default=None, help="Path to a scanner-config.yaml file")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM analysis entirely (faster, no API key needed)")
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN", help="GitHub PAT (overrides GITHUB_TOKEN env var)")
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, etc.)")
@click.option("--no-vuln-check", is_flag=True, default=False, help="Skip vulnerability lookup (OSV + web search)")
@click.option(
    "--vuln-search-provider", default=None, envvar="VULN_SEARCH_PROVIDER",
    type=click.Choice(["perplexity", "gemini", "openai", "anthropic", "none"]),
    help="LLM provider for web-based vulnerability search",
)
@click.option(
    "--detect-aegis", is_flag=True, default=False,
    help="Detect Aegis SDK usage and classify the agent as governed (off by default)",
)
def scan_batch(
    targets_file: str,
    output: str,
    output_dir: str,
    llm_provider: str | None,
    llm_model: str | None,
    llm_api_key: str | None,
    config: str | None,
    no_llm: bool,
    github_token: str | None,
    openai_compatible_url: str | None,
    no_vuln_check: bool,
    vuln_search_provider: str | None,
    detect_aegis: bool,
) -> None:
    """Scan multiple repositories listed in a file.

    TARGETS_FILE should contain one target per line (local paths, GitHub URLs,
    or owner/repo shorthand). Lines starting with # are ignored.

    \b
    Exit codes:
      0  every target was scanned
      1  at least one target failed (reports for the others are still written)
      2  invalid config file, or usage error such as a missing targets file

    \b
    Examples:
      quin-scanner scan-batch targets.txt
      quin-scanner scan-batch targets.txt -d reports/ -o yaml
      quin-scanner scan-batch targets.txt --no-llm
    """
    targets = [
        line.strip()
        for line in Path(targets_file).read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    try:
        if config:
            base_cfg = ScannerConfig.load_from_file(config)
            if no_llm:
                base_cfg.no_llm = True
        else:
            base_cfg = ScannerConfig.load_from_args(
                llm_provider=llm_provider,
                llm_model=llm_model,
                llm_api_key=llm_api_key,
                output_format=output,
                no_llm=no_llm,
                github_token=github_token,
                openai_compatible_url=openai_compatible_url,
            )
    except ConfigError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    if detect_aegis:
        base_cfg.detect_aegis = True
    if no_vuln_check:
        base_cfg.vuln_check_enabled = False
    if vuln_search_provider:
        base_cfg.vuln_search_provider = None if vuln_search_provider == "none" else vuln_search_provider

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    failed: list[str] = []
    for target in targets:
        click.echo(f"Scanning {target} ...", err=True)
        accessor = None
        try:
            accessor = _open_target(target, github_token=base_cfg.github_token)
            report = ScanOrchestrator().run(accessor, base_cfg, verbose=sys.stderr.isatty())
            _record_flags(report, _flags_used(
                base_cfg, config=config, llm_provider=llm_provider, llm_model=llm_model,
                vuln_search_provider=vuln_search_provider, openai_compatible_url=openai_compatible_url,
            ))
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
            failed.append(target)
            continue
        finally:
            if accessor:
                accessor.cleanup()

        out_path = Path(output_dir) / _output_filename(target, output)
        ReportGenerator.write_to_file(report, str(out_path), output)
        click.echo(f"  -> {out_path}", err=True)

    if failed:
        click.echo(f"{len(failed)} of {len(targets)} targets failed: {', '.join(failed)}", err=True)
        sys.exit(1)


@cli.command("scan-org")
@click.argument("org_name")
@click.option("--output", "-o", type=_OUTPUT_CHOICES, default="html", show_default=True, help="Output format")
@click.option("--output-dir", default="./report", type=click.Path(), show_default=True, help="Directory for per-repo output files")
@click.option("--github-token", envvar="GITHUB_TOKEN", default=None, help="GitHub PAT (overrides GITHUB_TOKEN env var)")
@click.option("--skip-archived", is_flag=True, default=False, help="Skip archived repositories")
@click.option("--skip-forks", is_flag=True, default=False, help="Skip forked repositories")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM analysis entirely (faster, no API key needed)")
@click.option("--config", "-c", type=click.Path(exists=True), default=None, help="Path to a scanner-config.yaml file")
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, etc.)")
@click.option("--no-vuln-check", is_flag=True, default=False, help="Skip vulnerability lookup (OSV + web search)")
@click.option(
    "--vuln-search-provider", default=None, envvar="VULN_SEARCH_PROVIDER",
    type=click.Choice(["perplexity", "gemini", "openai", "anthropic", "none"]),
    help="LLM provider for web-based vulnerability search",
)
@click.option(
    "--detect-aegis", is_flag=True, default=False,
    help="Detect Aegis SDK usage and classify the agent as governed (off by default)",
)
@click.pass_context
def scan_org(
    ctx: click.Context,
    org_name: str,
    output: str,
    output_dir: str,
    github_token: str | None,
    skip_archived: bool,
    skip_forks: bool,
    no_llm: bool,
    config: str | None,
    openai_compatible_url: str | None,
    no_vuln_check: bool,
    vuln_search_provider: str | None,
    detect_aegis: bool,
) -> None:
    """Scan all repositories in a GitHub organization or user account.

    ORG_NAME is a GitHub organization or user account name (auto-detected).
    Discovers all repos via the GitHub API, then scans each one.
    Requires a GITHUB_TOKEN with org/user read access.

    \b
    Exit codes:
      0  every repository was scanned
      1  the repository list could not be fetched, or at least one repository failed
      2  invalid config file, or usage error

    \b
    Examples:
      quin-scanner scan-org my-org --skip-archived --skip-forks
      quin-scanner scan-org my-org -d reports/ -o yaml --no-llm
      quin-scanner scan-org my-username --github-token $GITHUB_TOKEN
    """
    from quin_scanner.github_client import GitHubClient

    # Validate the config before any network call.
    try:
        if config:
            base_cfg = ScannerConfig.load_from_file(config)
            if no_llm:
                base_cfg.no_llm = True
        else:
            base_cfg = ScannerConfig.load_from_args(
                no_llm=no_llm,
                github_token=github_token,
                openai_compatible_url=openai_compatible_url,
            )
    except ConfigError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    client = GitHubClient(token=github_token)

    verbose = sys.stderr.isatty()

    def _listing_progress(page: int, total: int) -> None:
        if verbose:
            sys.stderr.write(f"\r  Listing repos … page {page} ({total} repos found)")
            sys.stderr.flush()

    click.echo(f"Listing repos for: {org_name} …", err=True)
    try:
        repos = client.list_repos_for(
            org_name,
            skip_archived=skip_archived,
            skip_forks=skip_forks,
            on_progress=_listing_progress if verbose else None,
        )
    except Exception as e:
        click.echo(f"Error listing repos: {e}", err=True)
        sys.exit(1)

    if verbose:
        sys.stderr.write("\n")
        sys.stderr.flush()
    click.echo(f"Found {len(repos)} repos to scan.", err=True)

    if detect_aegis:
        base_cfg.detect_aegis = True
    if no_vuln_check:
        base_cfg.vuln_check_enabled = False
    if vuln_search_provider:
        base_cfg.vuln_search_provider = None if vuln_search_provider == "none" else vuln_search_provider

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    reports = []
    failed: list[str] = []
    for repo in repos:
        click.echo(f"Scanning {repo.full_name} ...", err=True)
        accessor = None
        try:
            accessor = RepoAccessorFactory.create(
                repo.clone_url,
                github_token=github_token,
                branch=repo.default_branch,
            )
            report = ScanOrchestrator().run(accessor, base_cfg, verbose=sys.stderr.isatty())
            _record_flags(report, _flags_used(
                base_cfg, config=config, vuln_search_provider=vuln_search_provider,
                openai_compatible_url=openai_compatible_url,
            ))
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
            failed.append(repo.full_name)
            continue
        finally:
            if accessor:
                accessor.cleanup()

        out_path = Path(output_dir) / _output_filename(repo.full_name, output)
        ReportGenerator.write_to_file(report, str(out_path), output)
        click.echo(f"  -> {out_path}", err=True)
        reports.append({"repo": repo.full_name, "is_ai_application": report.is_ai_application, "confidence": report.confidence})

    import json
    click.echo(json.dumps(reports, indent=2))

    if failed:
        click.echo(f"{len(failed)} of {len(repos)} repositories failed: {', '.join(failed)}", err=True)
        sys.exit(1)


# ── quin-scanner skills ──────────────────────────────────────────────────────

_VERDICT_RANK = {"SAFE": 0, "CAUTION": 1, "HIGH_RISK": 2}
_FAIL_ON = {"caution": 1, "high_risk": 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_EVIDENCE_WIDTH = 160


def _skills_report(target: str, result, baseline_path: str | None = None) -> ScanReport:
    """Minimal ScanReport holding only the skills results (for the summary lines and SARIF)."""
    from quin_scanner.scanners.skills.baseline import baseline_metadata
    from quin_scanner.scanners.skills.promotion import promote_skill_findings

    metadata: dict = {"skills_notes": result.notes[:50]} if result.notes else {}
    if baseline_path and result.baseline is not None:
        metadata["skills_baseline"] = baseline_metadata(baseline_path, result.baseline)
    return ScanReport(
        repo_path=target,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        is_ai_application=False,
        confidence=0.0,
        risk_signals=promote_skill_findings(result.assessments),
        coverage=result.coverage,
        metadata=metadata,
        skills=list(result.assessments),
    )


def _skills_terminal(report, notes: list[str]) -> str:
    """Per-skill verdict table, then findings grouped per skill (highest risk first)."""
    lines = skill_summary_lines(report)
    if not report.skills:
        lines.insert(0, "No skills found.")
    with_findings = [a for a in sorted(report.skills, key=lambda s: -s.risk_score) if a.findings]
    if with_findings:
        lines += ["", "Findings"]
    for a in with_findings:
        lines.append(f"{a.record.name} ({a.verdict} {a.risk_score})")
        for f in sorted(a.findings, key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.file_path, f.line_number or 0)):
            loc = f"{f.file_path}:{f.line_number}" if f.line_number is not None else f.file_path
            lines.append(f"  {f.severity.upper():<9} {f.rule_id:<12} {f.title}")
            lines.append(f"  {'':<9} {loc}")
            evidence = " ".join(f.evidence.split())
            if evidence:
                if len(evidence) > _EVIDENCE_WIDTH:
                    evidence = evidence[: _EVIDENCE_WIDTH - 3] + "..."
                lines.append(f"  {'':<9} evidence: {evidence}")
            if f.llm_verdict != "none":
                lines.append(f"  {'':<9} LLM {f.llm_verdict}: {f.explanation}".rstrip())
    if notes:
        lines += ["", "Notes"] + [f"  {n}" for n in notes]
    return "\n".join(lines)


def _skills_json(target: str, report, notes: list[str]) -> str:
    import json

    envelope = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": target,
        "scanned_at": report.scan_timestamp,
        "skills": [s.to_dict() for s in report.skills],
        "notes": notes,
        "coverage": report.coverage,
    }
    if "skills_baseline" in report.metadata:
        envelope["metadata"] = {"skills_baseline": report.metadata["skills_baseline"]}
    return json.dumps(envelope, indent=2, default=str)


@cli.group()
def skills() -> None:
    """Agent Skills security commands (pre-install checks)."""


@skills.command("scan")
@click.argument("target")
@click.option(
    "--output", "-o", default="terminal", type=click.Choice(["terminal", "json", "sarif"]),
    show_default=True, help="Output format",
)
@click.option("--output-file", "-f", default=None, help="Write output to a file instead of stdout")
@click.option(
    "--fail-on", default="high_risk", type=click.Choice(["caution", "high_risk"]), show_default=True,
    help="Exit 1 when any skill's verdict is at or above this level",
)
@click.option(
    "--llm-provider", default=None,
    help="Enable LLM review with this provider (openai|anthropic|google|ollama|openai-compatible)",
)
@click.option("--llm-model", default=None, help="Override the default model for the provider")
@click.option("--llm-api-key", default=None, help="API key (overrides env var)")
@click.option("--config", "-c", default=None, help="Path to a scanner-config.yaml file")
@click.option("--branch", default="main", show_default=True, help="Branch to scan (for repo URL targets)")
@click.option("--no-llm", is_flag=True, default=False, help="Never run the LLM review")
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN", help="GitHub PAT (overrides GITHUB_TOKEN env var)")
@click.option("--azure-token", default=None, envvar="AZURE_DEVOPS_TOKEN", help="Azure DevOps PAT (overrides AZURE_DEVOPS_TOKEN env var)")
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, etc.)")
@click.option("--no-vuln-check", is_flag=True, default=False, help="Skip OSV lookups for pinned skill dependencies")
@click.option(
    "--baseline", "baseline_file", default=None, metavar="FILE",
    help="Suppress findings listed in this baseline file (from 'quin-scanner skills baseline')",
)
def skills_scan(
    target: str,
    output: str,
    output_file: str | None,
    fail_on: str,
    llm_provider: str | None,
    llm_model: str | None,
    llm_api_key: str | None,
    config: str | None,
    branch: str,
    no_llm: bool,
    github_token: str | None,
    azure_token: str | None,
    openai_compatible_url: str | None,
    no_vuln_check: bool,
    baseline_file: str | None,
) -> None:
    """Scan Agent Skills on their own, e.g. before installing them.

    TARGET is a skill directory, a .zip file, a GitHub/Azure DevOps URL or owner/repo.
    Static by default; passing an LLM option (--llm-provider, --llm-model, --llm-api-key,
    --openai-compatible-url or --config) adds the LLM review. Nothing in the target is executed.

    \b
    Exit codes:
      0  every skill is below --fail-on (default: SAFE or CAUTION)
      1  at least one skill is at or above --fail-on (default: HIGH_RISK)
      2  error (bad target, unreadable or unsafe zip, bad config, missing or malformed baseline)

    --baseline suppresses findings accepted earlier with 'skills baseline', so only new
    findings are reported, scored and counted towards the exit code.

    \b
    Examples:
      quin-scanner skills scan ./my-skill
      quin-scanner skills scan downloaded-skill.zip --fail-on caution
      quin-scanner skills scan ./skills --baseline skills-baseline.yaml
      quin-scanner skills scan https://github.com/owner/repo/tree/main/skills/pdf -o sarif -f skills.sarif
    """
    from quin_scanner.scanners.skills.baseline import load_baseline
    from quin_scanner.scanners.skills.runner import open_skill_target, run_skill_scan

    try:
        baseline = load_baseline(baseline_file) if baseline_file else None
        cfg = _build_config(
            config=config, llm_provider=llm_provider, llm_model=llm_model, llm_api_key=llm_api_key,
            output_format=None, no_llm=no_llm, github_token=github_token,
            openai_compatible_url=openai_compatible_url,
        )
        if no_vuln_check:
            cfg.vuln_check_enabled = False
        if not any((llm_provider, llm_model, llm_api_key, openai_compatible_url, config)):
            cfg.no_llm = True
        _warn_if_no_llm_key(cfg)

        with open_skill_target(target, github_token=cfg.github_token, azure_token=azure_token, branch=branch) as accessor:
            result = run_skill_scan(accessor, cfg, baseline=baseline)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    report = _skills_report(target, result, baseline_file)
    if output == "json":
        rendered = _skills_json(target, report, result.notes)
    elif output == "sarif":
        rendered = ReportGenerator.to_sarif(report)
    else:
        rendered = _skills_terminal(report, result.notes)

    if output_file:
        try:
            Path(output_file).write_text(rendered + "\n", encoding="utf-8")
        except OSError as e:
            click.echo(f"Error: cannot write {output_file}: {e}", err=True)
            sys.exit(2)
        click.echo(f"Report written to {output_file}", err=True)
    else:
        click.echo(rendered)
    if output != "terminal" and "skills_baseline" in report.metadata:
        from quin_scanner.scanners.skills.baseline import baseline_summary

        click.echo(baseline_summary(report.metadata["skills_baseline"]), err=True)

    threshold = _FAIL_ON[fail_on]
    sys.exit(1 if any(_VERDICT_RANK.get(a.verdict, 0) >= threshold for a in result.assessments) else 0)


@skills.command("baseline")
@click.argument("target")
@click.option("--output", "-o", "output_file", required=True, metavar="FILE", help="Baseline file to write (YAML)")
@click.option("--force", is_flag=True, default=False, help="Overwrite FILE if it already exists")
@click.option("--config", "-c", default=None, help="Path to a scanner-config.yaml file")
@click.option("--branch", default="main", show_default=True, help="Branch to scan (for repo URL targets)")
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN", help="GitHub PAT (overrides GITHUB_TOKEN env var)")
@click.option("--azure-token", default=None, envvar="AZURE_DEVOPS_TOKEN", help="Azure DevOps PAT (overrides AZURE_DEVOPS_TOKEN env var)")
@click.option("--no-vuln-check", is_flag=True, default=False, help="Skip OSV lookups for pinned skill dependencies")
def skills_baseline(
    target: str,
    output_file: str,
    force: bool,
    config: str | None,
    branch: str,
    github_token: str | None,
    azure_token: str | None,
    no_vuln_check: bool,
) -> None:
    """Accept the current skill findings so later scans report only new ones.

    Scans TARGET (same targets as 'skills scan') statically, with no LLM review, and writes
    every current finding to FILE as a fingerprint (rule, skill, file and evidence, no line
    numbers and no raw evidence). Review the file, add a 'note' to entries if you like, and
    commit it. Then pass it to 'skills scan --baseline FILE' or 'scan --skills-baseline FILE'.

    \b
    Exit codes:
      0  baseline written
      2  error (bad target, FILE exists without --force, cannot write FILE)

    \b
    Examples:
      quin-scanner skills baseline ./skills -o skills-baseline.yaml
      quin-scanner skills baseline ./skills -o skills-baseline.yaml --force
    """
    from quin_scanner.scanners.skills.baseline import write_baseline
    from quin_scanner.scanners.skills.discovery import is_pseudo_record
    from quin_scanner.scanners.skills.runner import open_skill_target, run_skill_scan

    try:
        if Path(output_file).exists() and not force:
            raise click.ClickException(f"{output_file} already exists (use --force to overwrite)")
        cfg = _build_config(
            config=config, llm_provider=None, llm_model=None, llm_api_key=None,
            output_format=None, no_llm=True, github_token=github_token, openai_compatible_url=None,
        )
        cfg.no_llm = True
        if no_vuln_check:
            cfg.vuln_check_enabled = False
        with open_skill_target(target, github_token=cfg.github_token, azure_token=azure_token, branch=branch) as accessor:
            result = run_skill_scan(accessor, cfg)
        count = write_baseline(output_file, result.assessments)
    except click.ClickException as e:
        click.echo(f"Error: {e.message}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    skills_n = sum(1 for a in result.assessments if not is_pseudo_record(a.record))
    click.echo(
        f"Baseline written to {output_file}: {count} {'entry' if count == 1 else 'entries'} "
        f"from {skills_n} skill{'s' if skills_n != 1 else ''}"
    )
