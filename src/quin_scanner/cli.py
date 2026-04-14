from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click
from dotenv import load_dotenv

from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import RepoAccessorFactory
from quin_scanner.report import ReportGenerator

load_dotenv()


def _output_filename(target: str, fmt: str) -> str:
    """Build an output filename: <repo-name>_<YYYYMMDD_HHMMSS>.<fmt>"""
    # Extract the repo (or directory) name from the target
    clean = target.rstrip("/").removesuffix(".git")
    name = clean.rsplit("/", 1)[-1] or clean.replace("/", "_").replace(":", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{name}_{ts}.{fmt}"

_OUTPUT_CHOICES = click.Choice(["json", "yaml", "html"])


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(prog_name="quin-scanner")
def cli() -> None:
    """Quin Scanner — detect GenAI and Agentic AI applications in repositories.

    Scans local directories, GitHub repos, or entire GitHub organizations to
    identify LLM usage, AI agent frameworks, model configurations, prompt
    templates, and tool definitions.

    \b
    Targets accepted by the scan command:
      - Local path:        /path/to/repo
      - GitHub URL:        https://github.com/owner/repo
      - GitHub shorthand:  owner/repo

    \b
    Examples:
      quin-scanner scan ./my-project
      quin-scanner scan owner/repo --no-llm
      quin-scanner scan https://github.com/owner/repo -o yaml -d reports/
      quin-scanner scan-batch targets.txt -d reports/
      quin-scanner scan-org my-org --skip-archived --skip-forks

    \b
    Environment variables:
      GITHUB_TOKEN          GitHub personal access token
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
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, etc.)")
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
    openai_compatible_url: str | None,
) -> None:
    """Scan a single repository for GenAI/Agentic AI indicators.

    TARGET can be a local path, a GitHub URL, or owner/repo shorthand.

    \b
    Examples:
      quin-scanner scan ./my-project
      quin-scanner scan owner/repo --no-llm -o yaml
      quin-scanner scan owner/repo --min-confidence 0.7 -d reports/
      quin-scanner scan owner/repo --llm-provider anthropic --llm-model claude-sonnet-4-20250514
    """
    # Build config
    if config:
        cfg = ScannerConfig.load_from_file(config)
        if no_llm:
            cfg.no_llm = True
        if github_token:
            cfg.github_token = github_token
        if openai_compatible_url:
            cfg.openai_compatible_url = openai_compatible_url
    else:
        cfg = ScannerConfig.load_from_args(
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_api_key=llm_api_key,
            output_format=output,
            no_llm=no_llm,
            github_token=github_token,
            openai_compatible_url=openai_compatible_url,
        )

    # Create accessor
    try:
        accessor = RepoAccessorFactory.create(target, github_token=cfg.github_token, branch=branch)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Run scan
    try:
        report = ScanOrchestrator().run(accessor, cfg, verbose=sys.stderr.isatty())

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
) -> None:
    """Scan multiple repositories listed in a file.

    TARGETS_FILE should contain one target per line (local paths, GitHub URLs,
    or owner/repo shorthand). Lines starting with # are ignored.

    \b
    Examples:
      quin-scanner scan-batch targets.txt
      quin-scanner scan-batch targets.txt -d reports/ -o yaml
      quin-scanner scan-batch targets.txt --no-llm
    """
    targets = [
        line.strip()
        for line in Path(targets_file).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

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

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    for target in targets:
        click.echo(f"Scanning {target} ...", err=True)
        accessor = None
        try:
            accessor = RepoAccessorFactory.create(target, github_token=base_cfg.github_token)
            report = ScanOrchestrator().run(accessor, base_cfg, verbose=sys.stderr.isatty())
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
            continue
        finally:
            if accessor:
                accessor.cleanup()

        out_path = Path(output_dir) / _output_filename(target, output)
        ReportGenerator.write_to_file(report, str(out_path), output)
        click.echo(f"  -> {out_path}", err=True)


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
) -> None:
    """Scan all repositories in a GitHub organization or user account.

    ORG_NAME is a GitHub organization or user account name (auto-detected).
    Discovers all repos via the GitHub API, then scans each one.
    Requires a GITHUB_TOKEN with org/user read access.

    \b
    Examples:
      quin-scanner scan-org my-org --skip-archived --skip-forks
      quin-scanner scan-org my-org -d reports/ -o yaml --no-llm
      quin-scanner scan-org my-username --github-token $GITHUB_TOKEN
    """
    from quin_scanner.github_client import GitHubClient

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

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    reports = []
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
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
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
