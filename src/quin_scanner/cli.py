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
    safe = target.replace("/", "_").replace(":", "_").replace(".git", "").strip("_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{safe}_{ts}.{fmt}"

_OUTPUT_CHOICES = click.Choice(["json", "yaml"])


@click.group()
@click.version_option()
def cli() -> None:
    """Quin Scanner — detect GenAI/Agentic AI applications in repos."""


@cli.command()
@click.argument("target")
@click.option("--output", "-o", default="json", type=_OUTPUT_CHOICES, show_default=True)
@click.option("--output-file", "-f", default=None, help="Write output to file instead of stdout")
@click.option("--output-dir", "-d", default=None, help="Write output to this directory (auto-names the file)")
@click.option("--llm-provider", default=None, help="LLM provider (openai|anthropic|google|ollama)")
@click.option("--llm-model", default=None, help="Model name")
@click.option("--llm-api-key", default=None, help="API key (overrides env var)")
@click.option("--config", "-c", default=None, help="Path to scanner-config.yaml")
@click.option("--branch", default="main", show_default=True, help="Git branch (for GitHub targets)")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM analysis")
@click.option(
    "--min-confidence", default=0.0, show_default=True, type=float,
    help="Exclude findings below this confidence threshold (0.0–1.0)"
)
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--openai-compatible-url", default=None, help="Base URL for OpenAI-compatible API endpoint")
def scan(
    target: str,
    output: str,
    output_file: str | None,
    output_dir: str | None,
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
    """Scan a repo for GenAI/Agentic AI indicators.

    TARGET can be a local path, GitHub URL, or owner/repo shorthand.
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
    except Exception as e:
        click.echo(f"Scan failed: {e}", err=True)
        sys.exit(1)

    # Apply confidence filter if requested
    if min_confidence > 0.0:
        report.findings = [f for f in report.findings if f.confidence >= min_confidence]

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


@cli.command("scan-batch")
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--output", "-o", default="json", type=_OUTPUT_CHOICES, show_default=True)
@click.option("--output-dir", "-d", default=None, help="Directory for per-repo output files")
@click.option("--llm-provider", default=None)
@click.option("--llm-model", default=None)
@click.option("--llm-api-key", default=None)
@click.option("--config", "-c", default=None)
@click.option("--no-llm", is_flag=True, default=False)
@click.option("--github-token", default=None, envvar="GITHUB_TOKEN")
@click.option("--openai-compatible-url", default=None)
def scan_batch(
    targets_file: str,
    output: str,
    output_dir: str | None,
    llm_provider: str | None,
    llm_model: str | None,
    llm_api_key: str | None,
    config: str | None,
    no_llm: bool,
    github_token: str | None,
    openai_compatible_url: str | None,
) -> None:
    """Scan multiple repos listed in TARGETS_FILE (one target per line)."""
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

    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    reports = []
    for target in targets:
        click.echo(f"Scanning {target} ...", err=True)
        try:
            accessor = RepoAccessorFactory.create(target, github_token=base_cfg.github_token)
            report = ScanOrchestrator().run(accessor, base_cfg, verbose=sys.stderr.isatty())
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
            continue

        if output_dir:
            out_path = Path(output_dir) / _output_filename(target, output)
            ReportGenerator.write_to_file(report, str(out_path), output)
            click.echo(f"  -> {out_path}", err=True)
        else:
            reports.append(report.to_dict())

    if not output_dir:
        import json
        click.echo(json.dumps(reports, indent=2, default=str))


@cli.command("scan-org")
@click.argument("org_name")
@click.option("--output", "-o", type=click.Choice(["json", "yaml"]), default="json")
@click.option("--output-dir", default=".", type=click.Path())
@click.option("--github-token", envvar="GITHUB_TOKEN", default=None)
@click.option("--skip-archived", is_flag=True, default=False)
@click.option("--skip-forks", is_flag=True, default=False)
@click.option("--no-llm", is_flag=True, default=False)
@click.option("--config", "-c", type=click.Path(exists=True), default=None)
@click.option("--openai-compatible-url", default=None)
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
    """Scan all repositories in a GitHub organization."""
    from quin_scanner.github_client import GitHubClient

    client = GitHubClient(token=github_token)

    click.echo(f"Listing repos for org: {org_name} ...", err=True)
    try:
        repos = client.list_repos_for(org_name, skip_archived=skip_archived, skip_forks=skip_forks)
    except Exception as e:
        click.echo(f"Error listing repos: {e}", err=True)
        sys.exit(1)

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

        out_path = Path(output_dir) / _output_filename(repo.full_name, output)
        ReportGenerator.write_to_file(report, str(out_path), output)
        click.echo(f"  -> {out_path}", err=True)
        reports.append({"repo": repo.full_name, "is_ai_application": report.is_ai_application, "confidence": report.confidence})

    import json
    click.echo(json.dumps(reports, indent=2))
