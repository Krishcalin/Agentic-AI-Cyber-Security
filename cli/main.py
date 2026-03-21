"""CLI entry point for Agentic AI Security Scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from core.engine import ScanEngine
from core.logger import setup_logging
from core.reporter import JsonReporter, SarifReporter, TerminalReporter

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="agentic-scan")
def cli() -> None:
    """Agentic AI Security Scanner — AI-powered source code security analysis."""
    pass


@cli.command()
@click.option("--file", "-f", "file_path", default=None, help="Scan a single file")
@click.option("--project", "-p", "project_dir", default=None, help="Scan a project directory")
@click.option("--format", "-o", "output_format", default="terminal",
              type=click.Choice(["terminal", "json", "sarif"]),
              help="Output format")
@click.option("--output", "output_path", default=None, help="Write output to file")
@click.option("--verbosity", "-v", default="compact",
              type=click.Choice(["minimal", "compact", "full"]),
              help="Output verbosity level")
@click.option("--rules-dir", default="rules", help="Path to rules directory")
@click.option("--exclude", multiple=True, help="Directories to exclude")
def scan(
    file_path: str | None,
    project_dir: str | None,
    output_format: str,
    output_path: str | None,
    verbosity: str,
    rules_dir: str,
    exclude: tuple[str, ...],
) -> None:
    """Scan source code for security vulnerabilities."""
    setup_logging(log_level="WARNING")

    if not file_path and not project_dir:
        console.print("[red]Error: specify --file or --project[/]")
        sys.exit(1)

    engine = ScanEngine(rules_dir=rules_dir)
    rules = engine.initialize()
    if rules == 0:
        console.print("[yellow]Warning: no rules loaded. Check rules directory.[/]")

    if file_path:
        if not Path(file_path).exists():
            console.print(f"[red]File not found: {file_path}[/]")
            sys.exit(1)
        result = engine.scan_file(file_path)
    else:
        if not Path(project_dir).is_dir():
            console.print(f"[red]Directory not found: {project_dir}[/]")
            sys.exit(1)
        result = engine.scan_project(project_dir, exclude=list(exclude) if exclude else None)

    # Output results
    match output_format:
        case "terminal":
            reporter = TerminalReporter(console=console, verbosity=verbosity)
            reporter.print_result(result)
        case "json":
            json_reporter = JsonReporter()
            output = json_reporter.generate(result, output_path=output_path)
            if not output_path:
                console.print(output)
        case "sarif":
            sarif_reporter = SarifReporter()
            sarif_reporter.generate(result, output_path=output_path or "results.sarif")
            console.print(f"SARIF report: [cyan]{output_path or 'results.sarif'}[/]")

    # Exit code based on findings
    if result.error_count > 0:
        sys.exit(2)
    elif result.warning_count > 0:
        sys.exit(1)
    sys.exit(0)


@cli.command(name="check-package")
@click.argument("package_name")
@click.option("--registry", "-r", default="pypi",
              type=click.Choice(["pypi", "npm", "crates"]),
              help="Package registry to check")
def check_package(package_name: str, registry: str) -> None:
    """Check if a package exists on a registry (hallucination detection)."""
    setup_logging(log_level="WARNING")
    from core.package_checker import PackageChecker

    checker = PackageChecker()
    result = checker.check_package(package_name, registry)

    if result.is_malicious:
        console.print(f"[red bold]MALICIOUS[/] — {package_name} is in the known malicious package database")
        console.print(f"  [red]{result.reason}[/]")
        sys.exit(2)
    elif result.is_typosquat:
        console.print(f"[red]TYPOSQUAT[/] — '{package_name}' looks like a typosquat of '[cyan]{result.similar_to}[/]'")
        console.print(f"  Edit distance: {result.distance}")
        sys.exit(2)
    elif not result.exists:
        console.print(f"[yellow]NOT FOUND[/] — '{package_name}' not found on {registry}")
        console.print(f"  This may be a hallucinated package name")
        sys.exit(1)
    else:
        console.print(f"[green]OK[/] — '{package_name}' appears legitimate on {registry}")


@cli.command(name="scan-packages")
@click.option("--file", "-f", "file_path", required=True, help="File to scan for package imports")
def scan_packages(file_path: str) -> None:
    """Scan all imports in a file for hallucinated or malicious packages."""
    setup_logging(log_level="WARNING")
    from rich.table import Table
    from core.package_checker import PackageChecker

    if not Path(file_path).exists():
        console.print(f"[red]File not found: {file_path}[/]")
        sys.exit(1)

    checker = PackageChecker()
    results = checker.check_file_imports(file_path)

    if not results:
        console.print(f"[dim]No package imports found in {file_path}[/]")
        return

    table = Table(title=f"Package Verification — {file_path}")
    table.add_column("Package", style="cyan")
    table.add_column("Registry", width=8)
    table.add_column("Status", width=12)
    table.add_column("Risk", width=10)
    table.add_column("Details")

    risk_colors = {"safe": "green", "low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}
    status_icons = {"safe": "[green]OK[/]", "low": "[green]OK[/]", "medium": "[yellow]WARN[/]", "high": "[red]ALERT[/]", "critical": "[red bold]DANGER[/]"}

    for r in results:
        color = risk_colors.get(r.risk_level, "white")
        status = status_icons.get(r.risk_level, "?")
        table.add_row(r.package_name, r.registry, status, f"[{color}]{r.risk_level}[/]", r.reason or "—")

    console.print(table)

    critical = sum(1 for r in results if r.risk_level in ("high", "critical"))
    if critical:
        console.print(f"\n[red]{critical} package(s) require attention[/]")
        sys.exit(2)


@cli.command(name="scan-prompt")
@click.option("--text", "-t", required=True, help="Text to scan for prompt injection")
def scan_prompt(text: str) -> None:
    """Detect prompt injection patterns in text."""
    console.print(f"[yellow]Prompt scanner not yet implemented (Phase 4)[/]")


@cli.command(name="scan-diff")
@click.option("--base", "-b", default="main", help="Base branch/ref to diff against")
def scan_diff(base: str) -> None:
    """Scan only files changed in git diff."""
    console.print(f"[yellow]Git diff scanning not yet implemented (Phase 9)[/]")


@cli.command(name="mcp-serve")
def mcp_serve() -> None:
    """Start MCP server for Claude Code integration."""
    console.print(f"[yellow]MCP server not yet implemented (Phase 6)[/]")


@cli.command()
@click.option("--file", "-f", "file_path", required=True, help="File to review")
@click.option("--provider", default="claude", type=click.Choice(["claude", "openai"]))
def review(file_path: str, provider: str) -> None:
    """AI-powered semantic code review."""
    console.print(f"[yellow]Semantic reviewer not yet implemented (Phase 7)[/]")


@cli.command(name="list-rules")
@click.option("--language", "-l", default=None, help="Filter rules by language")
@click.option("--rules-dir", default="rules", help="Path to rules directory")
def list_rules(language: str | None, rules_dir: str) -> None:
    """List all loaded security rules."""
    from rich.table import Table
    from core.rule_loader import RuleLoader

    loader = RuleLoader(rules_dir)
    rules = loader.load_all()

    if language:
        rules = [r for r in rules if language in r.languages]

    table = Table(title=f"Security Rules ({len(rules)} loaded)")
    table.add_column("ID", style="cyan", max_width=40)
    table.add_column("Severity", width=8)
    table.add_column("CWE", width=10)
    table.add_column("Languages", width=15)
    table.add_column("Message", ratio=1)

    sev_colors = {"error": "red", "warning": "yellow", "info": "cyan", "style": "dim"}

    for rule in sorted(rules, key=lambda r: r.id):
        color = sev_colors.get(rule.severity.value, "white")
        table.add_row(
            rule.id,
            f"[{color}]{rule.severity.value.upper()}[/]",
            rule.cwe or "—",
            ", ".join(rule.languages),
            rule.message[:70],
        )

    console.print(table)


# Entry point
def main() -> None:
    cli()
