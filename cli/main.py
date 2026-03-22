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
            from integrations.sarif_exporter import generate_sarif
            generate_sarif(result, output_path=output_path or "results.sarif")
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
    setup_logging(log_level="WARNING")
    from core.prompt_scanner import PromptScanner

    scanner = PromptScanner(rules_path="rules/prompt_injection.yaml")
    result = scanner.scan_text(text)

    if result.is_safe:
        console.print(f"[green]SAFE[/] — No prompt injection patterns detected")
        console.print(f"[dim]Scanned {result.input_length} characters against {scanner.pattern_count} patterns[/]")
        return

    risk_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}
    color = risk_colors.get(result.risk_level, "white")
    console.print(f"[{color}]INJECTION DETECTED[/] — Risk: [{color}]{result.risk_level.upper()}[/]")
    console.print(f"[dim]{result.finding_count} pattern(s) matched in {result.scan_time_ms:.1f}ms[/]\n")

    from rich.table import Table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Risk", width=10)
    table.add_column("Category", width=20)
    table.add_column("Description", ratio=1)
    table.add_column("Matched", width=40)

    for f in result.findings:
        rc = risk_colors.get(f.risk, "white")
        table.add_row(
            f"[{rc}]{f.risk.upper()}[/]",
            f.category,
            f.description,
            f.matched_text[:40] + ("..." if len(f.matched_text) > 40 else ""),
        )

    console.print(table)
    summary = scanner.get_risk_summary(result)
    if summary["by_category"]:
        cats = ", ".join(f"{k}: {v}" for k, v in summary["by_category"].items())
        console.print(f"\n[dim]Categories: {cats}[/]")

    sys.exit(2 if result.risk_level in ("critical", "high") else 1)


@cli.command()
@click.option("--file", "-f", "file_path", required=True, help="File to generate fixes for")
@click.option("--rules-dir", default="rules", help="Path to rules directory")
@click.option("--apply", is_flag=True, help="Apply fixes to file (modifies in-place)")
def fix(file_path: str, rules_dir: str, apply: bool) -> None:
    """Auto-fix detected vulnerabilities in a file."""
    setup_logging(log_level="WARNING")
    from core.fix_generator import FixGenerator

    if not Path(file_path).exists():
        console.print(f"[red]File not found: {file_path}[/]")
        sys.exit(1)

    engine = ScanEngine(rules_dir=rules_dir)
    engine.initialize()
    scan_result = engine.scan_file(file_path)

    if scan_result.total_findings == 0:
        console.print(f"[green]No findings to fix in {file_path}[/]")
        return

    gen = FixGenerator()
    fix_result = gen.generate_fixes(scan_result.all_findings)

    if fix_result.fix_count == 0:
        console.print(f"[yellow]{scan_result.total_findings} findings but no auto-fixes available[/]")
        return

    from rich.table import Table
    table = Table(title=f"Auto-Fix Results — {file_path}")
    table.add_column("Line", width=6, justify="right")
    table.add_column("CWE", width=10)
    table.add_column("Fix", ratio=1)
    table.add_column("Confidence", width=10)

    for f in fix_result.fixes:
        table.add_row(
            str(f.finding.line_number),
            f.cwe,
            f.explanation[:70],
            f.confidence,
        )

    console.print(table)
    console.print(f"\n[green]{fix_result.fix_count} fixes available[/], [dim]{fix_result.unfixable_count} unfixable[/]")

    if apply:
        # Apply fixes to file
        content = Path(file_path).read_text(encoding="utf-8")
        lines = content.splitlines()
        for f in sorted(fix_result.fixes, key=lambda x: x.finding.line_number, reverse=True):
            idx = f.finding.line_number - 1
            if 0 <= idx < len(lines):
                lines[idx] = f.fixed_line
        Path(file_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        console.print(f"[green]Fixes applied to {file_path}[/]")
    else:
        # Show diff
        diff = fix_result.generate_diff(file_path)
        if diff:
            from rich.syntax import Syntax
            console.print(Syntax(diff, "diff", theme="monokai"))
        console.print(f"\n[dim]Run with --apply to apply fixes[/]")


@cli.command(name="scan-diff")
@click.option("--base", "-b", default="HEAD", help="Base ref to diff against")
@click.option("--directory", "-d", default=".", help="Project directory")
@click.option("--format", "-o", "output_format", default="terminal",
              type=click.Choice(["terminal", "json", "sarif"]))
@click.option("--output", "output_path", default=None, help="Write output to file")
@click.option("--rules-dir", default="rules", help="Path to rules directory")
@click.option("--fail-on", default="error", type=click.Choice(["error", "warning", "info"]),
              help="Minimum severity to fail CI on")
def scan_diff(base: str, directory: str, output_format: str, output_path: str | None,
              rules_dir: str, fail_on: str) -> None:
    """Scan only files changed in git diff — ideal for CI/CD."""
    import subprocess as sp
    setup_logging(log_level="WARNING")

    try:
        diff_output = sp.run(
            ["git", "diff", "--name-only", base],
            capture_output=True, text=True, cwd=directory, timeout=30,
        )
        if diff_output.returncode != 0:
            console.print(f"[red]git diff failed: {diff_output.stderr.strip()}[/]")
            sys.exit(1)

        changed = [f.strip() for f in diff_output.stdout.strip().splitlines() if f.strip()]
    except (sp.TimeoutExpired, FileNotFoundError) as e:
        console.print(f"[red]git not available: {e}[/]")
        sys.exit(1)

    if not changed:
        console.print("[green]No changed files to scan.[/]")
        sys.exit(0)

    console.print(f"[dim]Scanning {len(changed)} changed files vs {base}...[/]")

    engine = ScanEngine(rules_dir=rules_dir)
    engine.initialize()

    from core.models import FileResult, ScanResult
    from datetime import datetime
    import uuid

    all_file_results: list[FileResult] = []
    for file in changed:
        full = str(Path(directory) / file)
        if Path(full).exists():
            result = engine.scan_file(full)
            all_file_results.extend(result.file_results)

    scan_result = ScanResult(
        scan_id=uuid.uuid4().hex[:8],
        target=f"git diff {base}",
        file_results=all_file_results,
        start_time=datetime.now(),
        end_time=datetime.now(),
        rules_loaded=engine.rules_loaded,
        total_files=len(all_file_results),
        total_lines=sum(fr.lines_scanned for fr in all_file_results),
    )
    from core.grader import calculate_grade
    scan_result.grade = calculate_grade(scan_result)

    match output_format:
        case "terminal":
            reporter = TerminalReporter(console=console, verbosity="compact")
            reporter.print_result(scan_result)
        case "json":
            json_reporter = JsonReporter()
            output = json_reporter.generate(scan_result, output_path=output_path)
            if not output_path:
                console.print(output)
        case "sarif":
            from integrations.sarif_exporter import generate_sarif
            generate_sarif(scan_result, output_path=output_path or "results.sarif")
            console.print(f"SARIF report: [cyan]{output_path or 'results.sarif'}[/]")

    # CI exit code
    from integrations.github_actions import get_exit_code
    code = get_exit_code(scan_result, fail_on=fail_on)
    if code > 0:
        console.print(f"[red]CI FAIL — findings at or above '{fail_on}' severity[/]")
    sys.exit(code)


@cli.command(name="audit-mcp")
@click.option("--tools-json", "-t", required=True, help="Path to MCP tools/list JSON response")
@click.option("--server-name", "-n", default="unknown", help="MCP server name")
def audit_mcp(tools_json: str, server_name: str) -> None:
    """Audit an MCP server's tool definitions for security vulnerabilities."""
    import json as json_mod
    setup_logging(log_level="WARNING")
    from core.mcp_auditor import MCPAuditor

    p = Path(tools_json)
    if not p.exists():
        console.print(f"[red]File not found: {tools_json}[/]")
        sys.exit(1)

    data = json_mod.loads(p.read_text(encoding="utf-8"))
    tools = data if isinstance(data, list) else data.get("tools", [])

    auditor = MCPAuditor()
    result = auditor.audit_tools(tools, server_name=server_name)

    risk_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}
    grade_colors = {"A": "green bold", "B": "green", "C": "yellow", "D": "red", "F": "red bold"}

    from rich.panel import Panel
    from rich.text import Text
    header = Text()
    header.append(f"MCP Server: {server_name}\n", style="bold")
    header.append(f"Grade: ", style="bold")
    header.append(f"{result.grade} ", style=grade_colors.get(result.grade, "white"))
    header.append(f"({result.score}/100)\n")
    header.append(f"Tools: {result.total_tools} | Findings: {result.finding_count}")
    console.print(Panel(header, title="MCP Security Audit", border_style="purple"))

    if result.findings:
        from rich.table import Table
        table = Table(show_header=True, header_style="bold")
        table.add_column("Risk", width=10)
        table.add_column("Tool", width=20)
        table.add_column("Category", width=15)
        table.add_column("Finding", ratio=1)

        for f in result.findings:
            color = risk_colors.get(f.risk, "white")
            table.add_row(f"[{color}]{f.risk.upper()}[/]", f.tool_name, f.category, f.title)
        console.print(table)

    sys.exit(2 if result.critical_count > 0 else 1 if result.high_count > 0 else 0)


@cli.command(name="scan-rag")
@click.option("--file", "-f", "file_path", default=None, help="Single document to scan")
@click.option("--directory", "-d", default=None, help="Directory of documents to scan")
def scan_rag(file_path: str | None, directory: str | None) -> None:
    """Scan documents for RAG pipeline security issues (injection, data leakage)."""
    setup_logging(log_level="WARNING")
    from core.rag_scanner import RAGScanner

    if not file_path and not directory:
        console.print("[red]Error: specify --file or --directory[/]")
        sys.exit(1)

    scanner = RAGScanner()

    if file_path:
        if not Path(file_path).exists():
            console.print(f"[red]File not found: {file_path}[/]")
            sys.exit(1)
        findings = scanner.scan_file(file_path)
        console.print(f"[bold]RAG Document Scan: {file_path}[/]")
    else:
        result = scanner.scan_directory(directory)
        findings = result.findings
        console.print(f"[bold]RAG Directory Scan: {directory}[/]")
        console.print(f"[dim]Documents: {result.total_documents} | With issues: {result.documents_with_issues}[/]")

    if not findings:
        console.print("[green]No RAG security issues found.[/]")
        return

    from rich.table import Table
    risk_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}
    table = Table(title=f"RAG Findings ({len(findings)})")
    table.add_column("Risk", width=10)
    table.add_column("Category", width=20)
    table.add_column("Finding", ratio=1)
    table.add_column("File", width=30)

    for f in findings:
        color = risk_colors.get(f.risk, "white")
        table.add_row(f"[{color}]{f.risk.upper()}[/]", f.category, f.title, f.source_file or "—")
    console.print(table)

    critical = sum(1 for f in findings if f.risk in ("critical", "high"))
    sys.exit(2 if critical > 0 else 1)


@cli.command(name="mcp-serve")
@click.option("--rules-dir", default="rules", help="Path to rules directory")
def mcp_serve(rules_dir: str) -> None:
    """Start MCP server for Claude Code / Cursor / Windsurf integration."""
    from mcp_server.server import run_server
    run_server(rules_dir=rules_dir)


@cli.command()
@click.option("--file", "-f", "file_path", default=None, help="File to review")
@click.option("--code", "-c", default=None, help="Code string to review")
@click.option("--language", "-l", default="python", help="Language of code string")
@click.option("--provider", default="claude", type=click.Choice(["claude", "openai", "mock"]))
@click.option("--model", default=None, help="Model override (e.g., claude-opus-4-20250514)")
@click.option("--format", "output_format", default="terminal", type=click.Choice(["terminal", "json"]))
def review(file_path: str | None, code: str | None, language: str, provider: str,
           model: str | None, output_format: str) -> None:
    """AI-powered semantic code review using Claude or OpenAI."""
    setup_logging(log_level="WARNING")
    from core.semantic_reviewer import SemanticReviewer

    if not file_path and not code:
        console.print("[red]Error: specify --file or --code[/]")
        sys.exit(1)

    try:
        reviewer = SemanticReviewer(provider=provider, model=model)
    except Exception as e:
        console.print(f"[red]Failed to initialize {provider}: {e}[/]")
        sys.exit(1)

    if file_path:
        if not Path(file_path).exists():
            console.print(f"[red]File not found: {file_path}[/]")
            sys.exit(1)
        result = reviewer.review_file(file_path)
    else:
        result = reviewer.review_code(code, language)

    if result.error:
        console.print(f"[yellow]Review error: {result.error}[/]")

    if output_format == "json":
        import json
        data = {
            "summary": result.summary,
            "intent_analysis": result.intent_analysis,
            "project_type": result.project_type,
            "findings": [{"title": f.title, "severity": f.severity, "description": f.description,
                          "cwe": f.cwe, "fix": f.fix_suggestion, "line": f.line_start}
                         for f in result.findings],
            "tokens_used": result.tokens_used,
            "review_time_ms": round(result.review_time_ms, 1),
            "provider": result.provider,
        }
        console.print(json.dumps(data, indent=2))
        return

    # Terminal output
    from rich.panel import Panel
    from rich.table import Table

    if result.summary:
        console.print(Panel(result.summary, title="[bold]Security Summary[/]", border_style="blue"))

    if result.intent_analysis:
        console.print(f"\n[dim]Intent:[/] {result.intent_analysis}")
        console.print(f"[dim]Project type:[/] {result.project_type}")

    if result.findings:
        table = Table(title=f"Semantic Findings ({result.finding_count})")
        table.add_column("Sev", width=8)
        table.add_column("Line", width=6, justify="right")
        table.add_column("Title", ratio=1)
        table.add_column("CWE", width=10)

        sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        for f in result.findings:
            color = sev_colors.get(f.severity, "white")
            table.add_row(f"[{color}]{f.severity.upper()}[/]", str(f.line_start), f.title, f.cwe)

        console.print(table)

        # Show details for high/critical
        for f in result.findings:
            if f.severity in ("critical", "high"):
                console.print(f"\n[red bold]{f.title}[/] (line {f.line_start})")
                console.print(f"  {f.description}")
                if f.fix_suggestion:
                    console.print(f"  [green]Fix: {f.fix_suggestion}[/]")
    else:
        console.print("\n[green]No security issues found by semantic review.[/]")

    console.print(f"\n[dim]Provider: {result.provider} | Tokens: {result.tokens_used} | Time: {result.review_time_ms:.0f}ms[/]")


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
