"""Report generation — terminal, JSON, and SARIF output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text

from core.grader import calculate_grade, calculate_score, grade_label
from core.models import FileResult, Finding, Grade, ScanResult, Severity


class TerminalReporter:
    """Rich-formatted terminal output."""

    SEVERITY_COLORS = {
        Severity.ERROR: "red bold",
        Severity.WARNING: "yellow",
        Severity.INFO: "cyan",
        Severity.STYLE: "dim",
    }

    GRADE_COLORS = {
        Grade.A: "green bold",
        Grade.B: "green",
        Grade.C: "yellow",
        Grade.D: "red",
        Grade.F: "red bold",
    }

    def __init__(self, console: Console | None = None, verbosity: str = "compact") -> None:
        self.console = console or Console()
        self.verbosity = verbosity

    def print_result(self, result: ScanResult) -> None:
        """Print full scan results to terminal."""
        grade = calculate_grade(result)
        score = calculate_score(result)
        result.grade = grade

        self._print_header(result, grade, score)

        if result.total_findings == 0:
            self.console.print("\n[green]No security issues found.[/]\n")
            return

        if self.verbosity != "minimal":
            self._print_summary_table(result)

        if self.verbosity == "full":
            self._print_findings(result)
        elif self.verbosity == "compact":
            self._print_findings_compact(result)

    def _print_header(self, result: ScanResult, grade: Grade, score: int) -> None:
        grade_color = self.GRADE_COLORS.get(grade, "white")
        header = Text()
        header.append("Security Grade: ", style="bold")
        header.append(f"{grade.value} ", style=grade_color)
        header.append(f"({score}/100)", style="dim")
        header.append(f"  —  {grade_label(grade)}", style="dim")

        self.console.print(Panel(
            header,
            title=f"[bold]Scan Results[/] — {result.target}",
            subtitle=f"{result.total_files} files | {result.total_findings} findings | {result.duration_seconds:.1f}s",
            border_style="blue",
        ))

    def _print_summary_table(self, result: ScanResult) -> None:
        table = Table(title="Finding Summary", show_header=True, header_style="bold")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("[red]ERROR (critical)[/]", str(result.error_count))
        table.add_row("[yellow]WARNING (high)[/]", str(result.warning_count))
        table.add_row("[cyan]INFO (medium)[/]", str(result.info_count))
        total_style = sum(1 for f in result.all_findings if f.severity == Severity.STYLE)
        table.add_row("[dim]STYLE[/]", str(total_style))
        table.add_row("[bold]Total[/]", f"[bold]{result.total_findings}[/]")

        self.console.print(table)

    def _print_findings(self, result: ScanResult) -> None:
        """Verbose finding output with code context."""
        for finding in result.all_findings:
            sev_color = self.SEVERITY_COLORS.get(finding.severity, "white")
            self.console.print(f"\n[{sev_color}]{finding.severity.value.upper()}[/] {finding.rule_id}")
            self.console.print(f"  {finding.message}")
            self.console.print(f"  [dim]{finding.location}[/]")
            if finding.line_content:
                self.console.print(f"  [dim]>[/] {finding.line_content.strip()}")
            if finding.cwe:
                self.console.print(f"  [dim]CWE: {finding.cwe}[/]")
            if finding.fix_suggestion:
                self.console.print(f"  [green]Fix: {finding.fix_suggestion}[/]")

    def _print_findings_compact(self, result: ScanResult) -> None:
        """Compact one-line-per-finding output."""
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Sev", width=7)
        table.add_column("Rule", width=35)
        table.add_column("Location", width=30)
        table.add_column("Message", ratio=1)

        for finding in result.all_findings:
            sev_color = self.SEVERITY_COLORS.get(finding.severity, "white")
            table.add_row(
                f"[{sev_color}]{finding.severity.value.upper()}[/]",
                finding.rule_id,
                finding.location,
                finding.message[:80],
            )

        self.console.print(table)


class JsonReporter:
    """JSON output for CI/CD integration."""

    def generate(self, result: ScanResult, output_path: str | None = None) -> str:
        """Generate JSON report. Returns JSON string, optionally writes to file."""
        grade = calculate_grade(result)
        result.grade = grade
        data = result.to_dict()
        data["score"] = calculate_score(result)

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")

        return json_str


class SarifReporter:
    """SARIF 2.1.0 output for GitHub Code Scanning / GitLab SAST."""

    def generate(self, result: ScanResult, output_path: str | None = None) -> dict[str, Any]:
        """Generate SARIF 2.1.0 report."""
        rules_map: dict[str, int] = {}
        sarif_rules: list[dict] = []
        sarif_results: list[dict] = []

        for finding in result.all_findings:
            # Build rules index
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = len(sarif_rules)
                rule_entry: dict[str, Any] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.message},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif(finding.severity),
                    },
                }
                if finding.cwe:
                    rule_entry["properties"] = {"tags": [finding.cwe]}
                sarif_rules.append(rule_entry)

            # Build result
            sarif_results.append({
                "ruleId": finding.rule_id,
                "ruleIndex": rules_map[finding.rule_id],
                "level": self._severity_to_sarif(finding.severity),
                "message": {"text": finding.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": finding.line_number,
                            "snippet": {"text": finding.line_content},
                        },
                    },
                }],
            })

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "agentic-ai-security",
                        "version": "0.1.0",
                        "rules": sarif_rules,
                    },
                },
                "results": sarif_results,
            }],
        }

        if output_path:
            Path(output_path).write_text(
                json.dumps(sarif, indent=2), encoding="utf-8"
            )

        return sarif

    @staticmethod
    def _severity_to_sarif(severity: Severity) -> str:
        return {
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "note",
            Severity.STYLE: "note",
        }.get(severity, "note")
