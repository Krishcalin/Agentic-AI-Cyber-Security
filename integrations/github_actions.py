"""GitHub Actions integration — annotations and summary output."""

from __future__ import annotations

import sys
from typing import Any

from core.models import Finding, ScanResult, Severity


def print_annotations(result: ScanResult) -> None:
    """Print GitHub Actions workflow annotations for findings."""
    for finding in result.all_findings:
        level = _severity_to_annotation(finding.severity)
        file_path = finding.file_path.replace("\\", "/")
        msg = f"{finding.rule_id}: {finding.message}"
        if finding.cwe:
            msg += f" ({finding.cwe})"

        # GitHub Actions annotation format
        print(f"::{level} file={file_path},line={finding.line_number}::{msg}")


def print_summary(result: ScanResult) -> None:
    """Print a markdown summary for GitHub Actions job summary."""
    lines = [
        "## Security Scan Results",
        "",
        f"**Grade:** {result.grade.value}",
        f"**Files scanned:** {result.total_files}",
        f"**Total findings:** {result.total_findings}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Error (critical) | {result.error_count} |",
        f"| Warning (high) | {result.warning_count} |",
        f"| Info (medium) | {result.info_count} |",
        "",
    ]

    if result.total_findings > 0:
        lines.append("### Top Findings")
        lines.append("")
        lines.append("| File | Line | Rule | Severity | CWE |")
        lines.append("|------|------|------|----------|-----|")

        for finding in result.all_findings[:20]:  # Limit to top 20
            sev = finding.severity.value.upper()
            lines.append(
                f"| {finding.file_path} | {finding.line_number} | "
                f"`{finding.rule_id}` | {sev} | {finding.cwe or '—'} |"
            )

    print("\n".join(lines))


def get_exit_code(result: ScanResult, fail_on: str = "error") -> int:
    """Return appropriate exit code for CI/CD.

    Args:
        fail_on: Minimum severity to fail on ("error", "warning", "info").
    """
    if fail_on == "error" and result.error_count > 0:
        return 2
    if fail_on == "warning" and (result.error_count > 0 or result.warning_count > 0):
        return 1
    if fail_on == "info" and result.total_findings > 0:
        return 1
    return 0


def _severity_to_annotation(severity: Severity) -> str:
    return {
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "notice",
        Severity.STYLE: "notice",
    }.get(severity, "notice")
