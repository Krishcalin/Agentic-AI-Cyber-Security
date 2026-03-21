"""A-F security grading system."""

from __future__ import annotations

from core.models import Grade, ScanResult, Severity


def calculate_grade(result: ScanResult) -> Grade:
    """Calculate security grade based on findings.

    Grading criteria:
        A (90-100): No critical/high, ≤2 medium
        B (75-89):  No critical, ≤2 high, ≤5 medium
        C (60-74):  No critical, ≤5 high
        D (40-59):  ≤2 critical, any high/medium
        F (0-39):   3+ critical findings
    """
    errors = result.error_count      # critical
    warnings = result.warning_count  # high
    infos = result.info_count        # medium/info

    if errors >= 3:
        return Grade.F
    if errors >= 1:
        return Grade.D
    if warnings > 5:
        return Grade.C
    if warnings > 2 or infos > 5:
        return Grade.B
    if warnings <= 2 and infos <= 2:
        return Grade.A
    return Grade.B


def calculate_score(result: ScanResult) -> int:
    """Calculate a numeric score 0-100."""
    errors = result.error_count
    warnings = result.warning_count
    infos = result.info_count

    # Start at 100, deduct points
    score = 100
    score -= errors * 25       # Critical: -25 each
    score -= warnings * 10     # High: -10 each
    score -= infos * 3         # Medium/Info: -3 each

    return max(0, min(100, score))


def grade_label(grade: Grade) -> str:
    """Return a human-readable label for a grade."""
    labels = {
        Grade.A: "Excellent — no significant issues",
        Grade.B: "Good — minor issues to address",
        Grade.C: "Fair — several issues need attention",
        Grade.D: "Poor — critical issues present",
        Grade.F: "Failing — immediate remediation required",
    }
    return labels.get(grade, "Unknown")
