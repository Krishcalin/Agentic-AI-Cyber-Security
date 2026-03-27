"""Self-scan: validate the scanner against its own codebase."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from core.engine import ScanEngine


def main() -> None:
    e = ScanEngine("rules")
    e.initialize()

    result = e.scan_project(
        ".",
        exclude=[".git", "__pycache__", ".venv", "node_modules", "tests", "evidence", "reports"],
    )

    print(f"Files scanned: {result.total_files}")
    print(f"Total findings: {result.total_findings}")
    print(f"Grade: {result.grade.value}")
    print()

    by_rule: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    for f in result.all_findings:
        by_rule[f.rule_id] += 1
        by_severity[f.severity.value] += 1

    print("=== Findings by severity ===")
    for sev, count in by_severity.most_common():
        print(f"  {sev}: {count}")

    print("\n=== Findings by rule (top 20) ===")
    for rule, count in by_rule.most_common(20):
        print(f"  {rule}: {count}")

    base = Path(".").resolve()
    print("\n=== All findings ===")
    for f in result.all_findings:
        try:
            rel = Path(f.file_path).resolve().relative_to(base)
        except ValueError:
            rel = f.file_path
        print(f"  {f.rule_id} [{f.severity.value}] {rel}:{f.line_number}")
        print(f"    {f.line_content.strip()[:100]}")

    # Export for analysis
    out = Path("benchmarks/self_scan_results.json")
    out.parent.mkdir(exist_ok=True)
    findings_data = []
    for f in result.all_findings:
        try:
            rel = str(Path(f.file_path).resolve().relative_to(base))
        except ValueError:
            rel = f.file_path
        findings_data.append({
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "file": rel,
            "line": f.line_number,
            "content": f.line_content.strip()[:200],
            "cwe": f.cwe,
        })
    out.write_text(json.dumps({"total": result.total_findings, "grade": result.grade.value,
                                "findings": findings_data}, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    main()
