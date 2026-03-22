"""Enhanced SARIF 2.1.0 exporter for GitHub Code Scanning and GitLab SAST.

Produces fully compliant SARIF output with:
- Tool driver with version and rule definitions
- Per-rule help URIs linking to CWE entries
- Code flow / taint tracking information
- Severity → SARIF level mapping
- Fingerprint hashing for deduplication
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import Finding, ScanResult, Severity


def generate_sarif(result: ScanResult, output_path: str | None = None) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 report from scan results."""

    rules_map: dict[str, int] = {}
    sarif_rules: list[dict[str, Any]] = []
    sarif_results: list[dict[str, Any]] = []

    for finding in result.all_findings:
        # Build rules index (dedup by rule_id)
        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = len(sarif_rules)
            rule_entry: dict[str, Any] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.message[:200]},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {
                    "level": _severity_to_level(finding.severity),
                },
                "properties": {
                    "tags": [finding.category] if finding.category else [],
                    "precision": _confidence_to_precision(finding.confidence.value),
                },
            }
            if finding.cwe:
                rule_entry["helpUri"] = f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[-1]}.html"
                rule_entry["properties"]["tags"].append(finding.cwe)
            if finding.owasp:
                rule_entry["properties"]["tags"].append(finding.owasp)

            sarif_rules.append(rule_entry)

        # Build result entry
        sarif_result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rules_map[finding.rule_id],
            "level": _severity_to_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _normalize_path(finding.file_path),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, finding.line_number),
                        "startColumn": 1,
                        "snippet": {"text": finding.line_content} if finding.line_content else {},
                    },
                },
            }],
            "fingerprints": {
                "primaryLocationLineHash": _fingerprint(finding),
            },
        }

        # Add fix suggestion if available
        if finding.fix_suggestion:
            sarif_result["fixes"] = [{
                "description": {"text": finding.fix_suggestion},
            }]

        # Add taint metadata if present
        if finding.metadata.get("source") and finding.metadata.get("sink"):
            sarif_result["codeFlows"] = [{
                "message": {"text": f"Tainted data flows from {finding.metadata['source']} to {finding.metadata['sink']}"},
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {
                                "message": {"text": f"Source: {finding.metadata['source']}"},
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _normalize_path(finding.file_path)},
                                    "region": {"startLine": max(1, finding.line_number)},
                                },
                            },
                        },
                    ],
                }],
            }]

        sarif_results.append(sarif_result)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentic-ai-security",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/Krishcalin/Agentic-AI-Cyber-Security",
                    "rules": sarif_rules,
                },
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": result.start_time.isoformat() + "Z" if result.start_time else "",
                "endTimeUtc": result.end_time.isoformat() + "Z" if result.end_time else "",
            }],
            "automationDetails": {
                "id": f"agentic-scan/{result.scan_id}",
            },
        }],
    }

    if output_path:
        Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    return sarif


def _severity_to_level(severity: Severity) -> str:
    return {
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "note",
        Severity.STYLE: "note",
    }.get(severity, "note")


def _confidence_to_precision(confidence: str) -> str:
    return {"high": "very-high", "medium": "high", "low": "medium"}.get(confidence, "medium")


def _normalize_path(path: str) -> str:
    """Normalize file path to forward slashes for SARIF."""
    return path.replace("\\", "/").lstrip("./")


def _fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for deduplication."""
    data = f"{finding.rule_id}:{finding.file_path}:{finding.line_number}:{finding.line_content}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]
