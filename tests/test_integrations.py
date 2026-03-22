"""Tests for CI/CD integrations — SARIF, GitHub Actions, exit codes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from core.models import (
    FileResult, Finding, Grade, ScanResult, Severity, Confidence,
)
from integrations.sarif_exporter import generate_sarif, _fingerprint, _normalize_path
from integrations.github_actions import get_exit_code, print_annotations, print_summary


def _make_result() -> ScanResult:
    return ScanResult(
        scan_id="ci01",
        target="./myapp",
        start_time=datetime(2026, 3, 22, 10, 0, 0),
        end_time=datetime(2026, 3, 22, 10, 0, 5),
        total_files=3,
        total_lines=500,
        file_results=[
            FileResult(
                file_path="app.py",
                language="python",
                findings=[
                    Finding(
                        rule_id="python.injection.sql",
                        message="SQL injection via f-string",
                        severity=Severity.ERROR,
                        file_path="app.py",
                        line_number=42,
                        line_content='cursor.execute(f"SELECT * FROM {table}")',
                        cwe="CWE-89",
                        owasp="A03:2021",
                        confidence=Confidence.HIGH,
                        category="injection",
                    ),
                    Finding(
                        rule_id="python.crypto.weak-hash",
                        message="MD5 hash used",
                        severity=Severity.WARNING,
                        file_path="app.py",
                        line_number=18,
                        cwe="CWE-328",
                        confidence=Confidence.HIGH,
                        category="crypto",
                    ),
                ],
            ),
            FileResult(
                file_path="utils.js",
                language="javascript",
                findings=[
                    Finding(
                        rule_id="javascript.xss.innerhtml",
                        message="innerHTML assignment",
                        severity=Severity.ERROR,
                        file_path="utils.js",
                        line_number=10,
                        cwe="CWE-79",
                        confidence=Confidence.HIGH,
                        category="xss",
                    ),
                ],
            ),
        ],
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(scan_id="clean", target="./safe", total_files=2, total_lines=100)


# ── SARIF Exporter ─────────────────────────────────────────────────────────


class TestSarifExporter:
    def test_valid_sarif_structure(self):
        sarif = generate_sarif(_make_result())
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_results_count(self):
        sarif = generate_sarif(_make_result())
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_rules_deduplicated(self):
        sarif = generate_sarif(_make_result())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))

    def test_severity_mapping(self):
        sarif = generate_sarif(_make_result())
        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels
        assert "warning" in levels

    def test_cwe_in_help_uri(self):
        sarif = generate_sarif(_make_result())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sql_rule = [r for r in rules if r["id"] == "python.injection.sql"][0]
        assert "cwe.mitre.org" in sql_rule["helpUri"]

    def test_fingerprints(self):
        sarif = generate_sarif(_make_result())
        for result in sarif["runs"][0]["results"]:
            assert "fingerprints" in result
            assert "primaryLocationLineHash" in result["fingerprints"]

    def test_tool_info(self):
        sarif = generate_sarif(_make_result())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "agentic-ai-security"
        assert driver["version"] == "0.1.0"
        assert "informationUri" in driver

    def test_invocation_times(self):
        sarif = generate_sarif(_make_result())
        inv = sarif["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True
        assert "startTimeUtc" in inv

    def test_write_to_file(self, tmp_path):
        path = str(tmp_path / "results.sarif")
        generate_sarif(_make_result(), output_path=path)
        data = json.loads(open(path).read())
        assert data["version"] == "2.1.0"

    def test_empty_result(self):
        sarif = generate_sarif(_make_clean_result())
        assert len(sarif["runs"][0]["results"]) == 0

    def test_taint_metadata_codeflows(self):
        result = ScanResult(scan_id="taint", target="test", file_results=[
            FileResult(file_path="app.py", language="python", findings=[
                Finding(
                    rule_id="python.taint.sql_injection",
                    message="Tainted SQL",
                    severity=Severity.ERROR,
                    file_path="app.py",
                    line_number=5,
                    cwe="CWE-89",
                    confidence=Confidence.HIGH,
                    metadata={"source": "request.args", "sink": "cursor.execute"},
                ),
            ]),
        ])
        sarif = generate_sarif(result)
        assert "codeFlows" in sarif["runs"][0]["results"][0]


class TestNormalizePath:
    def test_forward_slashes(self):
        assert _normalize_path("src\\app.py") == "src/app.py"

    def test_strip_dot_slash(self):
        assert _normalize_path("./src/app.py") == "src/app.py"


class TestFingerprint:
    def test_deterministic(self):
        f = Finding(rule_id="test", message="msg", severity=Severity.ERROR,
                    file_path="app.py", line_number=1, line_content="code")
        assert _fingerprint(f) == _fingerprint(f)

    def test_different_for_different_findings(self):
        f1 = Finding(rule_id="test1", message="msg", severity=Severity.ERROR,
                     file_path="app.py", line_number=1)
        f2 = Finding(rule_id="test2", message="msg", severity=Severity.ERROR,
                     file_path="app.py", line_number=2)
        assert _fingerprint(f1) != _fingerprint(f2)


# ── GitHub Actions ─────────────────────────────────────────────────────────


class TestGitHubActions:
    def test_annotations(self, capsys):
        print_annotations(_make_result())
        output = capsys.readouterr().out
        assert "::error" in output
        assert "::warning" in output
        assert "app.py" in output

    def test_summary(self, capsys):
        print_summary(_make_result())
        output = capsys.readouterr().out
        assert "Security Scan Results" in output
        assert "Grade" in output

    def test_summary_empty(self, capsys):
        print_summary(_make_clean_result())
        output = capsys.readouterr().out
        assert "0" in output


class TestExitCodes:
    def test_exit_0_clean(self):
        assert get_exit_code(_make_clean_result()) == 0

    def test_exit_2_errors(self):
        assert get_exit_code(_make_result(), fail_on="error") == 2

    def test_exit_1_warnings(self):
        assert get_exit_code(_make_result(), fail_on="warning") == 1

    def test_exit_0_only_info(self):
        result = ScanResult(scan_id="t", target="t", file_results=[
            FileResult(file_path="a.py", language="python", findings=[
                Finding(rule_id="r", message="m", severity=Severity.INFO,
                        file_path="a.py", line_number=1),
            ]),
        ])
        assert get_exit_code(result, fail_on="error") == 0
        assert get_exit_code(result, fail_on="warning") == 0
        assert get_exit_code(result, fail_on="info") == 1
