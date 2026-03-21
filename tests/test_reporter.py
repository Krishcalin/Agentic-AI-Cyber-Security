"""Tests for reporters."""

import json

from core.models import FileResult, Finding, Grade, ScanResult, Severity
from core.reporter import JsonReporter, SarifReporter, TerminalReporter


def _make_result() -> ScanResult:
    return ScanResult(
        scan_id="test01",
        target="myapp",
        file_results=[
            FileResult(
                file_path="app.py",
                language="python",
                findings=[
                    Finding(
                        rule_id="python.injection.sql",
                        message="SQL injection",
                        severity=Severity.ERROR,
                        file_path="app.py",
                        line_number=10,
                        line_content='cursor.execute(f"SELECT * FROM {table}")',
                        cwe="CWE-89",
                    ),
                    Finding(
                        rule_id="python.crypto.weak-hash",
                        message="Weak hash",
                        severity=Severity.WARNING,
                        file_path="app.py",
                        line_number=20,
                        cwe="CWE-328",
                    ),
                ],
            ),
        ],
    )


class TestJsonReporter:
    def test_generate_json(self):
        reporter = JsonReporter()
        result = _make_result()
        output = reporter.generate(result)
        data = json.loads(output)
        assert data["scan_id"] == "test01"
        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2

    def test_write_to_file(self, tmp_path):
        reporter = JsonReporter()
        result = _make_result()
        path = str(tmp_path / "report.json")
        reporter.generate(result, output_path=path)
        data = json.loads(open(path).read())
        assert data["total_findings"] == 2


class TestSarifReporter:
    def test_generate_sarif(self):
        reporter = SarifReporter()
        result = _make_result()
        sarif = reporter.generate(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 2

    def test_sarif_severity_mapping(self):
        reporter = SarifReporter()
        result = _make_result()
        sarif = reporter.generate(result)
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        assert "error" in levels
        assert "warning" in levels

    def test_write_to_file(self, tmp_path):
        reporter = SarifReporter()
        result = _make_result()
        path = str(tmp_path / "results.sarif")
        reporter.generate(result, output_path=path)
        data = json.loads(open(path).read())
        assert data["version"] == "2.1.0"


class TestTerminalReporter:
    def test_print_result(self):
        """Should not raise."""
        reporter = TerminalReporter()
        result = _make_result()
        reporter.print_result(result)

    def test_empty_result(self):
        reporter = TerminalReporter()
        result = ScanResult(scan_id="empty", target="none")
        reporter.print_result(result)

    def test_verbosity_levels(self):
        for verbosity in ["minimal", "compact", "full"]:
            reporter = TerminalReporter(verbosity=verbosity)
            result = _make_result()
            reporter.print_result(result)
