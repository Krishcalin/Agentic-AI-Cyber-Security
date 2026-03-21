"""Tests for data models."""

from core.models import (
    Confidence,
    FileResult,
    Finding,
    Grade,
    Rule,
    ScanResult,
    Severity,
    detect_language,
)


class TestSeverity:
    def test_enum_values(self):
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"
        assert Severity.STYLE.value == "style"


class TestGrade:
    def test_enum_values(self):
        assert Grade.A.value == "A"
        assert Grade.F.value == "F"


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            rule_id="python.injection.sql",
            message="SQL injection",
            severity=Severity.ERROR,
            file_path="app.py",
            line_number=10,
        )
        assert f.location == "app.py:10"
        assert f.severity == Severity.ERROR

    def test_to_dict(self):
        f = Finding(
            rule_id="test.rule",
            message="test",
            severity=Severity.WARNING,
            file_path="test.py",
            line_number=1,
            cwe="CWE-89",
        )
        d = f.to_dict()
        assert d["rule_id"] == "test.rule"
        assert d["cwe"] == "CWE-89"
        assert d["severity"] == "warning"


class TestFileResult:
    def test_empty_result(self):
        r = FileResult(file_path="test.py", language="python")
        assert r.finding_count == 0
        assert r.has_findings is False
        assert r.max_severity == Severity.STYLE

    def test_with_findings(self):
        r = FileResult(
            file_path="test.py",
            language="python",
            findings=[
                Finding(rule_id="r1", message="m", severity=Severity.ERROR, file_path="test.py", line_number=1),
                Finding(rule_id="r2", message="m", severity=Severity.WARNING, file_path="test.py", line_number=2),
            ],
        )
        assert r.finding_count == 2
        assert r.has_findings is True
        assert r.max_severity == Severity.ERROR


class TestScanResult:
    def test_empty_scan(self):
        r = ScanResult(scan_id="test")
        assert r.total_findings == 0
        assert r.error_count == 0

    def test_to_dict(self):
        r = ScanResult(scan_id="test", target="myapp")
        d = r.to_dict()
        assert d["scan_id"] == "test"
        assert d["total_findings"] == 0


class TestDetectLanguage:
    def test_python(self):
        assert detect_language("app.py") == "python"

    def test_javascript(self):
        assert detect_language("app.js") == "javascript"

    def test_typescript(self):
        assert detect_language("app.ts") == "typescript"

    def test_java(self):
        assert detect_language("App.java") == "java"

    def test_go(self):
        assert detect_language("main.go") == "go"

    def test_dockerfile(self):
        assert detect_language("Dockerfile") == "dockerfile"

    def test_unknown(self):
        assert detect_language("README.md") == "unknown"

    def test_terraform(self):
        assert detect_language("main.tf") == "terraform"
