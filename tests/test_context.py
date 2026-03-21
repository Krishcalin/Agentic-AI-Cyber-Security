"""Tests for context-aware filtering."""

from core.context import ContextFilter, Framework, ProjectContext
from core.models import Confidence, Finding, Severity


def make_finding(rule_id: str = "test.rule", file_path: str = "app.py",
                 severity: Severity = Severity.WARNING,
                 confidence: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="test",
        severity=severity,
        file_path=file_path,
        line_number=1,
        confidence=confidence,
    )


class TestIsTestFile:
    def test_test_prefix(self):
        f = ContextFilter()
        assert f.is_test_file("tests/test_app.py") is True
        assert f.is_test_file("test_utils.py") is True

    def test_test_directory(self):
        f = ContextFilter()
        assert f.is_test_file("tests/conftest.py") is True
        assert f.is_test_file("spec/helpers.py") is True

    def test_fixture_directory(self):
        f = ContextFilter()
        assert f.is_test_file("tests/fixtures/sample.py") is True

    def test_regular_file(self):
        f = ContextFilter()
        assert f.is_test_file("app.py") is False
        assert f.is_test_file("core/engine.py") is False


class TestFilterFindings:
    def test_exclude_test_files(self):
        f = ContextFilter()
        findings = [
            make_finding(file_path="app.py"),
            make_finding(file_path="tests/test_app.py"),
        ]
        filtered = f.filter_findings(findings, exclude_tests=True)
        assert len(filtered) == 1
        assert filtered[0].file_path == "app.py"

    def test_include_test_files(self):
        f = ContextFilter()
        findings = [
            make_finding(file_path="app.py"),
            make_finding(file_path="tests/test_app.py"),
        ]
        filtered = f.filter_findings(findings, exclude_tests=False)
        assert len(filtered) == 2

    def test_filter_by_confidence(self):
        f = ContextFilter()
        findings = [
            make_finding(confidence=Confidence.HIGH),
            make_finding(confidence=Confidence.LOW),
        ]
        filtered = f.filter_findings(findings, min_confidence="medium")
        assert len(filtered) == 1
        assert filtered[0].confidence == Confidence.HIGH

    def test_context_suppression_cli_subprocess(self):
        f = ContextFilter()
        ctx = ProjectContext(project_type="cli")
        findings = [
            make_finding(rule_id="python.ast.subprocess-shell", severity=Severity.WARNING),
        ]
        filtered = f.filter_findings(findings, context=ctx)
        assert len(filtered) == 0  # Suppressed for CLI tools

    def test_context_no_suppression_for_errors(self):
        f = ContextFilter()
        ctx = ProjectContext(project_type="cli")
        findings = [
            make_finding(rule_id="python.ast.subprocess-shell", severity=Severity.ERROR),
        ]
        filtered = f.filter_findings(findings, context=ctx)
        assert len(filtered) == 1  # Errors never suppressed


class TestProjectContext:
    def test_default_context(self):
        ctx = ProjectContext()
        assert ctx.framework == Framework.UNKNOWN
        assert ctx.project_type == "unknown"

    def test_web_context(self):
        ctx = ProjectContext(framework=Framework.FLASK, project_type="web", has_web_server=True)
        assert ctx.has_web_server is True
