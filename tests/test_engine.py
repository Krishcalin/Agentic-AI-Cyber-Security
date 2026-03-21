"""Tests for scan engine."""

import os

from core.engine import ScanEngine
from core.models import Grade, Severity


class TestScanEngine:
    def test_initialize(self, engine: ScanEngine):
        assert engine.rules_loaded > 0

    def test_scan_file(self, engine: ScanEngine, python_fixture: str):
        result = engine.scan_file(python_fixture)
        assert result.total_files == 1
        assert result.total_findings > 0
        assert result.scan_id != ""
        assert result.grade in Grade

    def test_scan_project(self, engine: ScanEngine):
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        result = engine.scan_project(fixtures_dir)
        assert result.total_files >= 2
        assert result.total_findings > 0

    def test_scan_content(self, engine: ScanEngine):
        code = 'password = "SuperSecret123!"\neval(user_input)\n'
        result = engine.scan_content(code, "python", "test.py")
        assert result.total_findings > 0
        assert result.target == "test.py"

    def test_grade_assigned(self, engine: ScanEngine, python_fixture: str):
        result = engine.scan_file(python_fixture)
        # Vulnerable fixture should not get grade A
        assert result.grade != Grade.A


class TestGrading:
    def test_import(self):
        from core.grader import calculate_grade, calculate_score, grade_label
        from core.models import ScanResult
        r = ScanResult(scan_id="test")
        assert calculate_grade(r) == Grade.A
        assert calculate_score(r) == 100
        assert "Excellent" in grade_label(Grade.A)
