"""Tests for cross-file taint tracking."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.cross_file_taint import CrossFileTaintTracker

FIXTURES = Path(__file__).parent / "fixtures" / "cross_file"


class TestCrossFileTaintTracker:
    def test_detects_cross_file_sql_injection(self):
        """Taint flows: routes.py (request.args) → utils.py → db.py (cursor.execute)."""
        tracker = CrossFileTaintTracker()
        findings = tracker.analyze_project(str(FIXTURES))
        assert len(findings) >= 1
        sql_findings = [f for f in findings if "sql" in f.rule_id.lower()]
        assert len(sql_findings) >= 1
        # The finding should be in db.py where the sink is
        assert any("db.py" in f.file_path for f in sql_findings)

    def test_finding_has_cross_file_metadata(self):
        """Cross-file findings should have flow_type metadata."""
        tracker = CrossFileTaintTracker()
        findings = tracker.analyze_project(str(FIXTURES))
        assert len(findings) >= 1
        for f in findings:
            assert f.metadata.get("flow_type") == "cross-file"
            assert f.category == "cross-file-taint"

    def test_no_findings_on_clean_project(self, tmp_path):
        """Project with no taint sources should produce no findings."""
        (tmp_path / "a.py").write_text("def add(x, y): return x + y\n")
        (tmp_path / "b.py").write_text("from a import add\nresult = add(1, 2)\n")
        tracker = CrossFileTaintTracker()
        findings = tracker.analyze_project(str(tmp_path))
        assert findings == []

    def test_single_file_not_analyzed(self, tmp_path):
        """Single file project should return empty (need 2+ files)."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        tracker = CrossFileTaintTracker()
        findings = tracker.analyze_project(str(tmp_path))
        assert findings == []

    def test_module_map_excludes_dirs(self, tmp_path):
        """Excluded directories should be skipped."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_app.py").write_text("x = 1\n")
        tracker = CrossFileTaintTracker()
        tracker._build_module_map(str(tmp_path), exclude=["tests"])
        assert not any("test" in m for m in tracker._module_map)
