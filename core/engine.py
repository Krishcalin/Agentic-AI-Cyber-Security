"""Main scanner orchestrator — coordinates engines, rules, and reporting."""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path

import structlog

from core.grader import calculate_grade
from core.models import FileResult, ScanResult, detect_language
from core.pattern_matcher import PatternMatcher

log = structlog.get_logger("engine")


class ScanEngine:
    """Main scanner that orchestrates pattern matching, grading, and results."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.pattern_matcher = PatternMatcher(rules_dir)
        self.rules_loaded = 0

    def initialize(self) -> int:
        """Load rules and prepare engines. Returns rules loaded count."""
        self.rules_loaded = self.pattern_matcher.load_rules()
        log.info("engine_initialized", rules=self.rules_loaded)
        return self.rules_loaded

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file."""
        if not self.rules_loaded:
            self.initialize()

        start = datetime.now()
        file_result = self.pattern_matcher.scan_file(file_path)

        result = ScanResult(
            scan_id=uuid.uuid4().hex[:8],
            target=file_path,
            file_results=[file_result],
            start_time=start,
            end_time=datetime.now(),
            rules_loaded=self.rules_loaded,
            total_files=1,
            total_lines=file_result.lines_scanned,
        )
        result.grade = calculate_grade(result)
        return result

    def scan_project(self, directory: str, exclude: list[str] | None = None) -> ScanResult:
        """Scan an entire project directory."""
        if not self.rules_loaded:
            self.initialize()

        start = datetime.now()
        file_results = self.pattern_matcher.scan_directory(directory, exclude)

        result = ScanResult(
            scan_id=uuid.uuid4().hex[:8],
            target=directory,
            file_results=file_results,
            start_time=start,
            end_time=datetime.now(),
            rules_loaded=self.rules_loaded,
            total_files=len(file_results),
            total_lines=sum(fr.lines_scanned for fr in file_results),
        )
        result.grade = calculate_grade(result)

        log.info(
            "scan_complete",
            target=directory,
            files=result.total_files,
            findings=result.total_findings,
            grade=result.grade.value,
        )
        return result

    def scan_content(self, content: str, language: str, filename: str = "<stdin>") -> ScanResult:
        """Scan a string of code content directly."""
        if not self.rules_loaded:
            self.initialize()

        import tempfile
        import os

        ext_map = {"python": ".py", "javascript": ".js", "java": ".java", "go": ".go"}
        ext = ext_map.get(language, ".txt")

        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            result = self.scan_file(tmp_path)
            result.target = filename
            # Fix file paths in findings
            for fr in result.file_results:
                fr.file_path = filename
                for finding in fr.findings:
                    finding.file_path = filename
            return result
        finally:
            os.unlink(tmp_path)
