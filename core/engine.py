"""Main scanner orchestrator — coordinates engines, rules, and reporting."""

from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import structlog

from core.ast_analyzer import ASTAnalyzer
from core.context import ContextFilter, ProjectContext
from core.cross_file_taint import CrossFileTaintTracker
from core.grader import calculate_grade
from core.js_ast_analyzer import JSASTAnalyzer
from core.models import FileResult, Finding, ScanResult, detect_language
from core.pattern_matcher import PatternMatcher
from core.taint_tracker import TaintTracker

log = structlog.get_logger("engine")


class ScanEngine:
    """Main scanner that orchestrates pattern matching, AST analysis,
    taint tracking, grading, and context-aware filtering."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self._rules_dir = rules_dir
        self.pattern_matcher = PatternMatcher(rules_dir)
        self.ast_analyzer = ASTAnalyzer()
        self.js_ast_analyzer = JSASTAnalyzer()
        self.taint_tracker = TaintTracker()
        self.cross_file_taint = CrossFileTaintTracker()
        self.context_filter = ContextFilter()
        self.rules_loaded = 0

    def initialize(self) -> int:
        """Load rules and prepare engines. Returns rules loaded count."""
        self.rules_loaded = self.pattern_matcher.load_rules()
        log.info("engine_initialized", rules=self.rules_loaded, engines=["pattern", "ast", "taint"])
        return self.rules_loaded

    def scan_file(self, file_path: str, context: ProjectContext | None = None) -> ScanResult:
        """Scan a single file with all engines."""
        if not self.rules_loaded:
            self.initialize()

        start = datetime.now()
        language = detect_language(file_path)

        # Engine 1: Pattern matching (all languages)
        pattern_result = self.pattern_matcher.scan_file(file_path)

        # Engine 2 & 3: AST + Taint (Python only)
        ast_findings: list[Finding] = []
        taint_findings: list[Finding] = []
        if language == "python":
            ast_result = self.ast_analyzer.analyze_file(file_path)
            ast_findings = ast_result.findings

            taint_result = self.taint_tracker.analyze_file(file_path)
            taint_findings = taint_result.findings
        elif language in ("javascript", "typescript"):
            js_result = self.js_ast_analyzer.analyze_file(file_path)
            ast_findings = js_result.findings

        # Merge and deduplicate findings
        all_findings = self._merge_findings(
            pattern_result.findings, ast_findings, taint_findings
        )

        # Context-aware filtering
        if context:
            all_findings = self.context_filter.filter_findings(all_findings, context)

        # Build merged FileResult
        merged = FileResult(
            file_path=file_path,
            language=language,
            findings=all_findings,
            lines_scanned=pattern_result.lines_scanned,
            scan_time_ms=pattern_result.scan_time_ms,
        )

        result = ScanResult(
            scan_id=uuid.uuid4().hex[:8],
            target=file_path,
            file_results=[merged],
            start_time=start,
            end_time=datetime.now(),
            rules_loaded=self.rules_loaded,
            total_files=1,
            total_lines=merged.lines_scanned,
        )
        result.grade = calculate_grade(result)
        return result

    def scan_project(
        self,
        directory: str,
        exclude: list[str] | None = None,
        exclude_tests: bool = False,
    ) -> ScanResult:
        """Scan an entire project directory with all engines."""
        if not self.rules_loaded:
            self.initialize()

        start = datetime.now()

        # Auto-exclude rules directory if scanning own project
        exclude = list(exclude or [])
        rules_dir = Path(self._rules_dir).resolve()
        scan_dir = Path(directory).resolve()
        if rules_dir.is_relative_to(scan_dir):
            rel_rules = str(rules_dir.relative_to(scan_dir))
            if rel_rules not in exclude:
                exclude.append(rel_rules)

        # Detect project context for smart filtering
        context = self.context_filter.detect_project_context(directory)

        # Pattern match all supported files
        pattern_results = self.pattern_matcher.scan_directory(directory, exclude)

        # Enhance Python files with AST + taint analysis
        file_results: list[FileResult] = []
        for pr in pattern_results:
            if pr.language == "python" and not pr.error:
                # Run AST analyzer
                ast_result = self.ast_analyzer.analyze_file(pr.file_path)
                # Run taint tracker
                taint_result = self.taint_tracker.analyze_file(pr.file_path)

                # Merge
                merged_findings = self._merge_findings(
                    pr.findings, ast_result.findings, taint_result.findings
                )

                # Context filter
                merged_findings = self.context_filter.filter_findings(
                    merged_findings, context, exclude_tests=exclude_tests
                )

                file_results.append(FileResult(
                    file_path=pr.file_path,
                    language=pr.language,
                    findings=merged_findings,
                    lines_scanned=pr.lines_scanned,
                    scan_time_ms=pr.scan_time_ms,
                ))
            elif pr.language in ("javascript", "typescript") and not pr.error:
                # Run JS AST analyzer
                js_result = self.js_ast_analyzer.analyze_file(pr.file_path)
                merged_findings = self._merge_findings(pr.findings, js_result.findings)
                merged_findings = self.context_filter.filter_findings(
                    merged_findings, context, exclude_tests=exclude_tests
                )
                file_results.append(FileResult(
                    file_path=pr.file_path,
                    language=pr.language,
                    findings=merged_findings,
                    lines_scanned=pr.lines_scanned,
                    scan_time_ms=pr.scan_time_ms,
                ))
            else:
                # Other languages: pattern results only, still apply context filter
                filtered = self.context_filter.filter_findings(
                    pr.findings, context, exclude_tests=exclude_tests
                )
                pr.findings = filtered
                file_results.append(pr)

        # Cross-file taint analysis
        try:
            cross_findings = self.cross_file_taint.analyze_project(directory, exclude)
            if cross_findings:
                # Add cross-file findings to the relevant file results
                cross_by_file: dict[str, list[Finding]] = {}
                for cf in cross_findings:
                    cross_by_file.setdefault(cf.file_path, []).append(cf)
                for fr in file_results:
                    abs_path = str(Path(fr.file_path).resolve())
                    if abs_path in cross_by_file:
                        fr.findings.extend(cross_by_file[abs_path])
        except Exception as e:
            log.warning("cross_file_taint_error", error=str(e))

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
            framework=context.framework,
        )
        return result

    def scan_content(self, content: str, language: str, filename: str = "<stdin>") -> ScanResult:
        """Scan a string of code content directly."""
        if not self.rules_loaded:
            self.initialize()

        ext_map = {"python": ".py", "javascript": ".js", "java": ".java", "go": ".go"}
        ext = ext_map.get(language, ".txt")

        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            result = self.scan_file(tmp_path)
            result.target = filename
            for fr in result.file_results:
                fr.file_path = filename
                for finding in fr.findings:
                    finding.file_path = filename
            return result
        finally:
            os.unlink(tmp_path)

    def _merge_findings(
        self,
        pattern_findings: list[Finding],
        ast_findings: list[Finding],
        taint_findings: list[Finding],
    ) -> list[Finding]:
        """Merge findings from all engines, deduplicating overlaps.

        Priority: taint > ast > pattern (taint is highest confidence).
        If multiple engines flag the same line+CWE, keep the highest-confidence one.
        """
        seen: dict[str, Finding] = {}  # key: "line:cwe" → best finding

        # Add in priority order (later overwrites lower priority)
        for finding in pattern_findings:
            key = f"{finding.file_path}:{finding.line_number}:{finding.cwe}"
            seen[key] = finding

        for finding in ast_findings:
            key = f"{finding.file_path}:{finding.line_number}:{finding.cwe}"
            existing = seen.get(key)
            if not existing or finding.confidence.value >= existing.confidence.value:
                seen[key] = finding

        for finding in taint_findings:
            key = f"{finding.file_path}:{finding.line_number}:{finding.cwe}"
            seen[key] = finding  # Taint always wins — highest confidence

        return list(seen.values())
