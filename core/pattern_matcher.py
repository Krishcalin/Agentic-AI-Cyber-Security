"""Regex-based pattern matching engine for vulnerability detection."""

from __future__ import annotations

import re
import time
from pathlib import Path

import structlog

from core.models import (
    Confidence,
    FileResult,
    Finding,
    Rule,
    Severity,
    detect_language,
)
from core.rule_loader import RuleLoader

log = structlog.get_logger("pattern_matcher")


class PatternMatcher:
    """Scans source files against YAML-defined regex security rules."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.loader = RuleLoader(rules_dir)
        self.rules: list[Rule] = []
        self._compiled: dict[str, list[re.Pattern]] = {}

    def load_rules(self) -> int:
        """Load and compile all rules. Returns count loaded."""
        self.rules = self.loader.load_all()
        self._compile_patterns()
        return len(self.rules)

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        self._compiled = {}
        for rule in self.rules:
            compiled = []
            for pattern in rule.patterns:
                try:
                    compiled.append(re.compile(pattern))
                except re.error as e:
                    log.warning("pattern_compile_error", rule=rule.id, pattern=pattern, error=str(e))
            self._compiled[rule.id] = compiled

    def scan_file(self, file_path: str) -> FileResult:
        """Scan a single file and return findings."""
        language = detect_language(file_path)
        result = FileResult(file_path=file_path, language=language)
        start = time.time()

        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError) as e:
            result.error = str(e)
            return result

        lines = content.splitlines()
        result.lines_scanned = len(lines)

        # Get applicable rules
        applicable = [r for r in self.rules if language in r.languages or "any" in r.languages]

        for rule in applicable:
            compiled_patterns = self._compiled.get(rule.id, [])
            for i, line in enumerate(lines, 1):
                # Skip comment lines
                stripped = line.strip()
                if self._is_comment(stripped, language):
                    continue

                # Support # nosec inline suppression
                if "# nosec" in line or "// nosec" in line or "/* nosec" in line:
                    continue

                for pattern in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        finding = Finding(
                            rule_id=rule.id,
                            message=rule.message,
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=i,
                            line_content=line.rstrip(),
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            confidence=rule.confidence,
                            fix_template=rule.fix_template,
                            language=language,
                            category=rule.category,
                            metadata=rule.metadata,
                        )
                        result.findings.append(finding)
                        break  # One match per rule per line

        result.scan_time_ms = (time.time() - start) * 1000
        log.debug(
            "file_scanned",
            file=file_path,
            language=language,
            findings=result.finding_count,
            time_ms=f"{result.scan_time_ms:.1f}",
        )
        return result

    def scan_directory(self, directory: str, exclude_patterns: list[str] | None = None) -> list[FileResult]:
        """Scan all supported files in a directory."""
        results: list[FileResult] = []
        exclude = exclude_patterns or [
            "__pycache__", "node_modules", ".git", ".venv", "venv",
            "dist", "build", ".eggs", ".tox", ".mypy_cache",
        ]

        dir_path = Path(directory)
        if not dir_path.exists():
            log.error("directory_not_found", path=directory)
            return results

        for file_path in sorted(dir_path.rglob("*")):
            if not file_path.is_file():
                continue
            if any(exc in file_path.parts for exc in exclude):
                continue

            language = detect_language(str(file_path))
            if language == "unknown":
                continue

            result = self.scan_file(str(file_path))
            results.append(result)

        return results

    @staticmethod
    def _is_comment(line: str, language: str) -> bool:
        """Check if a line is a comment."""
        if not line:
            return True
        match language:
            case "python" | "ruby" | "yaml" | "terraform":
                return line.startswith("#")
            case "javascript" | "typescript" | "java" | "go" | "c" | "cpp" | "rust" | "php":
                return line.startswith("//") or line.startswith("/*") or line.startswith("*")
            case _:
                return line.startswith("#") or line.startswith("//")
