"""Data models for the security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    ERROR = "error"         # Critical vulnerability — must fix
    WARNING = "warning"     # High risk — should fix
    INFO = "info"           # Informational — review recommended
    STYLE = "style"         # Code quality / best practice


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class RuleMatch:
    """A single pattern match within a rule."""
    pattern: str
    line_number: int
    line_content: str
    match_text: str = ""


@dataclass
class Finding:
    """A single security finding from scanning a file."""
    rule_id: str
    message: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str = ""
    cwe: str = ""
    owasp: str = ""
    confidence: Confidence = Confidence.HIGH
    fix_template: str = ""
    fix_suggestion: str = ""
    language: str = ""
    category: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line_number}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence.value,
            "fix_suggestion": self.fix_suggestion,
            "language": self.language,
            "category": self.category,
        }


@dataclass
class Rule:
    """A security scanning rule loaded from YAML."""
    id: str
    languages: list[str]
    severity: Severity
    message: str
    patterns: list[str]
    cwe: str = ""
    owasp: str = ""
    confidence: Confidence = Confidence.HIGH
    fix_template: str = ""
    category: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def language(self) -> str:
        return self.languages[0] if self.languages else "any"


@dataclass
class FileResult:
    """Scan results for a single file."""
    file_path: str
    language: str
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    lines_scanned: int = 0
    error: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.STYLE
        order = [Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.STYLE]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return Severity.STYLE


@dataclass
class ScanResult:
    """Aggregated results from a complete scan."""
    scan_id: str = ""
    target: str = ""
    profile: str = "quick"
    file_results: list[FileResult] = field(default_factory=list)
    grade: Grade = Grade.A
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    rules_loaded: int = 0
    total_files: int = 0
    total_lines: int = 0

    @property
    def total_findings(self) -> int:
        return sum(fr.finding_count for fr in self.file_results)

    @property
    def error_count(self) -> int:
        return sum(1 for fr in self.file_results for f in fr.findings if f.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for fr in self.file_results for f in fr.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for fr in self.file_results for f in fr.findings if f.severity == Severity.INFO)

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for fr in self.file_results:
            findings.extend(fr.findings)
        return findings

    @property
    def duration_seconds(self) -> float:
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "grade": self.grade.value,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "total_findings": self.total_findings,
            "errors": self.error_count,
            "warnings": self.warning_count,
            "infos": self.info_count,
            "duration_seconds": self.duration_seconds,
            "rules_loaded": self.rules_loaded,
            "findings": [f.to_dict() for f in self.all_findings],
        }


# Language detection mapping
LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
}


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    p = Path(file_path)
    if p.name.lower() in ("dockerfile", "containerfile"):
        return "dockerfile"
    return LANGUAGE_EXTENSIONS.get(p.suffix.lower(), "unknown")
