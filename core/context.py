"""Context-aware filtering — framework detection, test exclusion, and
intent classification for reducing false positives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Finding, Severity

log = structlog.get_logger("context")


class Framework:
    """Detected framework identifiers."""
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    EXPRESS = "express"
    REACT = "react"
    UNKNOWN = "unknown"


@dataclass
class ProjectContext:
    """Detected project context for intelligent filtering."""
    framework: str = Framework.UNKNOWN
    is_test_heavy: bool = False
    has_web_server: bool = False
    has_database: bool = False
    has_cli: bool = False
    project_type: str = "unknown"   # "web", "cli", "library", "script"
    detected_from: list[str] = field(default_factory=list)


class ContextFilter:
    """Applies context-aware filtering to reduce false positives."""

    TEST_INDICATORS = {
        "test_", "tests/", "test/", "_test.py", "spec/", "specs/",
        "conftest.py", "fixtures/", "mock", "__tests__",
    }

    FRAMEWORK_INDICATORS: dict[str, list[str]] = {
        Framework.DJANGO: [
            "django", "from django", "import django", "INSTALLED_APPS",
            "manage.py", "settings.py", "urls.py", "wsgi.py",
        ],
        Framework.FLASK: [
            "from flask", "import flask", "Flask(__name__)",
            "app.route", "@app.route", "Blueprint",
        ],
        Framework.FASTAPI: [
            "from fastapi", "import fastapi", "FastAPI()",
            "APIRouter", "@app.get", "@app.post",
        ],
        Framework.EXPRESS: [
            "require('express')", "from 'express'", "express()",
            "app.listen", "Router()",
        ],
        Framework.REACT: [
            "import React", "from 'react'", "useState",
            "useEffect", "ReactDOM", "jsx",
        ],
    }

    def detect_project_context(self, directory: str) -> ProjectContext:
        """Detect project context from files in a directory."""
        ctx = ProjectContext()
        dir_path = Path(directory)

        # Check common indicator files
        indicators: dict[str, str] = {}
        for p in dir_path.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            rel = str(p.relative_to(dir_path))

            # Framework detection from filenames
            if name in ("manage.py", "wsgi.py", "asgi.py"):
                ctx.framework = Framework.DJANGO
                ctx.detected_from.append(f"file: {name}")
            elif name == "package.json":
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    if "express" in content:
                        ctx.framework = Framework.EXPRESS
                        ctx.detected_from.append("package.json: express")
                    elif "react" in content:
                        ctx.framework = Framework.REACT
                        ctx.detected_from.append("package.json: react")
                except OSError:
                    pass

            # Detect project type
            if name in ("requirements.txt", "setup.py", "pyproject.toml"):
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    for fw, patterns in self.FRAMEWORK_INDICATORS.items():
                        for pattern in patterns:
                            if pattern.lower() in content.lower():
                                if ctx.framework == Framework.UNKNOWN:
                                    ctx.framework = fw
                                    ctx.detected_from.append(f"{name}: {pattern}")
                                break
                except OSError:
                    pass

        # Classify project type
        if ctx.framework in (Framework.DJANGO, Framework.FLASK, Framework.FASTAPI, Framework.EXPRESS):
            ctx.project_type = "web"
            ctx.has_web_server = True
        elif any((dir_path / f).exists() for f in ["setup.py", "pyproject.toml"]):
            ctx.project_type = "library"
        else:
            ctx.project_type = "script"

        log.debug("context_detected", framework=ctx.framework, type=ctx.project_type)
        return ctx

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        path_lower = file_path.lower().replace("\\", "/")
        return any(indicator in path_lower for indicator in self.TEST_INDICATORS)

    def filter_findings(
        self,
        findings: list[Finding],
        context: ProjectContext | None = None,
        exclude_tests: bool = True,
        min_confidence: str = "low",
    ) -> list[Finding]:
        """Filter findings based on context, removing false positives."""
        from core.models import Confidence

        confidence_order = {
            Confidence.HIGH: 3,
            Confidence.MEDIUM: 2,
            Confidence.LOW: 1,
        }
        min_conf_value = {"high": 3, "medium": 2, "low": 1}.get(min_confidence, 1)

        filtered: list[Finding] = []
        for finding in findings:
            # Skip test files
            if exclude_tests and self.is_test_file(finding.file_path):
                continue

            # Skip low-confidence findings if filter is set
            conf_value = confidence_order.get(finding.confidence, 1)
            if conf_value < min_conf_value:
                continue

            # Context-aware filtering
            if context:
                if self._should_suppress(finding, context):
                    continue

            filtered.append(finding)

        suppressed = len(findings) - len(filtered)
        if suppressed > 0:
            log.debug("findings_filtered", original=len(findings), filtered=len(filtered), suppressed=suppressed)

        return filtered

    # Files that are part of security tool internals (pattern definitions, fix templates)
    SECURITY_TOOL_FILES = {
        "fix_generator", "ast_analyzer", "taint_tracker", "pattern_matcher",
        "prompt_scanner", "secrets_scanner", "model_scanner", "mcp_auditor",
        "rag_scanner", "chain_detector", "redteam_generator", "clickbait_detector",
        "llm_worm_detector", "inference_monitor", "tool_response_analyzer",
    }

    # Patterns indicating a line is defining security patterns, not using them
    PATTERN_DEF_INDICATORS = [
        '": "', "': '",  # dict literal values
        "Sink(", "add(",  # sink/pattern definitions
        "TAINT_SINKS", "TAINT_SOURCES", "DANGEROUS_CALLS", "BUILTIN_PATTERNS",
        "SECRET_PATTERNS", "FALSE_POSITIVE_PATTERNS",
        "injection_patterns", "compiled_patterns",
        "fix_template", "FIX_TEMPLATES", "FIXES",
    ]

    def _should_suppress(self, finding: Finding, context: ProjectContext) -> bool:
        """Check if a finding should be suppressed based on project context."""
        # In CLI tools, subprocess usage is expected
        if context.project_type == "cli" and "subprocess" in finding.rule_id:
            if finding.severity != Severity.ERROR:
                return True

        # In web frameworks, route handlers are expected patterns
        if context.has_web_server:
            # bind to 0.0.0.0 is normal for web servers
            if "bind-all" in finding.rule_id and finding.severity == Severity.WARNING:
                return True

        # Suppress findings in security tool source files that are just pattern definitions
        if self._is_security_tool_file(finding.file_path):
            if self._is_pattern_definition_line(finding.line_content):
                return True

        # In library projects, suppress findings from YAML rule files
        if context.project_type == "library":
            fp = finding.file_path.replace("\\", "/")
            if "/rules/" in fp and fp.endswith(".yaml"):
                return True

        return False

    def _is_security_tool_file(self, file_path: str) -> bool:
        """Check if file is part of security tool internals."""
        name = Path(file_path).stem
        return name in self.SECURITY_TOOL_FILES

    def _is_pattern_definition_line(self, line_content: str) -> bool:
        """Check if a line is defining patterns/sinks rather than executing code."""
        stripped = line_content.strip()
        # Lines that are string constants in lists/dicts/tuples
        if any(indicator in stripped for indicator in self.PATTERN_DEF_INDICATORS):
            return True
        # Lines that are pure string assignments used as templates
        if stripped.startswith(("'", '"', "r'", 'r"', "f'", 'f"')) and "=" not in stripped[:5]:
            return True
        return False
