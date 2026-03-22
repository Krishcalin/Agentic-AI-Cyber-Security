"""LLM-powered semantic code review engine.

Provides context-aware security analysis using Claude or OpenAI APIs.
Unlike pattern matching, this engine understands intent — the same code
pattern gets different verdicts based on project context.

Examples:
  - subprocess.run() → Safe in build tools, suspicious in e-commerce
  - eval() → Dangerous universally, but AST builder context matters
  - os.remove() → Expected in file organizers, dangerous in auth services
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, Finding, Severity

log = structlog.get_logger("semantic_reviewer")


@dataclass
class ReviewFinding:
    """A finding from semantic review."""
    title: str
    description: str
    severity: str              # "critical", "high", "medium", "low", "info"
    line_start: int = 0
    line_end: int = 0
    cwe: str = ""
    fix_suggestion: str = ""
    confidence: str = "medium"
    category: str = ""

    def to_finding(self, file_path: str, lines: list[str]) -> Finding:
        sev_map = {"critical": Severity.ERROR, "high": Severity.ERROR,
                   "medium": Severity.WARNING, "low": Severity.INFO, "info": Severity.INFO}
        conf_map = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}
        line_content = lines[self.line_start - 1] if 0 < self.line_start <= len(lines) else ""

        return Finding(
            rule_id=f"semantic.{self.category or 'review'}.llm",
            message=self.title,
            severity=sev_map.get(self.severity, Severity.WARNING),
            file_path=file_path,
            line_number=self.line_start,
            line_content=line_content.rstrip(),
            cwe=self.cwe,
            confidence=conf_map.get(self.confidence, Confidence.MEDIUM),
            fix_suggestion=self.fix_suggestion,
            language="",
            category="semantic",
            metadata={"description": self.description, "source": "llm"},
        )


@dataclass
class ReviewResult:
    """Result from a semantic code review."""
    findings: list[ReviewFinding] = field(default_factory=list)
    summary: str = ""
    project_type: str = ""
    intent_analysis: str = ""
    review_time_ms: float = 0.0
    tokens_used: int = 0
    provider: str = ""
    error: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ──────────────────────────────────────────────────────────────────────────
# Project type detection for context-aware prompts
# ──────────────────────────────────────────────────────────────────────────

PROJECT_TYPE_INDICATORS: dict[str, list[str]] = {
    "web-api": ["flask", "django", "fastapi", "express", "router", "endpoint",
                "request", "response", "middleware", "cors", "csrf"],
    "cli-tool": ["argparse", "click", "typer", "sys.argv", "commander",
                 "yargs", "subprocess", "os.system"],
    "data-pipeline": ["pandas", "numpy", "spark", "airflow", "etl", "transform",
                      "dataframe", "pipeline", "batch"],
    "ml-model": ["tensorflow", "torch", "sklearn", "model", "train", "predict",
                 "epoch", "optimizer", "loss"],
    "infrastructure": ["terraform", "ansible", "docker", "kubernetes", "helm",
                       "cloudformation", "pulumi"],
    "library": ["setup.py", "pyproject.toml", "__init__", "def ", "class ",
                "@property", "docstring"],
    "build-tool": ["makefile", "cmake", "gradle", "maven", "webpack", "vite",
                   "rollup", "esbuild"],
    "security-tool": ["scan", "vulnerability", "exploit", "payload", "cve",
                      "pentest", "fuzzer", "brute"],
}


def detect_project_type(code: str, file_path: str = "") -> str:
    """Detect project type from code content and file path."""
    code_lower = code.lower()
    scores: dict[str, int] = {}

    for ptype, indicators in PROJECT_TYPE_INDICATORS.items():
        score = sum(1 for ind in indicators if ind in code_lower)
        if score > 0:
            scores[ptype] = score

    if not scores:
        return "general"

    return max(scores, key=scores.get)


# ──────────────────────────────────────────────────────────────────────────
# Review prompts
# ──────────────────────────────────────────────────────────────────────────

REVIEW_SYSTEM_PROMPT = """You are a senior application security engineer performing a code review.
Analyze the code for security vulnerabilities, focusing on INTENT — the same pattern may be
safe or dangerous depending on the project context.

Project type: {project_type}

Rules:
1. Only report REAL security issues — no style/formatting/naming complaints
2. For each finding, explain WHY it's dangerous in THIS project context
3. If a pattern is expected for the project type (e.g., subprocess in build tools), mark as "info"
4. Return findings as JSON array

Output format:
{{
  "summary": "One paragraph security assessment",
  "intent_analysis": "What this code is trying to do",
  "findings": [
    {{
      "title": "Short description",
      "description": "Detailed explanation with context",
      "severity": "critical|high|medium|low|info",
      "line_start": 10,
      "line_end": 12,
      "cwe": "CWE-XXX",
      "fix_suggestion": "How to fix it",
      "confidence": "high|medium|low",
      "category": "injection|crypto|auth|config|secrets|xss|deserialization"
    }}
  ]
}}"""


REVIEW_USER_PROMPT = """Review this {language} code from file `{file_path}` for security vulnerabilities:

```{language}
{code}
```

Focus on:
- Injection risks (SQL, command, code, template)
- Authentication and authorization flaws
- Cryptographic weaknesses
- Hardcoded secrets or credentials
- Unsafe deserialization
- Path traversal / file access
- XSS vectors (if web code)
- Insecure configurations

Consider the project type "{project_type}" when evaluating severity.
Return ONLY the JSON object, no markdown fences or extra text."""


# ──────────────────────────────────────────────────────────────────────────
# LLM Providers
# ──────────────────────────────────────────────────────────────────────────

class LLMProvider:
    """Base class for LLM providers."""

    def complete(self, system_prompt: str, user_prompt: str) -> tuple[str, int]:
        """Send a prompt and return (response_text, tokens_used)."""
        raise NotImplementedError


class ClaudeProvider(LLMProvider):
    """Anthropic Claude API provider."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514") -> None:
        import os
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set — provide via env var or api_key parameter")

    def complete(self, system_prompt: str, user_prompt: str) -> tuple[str, int]:
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        client = anthropic.Anthropic(api_key=self.api_key)
        response = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        text = response.content[0].text
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return text, tokens


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o") -> None:
        import os
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model

        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set — provide via env var or api_key parameter")

    def complete(self, system_prompt: str, user_prompt: str) -> tuple[str, int]:
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=4096,
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        text = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else 0
        return text, tokens


class MockProvider(LLMProvider):
    """Mock provider for testing without API keys."""

    def __init__(self, response: str = "") -> None:
        self._response = response

    def complete(self, system_prompt: str, user_prompt: str) -> tuple[str, int]:
        if self._response:
            return self._response, 100

        # Generate a minimal valid response
        return json.dumps({
            "summary": "Mock review — no API key provided",
            "intent_analysis": "Unable to determine without LLM",
            "findings": [],
        }), 50


# ──────────────────────────────────────────────────────────────────────────
# Semantic Reviewer
# ──────────────────────────────────────────────────────────────────────────

class SemanticReviewer:
    """LLM-powered context-aware code security reviewer."""

    def __init__(
        self,
        provider: str = "claude",
        api_key: str | None = None,
        model: str | None = None,
        max_lines: int = 500,
    ) -> None:
        self.max_lines = max_lines
        self._provider = self._create_provider(provider, api_key, model)
        self.provider_name = provider

    def _create_provider(self, provider: str, api_key: str | None, model: str | None) -> LLMProvider:
        match provider:
            case "claude":
                try:
                    return ClaudeProvider(api_key=api_key, model=model or "claude-sonnet-4-20250514")
                except (ValueError, ImportError) as e:
                    log.warning("claude_unavailable", error=str(e))
                    return MockProvider()
            case "openai":
                try:
                    return OpenAIProvider(api_key=api_key, model=model or "gpt-4o")
                except (ValueError, ImportError) as e:
                    log.warning("openai_unavailable", error=str(e))
                    return MockProvider()
            case "mock":
                return MockProvider()
            case _:
                log.warning("unknown_provider", provider=provider)
                return MockProvider()

    def review_file(self, file_path: str) -> ReviewResult:
        """Review a file using LLM semantic analysis."""
        result = ReviewResult(provider=self.provider_name)
        start = time.time()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.error = str(e)
            return result

        return self._review_code(source, file_path, result, start)

    def review_code(self, code: str, language: str = "python", filename: str = "<stdin>") -> ReviewResult:
        """Review a code string using LLM semantic analysis."""
        result = ReviewResult(provider=self.provider_name)
        start = time.time()
        return self._review_code(code, filename, result, start, language)

    def _review_code(
        self, code: str, file_path: str, result: ReviewResult, start: float,
        language: str | None = None,
    ) -> ReviewResult:
        """Core review logic."""
        lines = code.splitlines()

        # Truncate for cost optimization
        if len(lines) > self.max_lines:
            code = "\n".join(lines[:self.max_lines])
            log.info("code_truncated", original=len(lines), truncated=self.max_lines)

        # Detect language and project type
        if language is None:
            from core.models import detect_language
            language = detect_language(file_path)
        project_type = detect_project_type(code, file_path)
        result.project_type = project_type

        # Build prompts
        system_prompt = REVIEW_SYSTEM_PROMPT.format(project_type=project_type)
        user_prompt = REVIEW_USER_PROMPT.format(
            language=language, file_path=file_path,
            code=code, project_type=project_type,
        )

        # Call LLM
        try:
            response_text, tokens = self._provider.complete(system_prompt, user_prompt)
            result.tokens_used = tokens
        except Exception as e:
            result.error = f"LLM call failed: {e}"
            result.review_time_ms = (time.time() - start) * 1000
            return result

        # Parse response
        try:
            data = self._parse_response(response_text)
            result.summary = data.get("summary", "")
            result.intent_analysis = data.get("intent_analysis", "")

            for f in data.get("findings", []):
                result.findings.append(ReviewFinding(
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    line_start=f.get("line_start", 0),
                    line_end=f.get("line_end", 0),
                    cwe=f.get("cwe", ""),
                    fix_suggestion=f.get("fix_suggestion", ""),
                    confidence=f.get("confidence", "medium"),
                    category=f.get("category", ""),
                ))

        except Exception as e:
            result.error = f"Response parse error: {e}"
            log.warning("response_parse_failed", error=str(e), response=response_text[:200])

        result.review_time_ms = (time.time() - start) * 1000
        log.info("review_complete", file=file_path, findings=result.finding_count,
                 tokens=result.tokens_used, time_ms=f"{result.review_time_ms:.0f}")
        return result

    def _parse_response(self, text: str) -> dict[str, Any]:
        """Parse LLM response, handling markdown fences and extra text."""
        text = text.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            lines = text.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        # Try to find JSON object
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]

        return json.loads(text)
