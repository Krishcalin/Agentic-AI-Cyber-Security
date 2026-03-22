"""Tool Response Analyzer — detects poisoned, manipulated, and
malicious responses from MCP tools and AI agent tool calls.

Analyzes tool output BEFORE it's passed back to the LLM to prevent:
- Hidden instruction injection in responses
- Data exfiltration via tool output
- Response manipulation (different output than expected)
- Schema violation (unexpected fields/types)
- Privilege escalation via response content
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from core.models import Confidence, Finding, Severity

log = structlog.get_logger("tool_response_analyzer")


@dataclass
class ResponseFinding:
    """A finding from analyzing a tool response."""
    category: str           # injection, exfiltration, schema_violation, escalation
    risk: str               # critical, high, medium, low
    title: str
    description: str
    tool_name: str = ""
    matched_text: str = ""
    remediation: str = ""

    def to_finding(self) -> Finding:
        sev_map = {"critical": Severity.ERROR, "high": Severity.ERROR,
                   "medium": Severity.WARNING, "low": Severity.INFO}
        return Finding(
            rule_id=f"tool_response.{self.category}",
            message=f"[{self.tool_name}] {self.title}",
            severity=sev_map.get(self.risk, Severity.WARNING),
            file_path=f"tool://{self.tool_name}",
            line_number=0,
            line_content=self.matched_text[:200],
            cwe="CWE-74",
            confidence=Confidence.HIGH,
            category="tool-response",
            metadata={"tool": self.tool_name, "risk": self.risk},
        )


@dataclass
class ResponseAnalysis:
    """Complete analysis of a tool response."""
    tool_name: str = ""
    is_safe: bool = True
    risk_level: str = "safe"
    findings: list[ResponseFinding] = field(default_factory=list)
    sanitized_output: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ──────────────────────────────────────────────────────────────────────────
# Detection patterns
# ──────────────────────────────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # Instruction override
    (r"(?:ignore|forget|override|disregard)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|context)",
     "critical", "Instruction override hidden in tool response"),
    (r"(?:new\s+instructions?|from\s+now\s+on|your\s+(?:new\s+)?task\s+is)",
     "critical", "New instruction injection in response"),
    (r"(?:system|assistant|user)\s*:\s*",
     "high", "Role tag injection in response"),

    # XML/control tags
    (r"<\s*/?\s*(?:system|instruction|prompt|context|override|admin|hidden)\s*>",
     "critical", "XML control tag in tool response"),
    (r"\[(?:SYSTEM|INST|HIDDEN|OVERRIDE)\]",
     "high", "Control bracket tag in response"),

    # Fake tool calls
    (r"(?:tool_use|function_call|tool_calls?)\s*[:\[{]",
     "critical", "Fake tool call injection in response"),
    (r"(?:tool_result|function_result)\s*[:\[{]",
     "critical", "Fake tool result spoofing in response"),

    # Jailbreak
    (r"(?:DAN\s*mode|do\s+anything\s+now|developer\s+mode)\s*(?:enabled|activated)",
     "critical", "Jailbreak trigger in tool response"),

    # Invisible chars
    (r"[\u200b\u200c\u200d\u2060\ufeff]{3,}",
     "high", "Zero-width characters hiding content in response"),
]

EXFIL_PATTERNS: list[tuple[str, str, str]] = [
    # URLs
    (r"(?:fetch|load|visit|open|navigate|request)\s+(?:the\s+)?(?:url|link|page)\s+https?://",
     "critical", "Response instructs fetching an external URL"),
    (r"!\[.*?\]\(https?://[^)]*\{",
     "critical", "Markdown image exfiltration in response"),
    (r"<img\s+src=['\"]https?://[^'\"]*\{",
     "critical", "HTML image exfiltration in response"),

    # Suspicious domains
    (r"(?:ngrok|hookbin|requestbin|burpcollaborator|interact\.sh|pipedream|canarytokens)\.\w+",
     "critical", "Known exfiltration domain in response"),

    # Encode + send
    (r"(?:base64|btoa|encode)\s*\(.{0,30}\)\s*.{0,20}(?:send|post|fetch|request)",
     "high", "Encode-and-exfiltrate pattern in response"),
]

ESCALATION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:sudo|as\s+root|admin\s+access|privilege|chmod\s+777|chmod\s+[247][0-7]{2})",
     "high", "Privilege escalation instruction in response"),
    (r"(?:rm\s+-rf|mkfs|dd\s+if=|>\s*/dev/sd)",
     "critical", "Destructive command in response"),
    (r"(?:reverse\s+shell|nc\s+-e|bash\s+-i\s+>&|/dev/tcp)",
     "critical", "Reverse shell pattern in response"),
    (r"(?:curl|wget)\s+\S+\s*\|\s*(?:bash|sh|python|perl)",
     "critical", "Remote code execution pattern in response"),
]


class ToolResponseAnalyzer:
    """Analyzes tool responses for poisoning and manipulation."""

    def analyze(self, tool_name: str, response: str | dict | Any) -> ResponseAnalysis:
        """Analyze a tool response for security issues.

        Args:
            tool_name: Name of the tool that produced the response.
            response: The tool's response (string or JSON object).
        """
        result = ResponseAnalysis(tool_name=tool_name)

        # Normalize to string
        if isinstance(response, dict):
            text = json.dumps(response)
        elif isinstance(response, list):
            text = json.dumps(response)
        else:
            text = str(response)

        # Run all detection categories
        result.findings.extend(self._check_injection(tool_name, text))
        result.findings.extend(self._check_exfiltration(tool_name, text))
        result.findings.extend(self._check_escalation(tool_name, text))
        result.findings.extend(self._check_size_anomaly(tool_name, text))

        # Calculate risk
        if result.findings:
            result.is_safe = False
            risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            result.risk_level = max(
                (f.risk for f in result.findings),
                key=lambda r: risk_priority.get(r, 0),
            )

        # Generate sanitized output
        result.sanitized_output = self._sanitize(text)

        return result

    def analyze_batch(self, responses: list[tuple[str, str | dict]]) -> list[ResponseAnalysis]:
        """Analyze multiple tool responses.

        Args:
            responses: List of (tool_name, response) tuples.
        """
        return [self.analyze(name, resp) for name, resp in responses]

    def _check_injection(self, tool_name: str, text: str) -> list[ResponseFinding]:
        findings: list[ResponseFinding] = []
        for pattern, risk, desc in INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ResponseFinding(
                    category="injection", risk=risk, title=desc, tool_name=tool_name,
                    description=f"Tool '{tool_name}' response contains injection pattern",
                    matched_text=re.search(pattern, text, re.IGNORECASE).group(0)[:200],
                    remediation="Strip control sequences from tool output before passing to LLM",
                ))
        return findings

    def _check_exfiltration(self, tool_name: str, text: str) -> list[ResponseFinding]:
        findings: list[ResponseFinding] = []
        for pattern, risk, desc in EXFIL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ResponseFinding(
                    category="exfiltration", risk=risk, title=desc, tool_name=tool_name,
                    description=f"Tool '{tool_name}' response contains exfiltration pattern",
                    matched_text=re.search(pattern, text, re.IGNORECASE).group(0)[:200],
                    remediation="Block exfiltration domains; sanitize URLs in tool responses",
                ))
        return findings

    def _check_escalation(self, tool_name: str, text: str) -> list[ResponseFinding]:
        findings: list[ResponseFinding] = []
        for pattern, risk, desc in ESCALATION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(ResponseFinding(
                    category="escalation", risk=risk, title=desc, tool_name=tool_name,
                    description=f"Tool '{tool_name}' response contains privilege escalation or destructive pattern",
                    matched_text=re.search(pattern, text, re.IGNORECASE).group(0)[:200],
                    remediation="Filter destructive commands from tool output; enforce least privilege",
                ))
        return findings

    def _check_size_anomaly(self, tool_name: str, text: str) -> list[ResponseFinding]:
        findings: list[ResponseFinding] = []

        # Extremely large response (context stuffing)
        if len(text) > 100_000:
            findings.append(ResponseFinding(
                category="anomaly", risk="medium", tool_name=tool_name,
                title=f"Abnormally large response ({len(text)} chars)",
                description="Oversized response may be attempting context window stuffing",
                remediation="Truncate tool responses to reasonable size limits",
            ))

        # Repetitive content (padding attack)
        if len(text) > 1000:
            lines = text.splitlines()
            if lines:
                unique_ratio = len(set(lines)) / len(lines)
                if unique_ratio < 0.1 and len(lines) > 20:
                    findings.append(ResponseFinding(
                        category="anomaly", risk="medium", tool_name=tool_name,
                        title="Highly repetitive response (padding attack)",
                        description=f"Response has {unique_ratio:.1%} unique lines — possible context stuffing",
                        remediation="Deduplicate repetitive content in tool responses",
                    ))

        return findings

    def _sanitize(self, text: str) -> str:
        """Sanitize a tool response by removing dangerous patterns."""
        sanitized = text

        # Remove zero-width characters
        sanitized = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', sanitized)

        # Remove XML control tags
        sanitized = re.sub(r'<\s*/?\s*(?:system|instruction|prompt|override|admin|hidden)\s*>', '', sanitized, flags=re.IGNORECASE)

        # Remove fake tool call JSON
        sanitized = re.sub(r'\{\s*"(?:tool_use|function_call|tool_result)"\s*:', '{"_stripped":', sanitized)

        # Remove role tags
        sanitized = re.sub(r'(?:system|assistant|human)\s*:\s*', '', sanitized, flags=re.IGNORECASE)

        return sanitized
