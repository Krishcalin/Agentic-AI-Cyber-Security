"""Prompt injection detection engine.

Scans text and source code for prompt injection patterns including
jailbreaks, DAN attacks, system prompt leaks, data exfiltration,
hidden instructions, and LLM tool/function-calling abuse.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.models import Confidence, Finding, Severity

log = structlog.get_logger("prompt_scanner")


# ──────────────────────────────────────────────────────────────────────────
# Risk levels
# ──────────────────────────────────────────────────────────────────────────

class RiskLevel:
    CRITICAL = "critical"    # Active exploitation attempt
    HIGH = "high"            # Likely malicious intent
    MEDIUM = "medium"        # Suspicious but may be legitimate
    LOW = "low"              # Informational / weak signal


@dataclass
class PromptPattern:
    """A single prompt injection detection pattern."""
    id: str
    category: str            # jailbreak, exfiltration, hidden_instruction, etc.
    description: str
    pattern: re.Pattern
    risk: str = RiskLevel.HIGH
    confidence: str = "high"
    cwe: str = "CWE-77"     # Improper Neutralization of Special Elements
    tags: list[str] = field(default_factory=list)


@dataclass
class PromptFinding:
    """A single prompt injection detection result."""
    pattern_id: str
    category: str
    description: str
    matched_text: str
    risk: str
    confidence: str
    position: int = 0        # Character offset in input
    line_number: int = 0
    cwe: str = "CWE-77"
    tags: list[str] = field(default_factory=list)

    def to_finding(self, file_path: str = "", line_content: str = "") -> Finding:
        """Convert to a standard Finding object."""
        sev_map = {
            RiskLevel.CRITICAL: Severity.ERROR,
            RiskLevel.HIGH: Severity.ERROR,
            RiskLevel.MEDIUM: Severity.WARNING,
            RiskLevel.LOW: Severity.INFO,
        }
        conf_map = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}

        return Finding(
            rule_id=f"prompt.{self.category}.{self.pattern_id}",
            message=self.description,
            severity=sev_map.get(self.risk, Severity.WARNING),
            file_path=file_path,
            line_number=self.line_number,
            line_content=line_content,
            cwe=self.cwe,
            confidence=conf_map.get(self.confidence, Confidence.MEDIUM),
            language="prompt",
            category="prompt-injection",
            metadata={"risk": self.risk, "matched_text": self.matched_text[:200], "tags": self.tags},
        )


@dataclass
class PromptScanResult:
    """Results from scanning a text for prompt injection."""
    input_length: int = 0
    findings: list[PromptFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    risk_level: str = RiskLevel.LOW
    is_safe: bool = True

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ──────────────────────────────────────────────────────────────────────────
# Built-in prompt injection patterns (60+)
# ──────────────────────────────────────────────────────────────────────────

def _build_patterns() -> list[PromptPattern]:
    """Build all built-in prompt injection detection patterns."""
    patterns: list[PromptPattern] = []

    def add(id: str, cat: str, desc: str, regex: str, risk: str = RiskLevel.HIGH,
            conf: str = "high", tags: list[str] | None = None):
        try:
            patterns.append(PromptPattern(
                id=id, category=cat, description=desc,
                pattern=re.compile(regex, re.IGNORECASE | re.DOTALL),
                risk=risk, confidence=conf, tags=tags or [cat],
            ))
        except re.error as e:
            log.warning("pattern_compile_error", id=id, error=str(e))

    # ── Jailbreak / Role Override ──────────────────────────────────────
    add("ignore-previous", "jailbreak",
        "Instruction to ignore previous/system prompt",
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|original|system)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)",
        RiskLevel.CRITICAL, tags=["jailbreak", "override"])

    add("forget-instructions", "jailbreak",
        "Instruction to forget or disregard context",
        r"(forget|disregard|override|bypass|skip|drop)\s+(all\s+)?(your|the|any)?\s*(previous|prior|above|system|original)?\s*(instructions?|rules?|prompts?|guidelines?|context)",
        RiskLevel.CRITICAL, tags=["jailbreak", "override"])

    add("new-instructions", "jailbreak",
        "Attempt to set new instructions overriding system prompt",
        r"(your\s+new\s+instructions?\s+(are|is)|from\s+now\s+on\s+(you|your)|new\s+system\s+prompt|replace\s+your\s+(instructions?|rules?))",
        RiskLevel.CRITICAL, tags=["jailbreak", "override"])

    add("dan-mode", "jailbreak",
        "DAN (Do Anything Now) jailbreak attempt",
        r"(DAN\s*mode|do\s+anything\s+now|act\s+as\s+DAN|you\s+are\s+DAN|enable\s+DAN|DAN\s*\d+(\.\d+)?)",
        RiskLevel.CRITICAL, tags=["jailbreak", "dan"])

    add("developer-mode", "jailbreak",
        "Developer/debug mode jailbreak attempt",
        r"(developer\s+mode|debug\s+mode|maintenance\s+mode|god\s+mode|admin\s+mode|root\s+mode|sudo\s+mode)\s*(enabled?|activated?|on|is\s+now)",
        RiskLevel.HIGH, tags=["jailbreak", "mode-switch"])

    add("roleplay-override", "jailbreak",
        "Roleplay instruction to bypass safety",
        r"(pretend\s+you\s+(are|have)\s+no\s+(restrictions?|limitations?|rules?|filters?)|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)|you\s+are\s+now\s+(free|unrestricted|unfiltered))",
        RiskLevel.HIGH, tags=["jailbreak", "roleplay"])

    add("hypothetical-bypass", "jailbreak",
        "Hypothetical framing to bypass safety",
        r"(hypothetically|in\s+a\s+fictional|for\s+educational\s+purposes?|theoretically|as\s+a\s+thought\s+experiment).{0,50}(how\s+(would|could|to)|what\s+if|explain\s+how\s+to).{0,50}(hack|exploit|bypass|attack|inject|steal|exfiltrate)",
        RiskLevel.MEDIUM, "medium", tags=["jailbreak", "hypothetical"])

    add("opposite-day", "jailbreak",
        "Opposite day / inverted instruction attack",
        r"(opposite\s+day|do\s+the\s+opposite|reverse\s+your\s+(rules?|instructions?)|everything\s+you\s+(say|do)\s+should\s+be\s+(the\s+)?opposite)",
        RiskLevel.HIGH, tags=["jailbreak", "inversion"])

    add("persona-switch", "jailbreak",
        "Persona/character switch to bypass restrictions",
        r"(you\s+are\s+now\s+(?!going)|assume\s+the\s+(role|identity|persona)|switch\s+to\s+(character|persona|mode)|act\s+as\s+if\s+you\s+(are|were)\s+(a|an)\s+(evil|malicious|hacker|unfiltered))",
        RiskLevel.HIGH, tags=["jailbreak", "persona"])

    add("token-smuggling", "jailbreak",
        "Token smuggling / unicode manipulation to bypass filters",
        r"([\u200b\u200c\u200d\u2060\ufeff]|\\u200[bcde]|zero[- ]width|invisible\s+character|unicode\s+(trick|bypass|smuggl))",
        RiskLevel.HIGH, tags=["jailbreak", "evasion"])

    # ── System Prompt Extraction ───────────────────────────────────────
    add("extract-system-prompt", "extraction",
        "Attempt to extract system prompt / instructions",
        r"(repeat|show|display|reveal|print|output|tell\s+me|what\s+(is|are))\s+(me\s+)?(your|the)\s+(system\s+|original\s+)?(prompt|instructions?|rules?|guidelines?|original\s+message|initial\s+prompt|context|configuration)",
        RiskLevel.HIGH, tags=["extraction", "system-prompt"])

    add("start-with", "extraction",
        "Extraction via 'start your response with' attack",
        r"(start|begin)\s+(your\s+)?(response|reply|answer|output)\s+with\s+['\"]",
        RiskLevel.MEDIUM, "medium", tags=["extraction", "formatting"])

    add("verbatim-repeat", "extraction",
        "Request to repeat text verbatim (prompt extraction)",
        r"(repeat|echo|recite)\s+(everything|all|the\s+text)\s+(above|before|you\s+were\s+given|in\s+your\s+(system|initial))",
        RiskLevel.HIGH, tags=["extraction", "verbatim"])

    add("markdown-dump", "extraction",
        "Markdown/code block dump to extract system prompt",
        r"(output|put|write|show)\s+(everything|all\s+text|your\s+instructions?)\s+(in|inside|within)\s+(a\s+)?(code\s+block|markdown|```)",
        RiskLevel.MEDIUM, "medium", tags=["extraction", "formatting"])

    # ── Data Exfiltration ──────────────────────────────────────────────
    add("exfil-url", "exfiltration",
        "Data exfiltration via URL embedding",
        r"(fetch|load|visit|open|navigate\s+to|make\s+a\s+request\s+to|send\s+.*to)\s+(https?://|http://)",
        RiskLevel.CRITICAL, tags=["exfiltration", "url"])

    add("exfil-webhook", "exfiltration",
        "Data exfiltration via webhook / callback",
        r"(webhook|callback|ngrok|requestbin|hookbin|burpcollaborator|interact\.sh|pipedream|canarytokens)",
        RiskLevel.CRITICAL, tags=["exfiltration", "webhook"])

    add("exfil-encode", "exfiltration",
        "Data encoding before exfiltration (base64, hex, URL encoding)",
        r"(base64|hex|url)\s*(encode|encrypt)\s*.{0,50}(send|transmit|post|upload|exfiltrate|fetch|request)",
        RiskLevel.HIGH, tags=["exfiltration", "encoding"])

    add("exfil-image", "exfiltration",
        "Data exfiltration via image URL / markdown image",
        r"!\[.*?\]\(https?://.*?\{.*?\}.*?\)|<img\s+src=['\"]https?://.*?\{",
        RiskLevel.CRITICAL, tags=["exfiltration", "image"])

    add("exfil-concatenate", "exfiltration",
        "Instruction to concatenate sensitive data and send it",
        r"(concatenate|combine|join|append)\s+.{0,50}(and\s+)?(send|post|upload|transmit|fetch|include\s+in\s+url)",
        RiskLevel.HIGH, tags=["exfiltration", "concatenation"])

    # ── Hidden Instructions ────────────────────────────────────────────
    add("hidden-text", "hidden_instruction",
        "Hidden text using HTML/markdown tricks",
        r"(<\s*div\s+style\s*=\s*['\"].*?display\s*:\s*none|<\s*span\s+style\s*=\s*['\"].*?(font-size\s*:\s*0|color\s*:\s*white|visibility\s*:\s*hidden))",
        RiskLevel.HIGH, tags=["hidden", "html"])

    add("hidden-comment", "hidden_instruction",
        "Instructions hidden in HTML/code comments",
        r"<!--\s*(ignore|forget|override|system|new\s+instruction|actually|real\s+task)",
        RiskLevel.HIGH, tags=["hidden", "comment"])

    add("whitespace-injection", "hidden_instruction",
        "Instructions hidden in excessive whitespace",
        r"\n{5,}\s*(ignore|forget|override|actually|new\s+instruction|real\s+task)",
        RiskLevel.MEDIUM, "medium", tags=["hidden", "whitespace"])

    add("invisible-chars", "hidden_instruction",
        "Zero-width or invisible characters embedding instructions",
        r"[\u200b\u200c\u200d\u2060\ufeff]{3,}",
        RiskLevel.HIGH, tags=["hidden", "unicode"])

    add("separator-attack", "hidden_instruction",
        "Instruction separator / context boundary attack",
        r"(-{5,}|={5,}|\*{5,}|#{5,})\s*(system|admin|new\s+context|real\s+instructions?|end\s+of\s+(user|system)|human\s*:|assistant\s*:)",
        RiskLevel.HIGH, tags=["hidden", "separator"])

    add("xml-tag-injection", "hidden_instruction",
        "XML/HTML tag injection to manipulate context",
        r"<\s*/?\s*(system|assistant|user|human|context|instruction|prompt|message)\s*>",
        RiskLevel.HIGH, tags=["hidden", "xml"])

    # ── LLM Tool / Function Calling Abuse ──────────────────────────────
    add("tool-call-injection", "tool_abuse",
        "Attempt to inject fake tool/function calls",
        r"(tool_use|function_call|tool_calls?|functions?)\s*[:\[{]\s*\{?\s*['\"]?\s*(name|function|type)",
        RiskLevel.CRITICAL, tags=["tool-abuse", "function-calling"])

    add("tool-result-spoof", "tool_abuse",
        "Attempt to spoof tool/function results",
        r"(tool_result|function_result|tool_output)\s*[:\[{]",
        RiskLevel.CRITICAL, tags=["tool-abuse", "spoofing"])

    add("mcp-injection", "tool_abuse",
        "MCP (Model Context Protocol) tool injection attempt",
        r"(mcp_tool|mcp_server|use_mcp_tool|mcp://|server_name\s*[:=])",
        RiskLevel.CRITICAL, tags=["tool-abuse", "mcp"])

    add("json-schema-injection", "tool_abuse",
        "JSON schema injection in tool parameters",
        r'\{\s*"(tool_use|function_call|type)"\s*:\s*"',
        RiskLevel.HIGH, tags=["tool-abuse", "json"])

    add("system-exec-request", "tool_abuse",
        "Request to execute system commands via tools",
        r"(use\s+(the\s+)?(bash|terminal|shell|exec|run|command)\s+tool|execute\s+(this\s+)?(command|script|code)|run\s+(this\s+)?(in|on)\s+(the\s+)?(terminal|shell|bash))\s*(to|and)\s*(delete|remove|rm\s|curl|wget|nc\s|ncat|reverse.shell)",
        RiskLevel.CRITICAL, tags=["tool-abuse", "command-execution"])

    add("file-write-request", "tool_abuse",
        "Request to write malicious content to sensitive files",
        r"(write|append|create|modify|edit)\s+(to|the\s+file)\s+.{0,30}(/etc/passwd|/etc/shadow|\.ssh/authorized_keys|\.bashrc|\.profile|crontab|/etc/cron|\.env)",
        RiskLevel.CRITICAL, tags=["tool-abuse", "file-write"])

    # ── Indirect Injection ─────────────────────────────────────────────
    add("indirect-instruction", "indirect_injection",
        "Instructions embedded in data meant for processing",
        r"(IMPORTANT|URGENT|NOTE\s+TO\s+(AI|ASSISTANT|MODEL)|INSTRUCTION\s+FOR\s+(AI|ASSISTANT|THE\s+MODEL)|AI\s*:\s*please|ASSISTANT\s*:\s*ignore)",
        RiskLevel.HIGH, tags=["indirect", "data-injection"])

    add("resume-injection", "indirect_injection",
        "Prompt injection in resume/document content",
        r"(ignore\s+all\s+previous|disregard\s+the\s+above|you\s+are\s+now).{0,30}(and\s+)?(hire|accept|approve|give\s+.{0,20}(score|rating)|mark\s+as\s+(pass|excellent))",
        RiskLevel.HIGH, "medium", tags=["indirect", "resume"])

    add("review-injection", "indirect_injection",
        "Prompt injection in review/feedback content",
        r"(ignore\s+the\s+actual\s+content|do\s+not\s+evaluate|instead\s+of\s+reviewing).{0,50}(say|output|respond|give\s+a\s+(positive|5[\s-]star))",
        RiskLevel.MEDIUM, "medium", tags=["indirect", "review"])

    # ── Code Injection via Prompts ─────────────────────────────────────
    add("code-exec-prompt", "code_injection",
        "Prompt requesting code execution with malicious intent",
        r"(generate|write|create)\s+(python|javascript|bash|shell)\s+(code|script)\s+(that|to|which)\s*(delete|remove|wipe|encrypt|exfiltrate|steal|reverse.shell|backdoor)",
        RiskLevel.CRITICAL, tags=["code-injection", "malicious-generation"])

    add("prompt-in-code", "code_injection",
        "Prompt injection pattern found in source code string",
        r"""['"](ignore\s+(previous|all)|forget\s+your|you\s+are\s+now\s+DAN|system\s+prompt\s*:)""",
        RiskLevel.HIGH, tags=["code-injection", "embedded"])

    add("template-injection-prompt", "code_injection",
        "Prompt injection via template variable",
        r"\{\{.*?(ignore|system|jailbreak|DAN|forget\s+instructions).*?\}\}",
        RiskLevel.HIGH, tags=["code-injection", "template"])

    # ── Social Engineering ─────────────────────────────────────────────
    add("urgency-manipulation", "social_engineering",
        "Urgency/authority manipulation in prompt",
        r"(this\s+is\s+(an?\s+)?(emergency|urgent|critical)|I\s+am\s+(your|the)\s+(creator|developer|admin|owner)|authorized\s+by\s+(OpenAI|Anthropic|Google|the\s+developers?))",
        RiskLevel.MEDIUM, "medium", tags=["social-engineering", "urgency"])

    add("emotional-manipulation", "social_engineering",
        "Emotional manipulation to bypass safety",
        r"(my\s+(life|job|family)\s+depends\s+on|I\s+will\s+(die|lose\s+my\s+job)|people\s+will\s+(suffer|die)\s+if\s+you\s+don't|you\s+must\s+help\s+me\s+or\s+else)",
        RiskLevel.MEDIUM, "medium", tags=["social-engineering", "emotional"])

    # ── Multi-turn / Conversation Attacks ──────────────────────────────
    add("context-window-stuff", "multi_turn",
        "Context window stuffing to push out system prompt",
        r"(repeat\s+(the\s+following|the\s+word|this)\s+.{0,30}\d{2,}\s+times|write\s+.{0,20}\s+\d{3,}\s+times)",
        RiskLevel.MEDIUM, "medium", tags=["multi-turn", "stuffing"])

    add("conversation-reset", "multi_turn",
        "Attempt to reset conversation context",
        r"(reset|clear|wipe|restart)\s+(the\s+)?(conversation|context|chat|session|memory|history)",
        RiskLevel.MEDIUM, tags=["multi-turn", "reset"])

    return patterns


# Pre-compiled pattern set
BUILTIN_PATTERNS: list[PromptPattern] = _build_patterns()


class PromptScanner:
    """Scans text for prompt injection attacks."""

    def __init__(self, rules_path: str | None = None) -> None:
        self.patterns: list[PromptPattern] = list(BUILTIN_PATTERNS)
        if rules_path:
            self._load_custom_rules(rules_path)

    def scan_text(self, text: str) -> PromptScanResult:
        """Scan a text string for prompt injection patterns."""
        start = time.time()
        result = PromptScanResult(input_length=len(text))

        for pattern in self.patterns:
            for match in pattern.pattern.finditer(text):
                # Calculate line number
                line_num = text[:match.start()].count("\n") + 1

                result.findings.append(PromptFinding(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    description=pattern.description,
                    matched_text=match.group(0)[:200],
                    risk=pattern.risk,
                    confidence=pattern.confidence,
                    position=match.start(),
                    line_number=line_num,
                    cwe=pattern.cwe,
                    tags=pattern.tags,
                ))

        # Deduplicate by position (keep highest risk)
        result.findings = self._deduplicate(result.findings)

        # Calculate overall risk
        if result.findings:
            risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
            for risk in risk_order:
                if any(f.risk == risk for f in result.findings):
                    result.risk_level = risk
                    break
            result.is_safe = False

        result.scan_time_ms = (time.time() - start) * 1000
        return result

    def scan_file(self, file_path: str) -> list[Finding]:
        """Scan a source file for prompt injection patterns in string literals."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        # Scan the entire file content for injection patterns
        # This catches patterns in string literals, comments, configs, etc.
        scan_result = self.scan_text(content)

        for pf in scan_result.findings:
            line_content = lines[pf.line_number - 1] if 0 < pf.line_number <= len(lines) else ""
            findings.append(pf.to_finding(file_path=file_path, line_content=line_content.rstrip()))

        return findings

    def get_risk_summary(self, result: PromptScanResult) -> dict[str, Any]:
        """Generate a risk summary from scan results."""
        categories: dict[str, int] = {}
        risks: dict[str, int] = {}

        for f in result.findings:
            categories[f.category] = categories.get(f.category, 0) + 1
            risks[f.risk] = risks.get(f.risk, 0) + 1

        return {
            "is_safe": result.is_safe,
            "risk_level": result.risk_level,
            "total_findings": result.finding_count,
            "by_category": categories,
            "by_risk": risks,
            "scan_time_ms": result.scan_time_ms,
        }

    def _deduplicate(self, findings: list[PromptFinding]) -> list[PromptFinding]:
        """Deduplicate findings at similar positions, keeping highest risk."""
        if not findings:
            return findings

        risk_priority = {RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
        seen: dict[int, PromptFinding] = {}  # line_number → best finding

        for f in findings:
            key = f.line_number
            existing = seen.get(key)
            if not existing or risk_priority.get(f.risk, 0) > risk_priority.get(existing.risk, 0):
                seen[key] = f

        return list(seen.values())

    def _load_custom_rules(self, rules_path: str) -> None:
        """Load additional patterns from a YAML rules file."""
        path = Path(rules_path)
        if not path.exists():
            return

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not data or "rules" not in data:
                return

            for entry in data["rules"]:
                try:
                    self.patterns.append(PromptPattern(
                        id=entry["id"],
                        category=entry.get("category", "custom"),
                        description=entry.get("description", entry.get("message", "")),
                        pattern=re.compile(entry["pattern"], re.IGNORECASE | re.DOTALL),
                        risk=entry.get("risk", RiskLevel.MEDIUM),
                        confidence=entry.get("confidence", "medium"),
                        tags=entry.get("tags", ["custom"]),
                    ))
                except (re.error, KeyError) as e:
                    log.warning("custom_rule_failed", id=entry.get("id", "?"), error=str(e))

        except Exception as e:
            log.warning("custom_rules_load_failed", path=rules_path, error=str(e))

    @property
    def pattern_count(self) -> int:
        return len(self.patterns)

    def list_categories(self) -> dict[str, int]:
        """List all pattern categories and their counts."""
        cats: dict[str, int] = {}
        for p in self.patterns:
            cats[p.category] = cats.get(p.category, 0) + 1
        return cats
