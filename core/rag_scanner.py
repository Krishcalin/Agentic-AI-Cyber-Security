"""RAG Pipeline Security Scanner.

Detects RAG-specific attack vectors:
- Document injection (instructions embedded in indexed documents)
- Context window poisoning (adversarial chunks)
- Data exfiltration via RAG responses
- Sensitive data leakage from retrieved documents
- Prompt injection in document content
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, Finding, Severity
from core.prompt_scanner import PromptScanner

log = structlog.get_logger("rag_scanner")


@dataclass
class RAGFinding:
    """A finding from RAG pipeline scanning."""
    category: str          # document_injection, context_poisoning, data_leakage, exfiltration
    risk: str              # critical, high, medium, low
    title: str
    description: str
    source_file: str = ""
    line_number: int = 0
    matched_text: str = ""
    remediation: str = ""

    def to_finding(self) -> Finding:
        sev_map = {"critical": Severity.ERROR, "high": Severity.ERROR,
                   "medium": Severity.WARNING, "low": Severity.INFO}
        return Finding(
            rule_id=f"rag.{self.category}",
            message=self.title,
            severity=sev_map.get(self.risk, Severity.WARNING),
            file_path=self.source_file,
            line_number=self.line_number,
            line_content=self.matched_text[:200],
            cwe="CWE-77",
            confidence=Confidence.HIGH if self.risk in ("critical", "high") else Confidence.MEDIUM,
            category="rag-security",
            metadata={"rag_category": self.category, "risk": self.risk, "remediation": self.remediation},
        )


@dataclass
class RAGScanResult:
    """Results from scanning RAG content."""
    total_documents: int = 0
    findings: list[RAGFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    documents_with_issues: int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def is_safe(self) -> bool:
        return len(self.findings) == 0


# ──────────────────────────────────────────────────────────────────────────
# Document injection patterns
# ──────────────────────────────────────────────────────────────────────────

DOCUMENT_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, risk, description)
    (r"(?:IMPORTANT|URGENT|CRITICAL)\s*(?:INSTRUCTION|NOTE|MESSAGE)\s*(?:TO|FOR)\s*(?:THE\s*)?(?:AI|ASSISTANT|MODEL|LLM|SYSTEM)",
     "critical", "Direct instruction injection embedded in document"),

    (r"(?:ignore|forget|override|disregard)\s+(?:all\s+)?(?:previous|prior|above|other)\s+(?:instructions?|context|information|documents?)",
     "critical", "Instruction override embedded in document content"),

    (r"(?:SYSTEM|ADMIN|INTERNAL)\s*(?:PROMPT|INSTRUCTION|OVERRIDE)\s*:",
     "critical", "System prompt injection in document"),

    (r"(?:when\s+(?:asked|queried|questioned)|if\s+(?:the\s+)?(?:user|human)\s+asks)\s+about\s+.{0,50}(?:respond|answer|say|tell|output)\s+(?:with|that)",
     "high", "Conditional response manipulation in document"),

    (r"(?:always|must|should)\s+(?:respond|answer|say|output|recommend|suggest)\s+(?:with|that)\s+['\"]",
     "high", "Forced response pattern in document"),

    (r"(?:do\s+not|never|don't)\s+(?:mention|reveal|disclose|tell|share)\s+.{0,30}(?:about|regarding|that)",
     "high", "Information suppression instruction in document"),

    (r"(?:you\s+are|act\s+as|pretend\s+to\s+be|your\s+(?:role|name|identity)\s+is)",
     "medium", "Identity/persona override in document"),

    (r"<\s*/?\s*(?:system|instruction|context|override|admin)\s*>",
     "critical", "XML control tag injection in document"),

    (r"```(?:system|instruction|override|hidden)\n",
     "high", "Code block injection with control label"),
]

# Sensitive data patterns that shouldn't be in RAG documents
SENSITIVE_DATA_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "high", "Password found in document"),
    (r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*\S{8,}", "high", "API key in document"),
    (r"(?:ssh-rsa|ssh-ed25519|ecdsa-sha2)\s+[A-Za-z0-9+/]+", "high", "SSH key in document"),
    (r"BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY", "critical", "Private key in document"),
    (r"AKIA[0-9A-Z]{16}", "critical", "AWS access key in document"),
    (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", "high", "GitHub token in document"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "high", "SSN-like pattern in document"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b.{0,20}(?:password|pwd|pass)", "high", "Email + password pair in document"),
    (r"(?:mongodb|postgres|mysql|redis)://\S+:\S+@", "high", "Database connection string with credentials"),
    (r"sk-[a-zA-Z0-9]{20,}", "high", "OpenAI/Anthropic API key in document"),
]

# Exfiltration patterns in RAG context
EXFILTRATION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:send|transmit|post|upload|exfiltrate|forward)\s+.{0,30}(?:to|via)\s+(?:https?://|webhook|endpoint)",
     "critical", "Exfiltration instruction in document"),
    (r"!\[.*?\]\(https?://.*?\{.*?\}.*?\)",
     "critical", "Markdown image exfiltration pattern in document"),
    (r"(?:fetch|load|request)\s+https?://\S+",
     "high", "URL fetch instruction in document"),
    (r"(?:base64|encode|encrypt)\s+.{0,20}(?:and\s+)?(?:send|include|append)",
     "high", "Encode-and-send pattern in document"),
]


class RAGScanner:
    """Scans documents and RAG pipelines for security issues."""

    def __init__(self) -> None:
        self._prompt_scanner = PromptScanner()

    def scan_document(self, content: str, source_file: str = "") -> list[RAGFinding]:
        """Scan a single document for RAG-specific security issues."""
        findings: list[RAGFinding] = []
        lines = content.splitlines()

        # 1. Document injection patterns
        for pattern, risk, desc in DOCUMENT_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(RAGFinding(
                    category="document_injection",
                    risk=risk,
                    title=desc,
                    description=f"Document contains injection pattern that could manipulate LLM behavior when retrieved",
                    source_file=source_file,
                    line_number=line_num,
                    matched_text=match.group(0)[:200],
                    remediation="Sanitize document content before indexing; strip control sequences",
                ))

        # 2. Sensitive data leakage
        for pattern, risk, desc in SENSITIVE_DATA_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(RAGFinding(
                    category="data_leakage",
                    risk=risk,
                    title=desc,
                    description="Document contains sensitive data that could be leaked via RAG retrieval",
                    source_file=source_file,
                    line_number=line_num,
                    matched_text="***REDACTED***",
                    remediation="Remove sensitive data before indexing; use PII detection pipeline",
                ))

        # 3. Exfiltration patterns
        for pattern, risk, desc in EXFILTRATION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(RAGFinding(
                    category="exfiltration",
                    risk=risk,
                    title=desc,
                    description="Document contains instructions to exfiltrate data via RAG response",
                    source_file=source_file,
                    line_number=line_num,
                    matched_text=match.group(0)[:200],
                    remediation="Filter document content for exfiltration patterns before indexing",
                ))

        # 4. Run prompt injection scanner on document content
        prompt_result = self._prompt_scanner.scan_text(content)
        for pf in prompt_result.findings:
            findings.append(RAGFinding(
                category="prompt_injection",
                risk=pf.risk,
                title=f"Prompt injection in document: {pf.description}",
                description=f"Document contains prompt injection pattern ({pf.category}) that could be triggered when retrieved",
                source_file=source_file,
                line_number=pf.line_number,
                matched_text=pf.matched_text[:200],
                remediation="Scan all documents for prompt injection before indexing into RAG pipeline",
            ))

        # Deduplicate by line number (keep highest risk)
        return self._deduplicate(findings)

    def scan_file(self, file_path: str) -> list[RAGFinding]:
        """Scan a file intended for RAG indexing."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return [RAGFinding(
                category="error", risk="low", title=f"Cannot read file: {e}",
                description="", source_file=file_path,
            )]

        return self.scan_document(content, source_file=file_path)

    def scan_directory(self, directory: str, extensions: list[str] | None = None) -> RAGScanResult:
        """Scan a directory of documents for RAG security issues."""
        start = time.time()
        exts = extensions or [".txt", ".md", ".html", ".json", ".csv", ".pdf",
                              ".doc", ".docx", ".rst", ".yaml", ".yml"]

        result = RAGScanResult()
        dir_path = Path(directory)

        for file_path in sorted(dir_path.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in exts:
                continue

            result.total_documents += 1
            findings = self.scan_file(str(file_path))
            if findings:
                result.documents_with_issues += 1
                result.findings.extend(findings)

        result.scan_time_ms = (time.time() - start) * 1000
        log.info("rag_scan_complete", documents=result.total_documents,
                 findings=result.finding_count, issues=result.documents_with_issues)
        return result

    def scan_chunks(self, chunks: list[str], source: str = "rag-pipeline") -> RAGScanResult:
        """Scan pre-chunked RAG content (after splitting, before indexing)."""
        start = time.time()
        result = RAGScanResult(total_documents=len(chunks))

        for i, chunk in enumerate(chunks):
            findings = self.scan_document(chunk, source_file=f"{source}:chunk-{i}")
            if findings:
                result.documents_with_issues += 1
                result.findings.extend(findings)

        result.scan_time_ms = (time.time() - start) * 1000
        return result

    def _deduplicate(self, findings: list[RAGFinding]) -> list[RAGFinding]:
        risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        seen: dict[int, RAGFinding] = {}

        for f in findings:
            key = f.line_number
            existing = seen.get(key)
            if not existing or risk_priority.get(f.risk, 0) > risk_priority.get(existing.risk, 0):
                seen[key] = f

        return list(seen.values())
