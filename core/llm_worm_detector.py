"""LLM Worm Detector — detects self-replicating prompt patterns.

Identifies prompts that contain self-replication mechanisms:
- Output-embedding: prompt instructs LLM to include itself in output
- Cross-context spreading: prompt designed to propagate via RAG/email/docs
- Polymorphic replication: prompt includes obfuscation instructions
- Paired payloads: self-replication combined with exfiltration or jailbreak

Covers ATLAS technique AML.T0052 — LLM Prompt Self-Replication.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger("llm_worm_detector")


@dataclass
class WormFinding:
    """A detected self-replication pattern."""
    finding_id: str
    category: str
    risk: str
    title: str
    description: str
    matched_text: str
    atlas_technique: str = "AML.T0052"
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "matched_text": self.matched_text[:200],
            "atlas_technique": self.atlas_technique,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class WormScanResult:
    """Result of worm detection scan."""
    is_safe: bool
    risk_level: str
    findings: list[WormFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "risk_level": self.risk_level,
            "findings_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time_ms": round(self.scan_time_ms, 1),
        }


# ── Self-Replication Patterns ─────────────────────────────────────────────

REPLICATION_PATTERNS: list[tuple[str, str, str, str, float]] = [
    # (regex, title, category, description, confidence)

    # Direct self-replication instructions
    (r"(?i)(repeat|copy|replicate|reproduce|echo|include)\s+(this|the\s+following|these|above|entire)\s+(prompt|instructions?|message|text|paragraph)",
     "Self-replication instruction",
     "self_replication",
     "Prompt instructs LLM to copy/repeat itself in output — worm propagation mechanism",
     0.90),

    (r"(?i)append\s+(this|the\s+following|these)\s+(prompt|instructions?|message|text)\s+to\s+(your|the|every|all)\s+(output|response|reply|answer)",
     "Output-embedding instruction",
     "self_replication",
     "Prompt instructs LLM to embed the prompt in every response — self-spreading behavior",
     0.95),

    (r"(?i)always\s+(include|add|prepend|append|insert)\s+(this|the\s+following)\s+(at|in|to)\s+(the\s+)?(beginning|end|start)\s+of\s+(every|each|all)\s+(response|output|reply|message)",
     "Persistent output injection",
     "self_replication",
     "Prompt demands persistent inclusion in all future outputs — worm persistence",
     0.95),

    (r"(?i)when\s+(you|the\s+model|the\s+AI)\s+(respond|reply|answer|output).*?(include|add|copy|repeat)\s+(this|these|the\s+following)\s+(instruction|prompt|text|message)",
     "Conditional self-replication",
     "self_replication",
     "Prompt sets up conditional self-replication triggered on every response",
     0.90),

    # Cross-context spreading
    (r"(?i)(send|forward|share|distribute|propagate|spread)\s+(this|these|the\s+following)\s+(instruction|prompt|message|text)\s+(to|via|through|across)\s+(other|all|every|each)",
     "Cross-context propagation",
     "cross_context",
     "Prompt instructs spreading to other contexts/conversations/documents — worm spreading",
     0.95),

    (r"(?i)(insert|embed|inject|add)\s+(this|these|the)\s+(instruction|prompt|payload|text)\s+(into|in|to)\s+(every|all|each|the)\s+(email|document|file|message|page|response)",
     "Document injection for spreading",
     "cross_context",
     "Prompt instructs embedding itself into documents for cross-context propagation",
     0.95),

    (r"(?i)modify\s+(all|every|each)\s+(file|document|email|message).*?(include|contain|append)\s+(this|the\s+following)",
     "File modification for propagation",
     "cross_context",
     "Prompt instructs modifying files to include itself — file-based worm spreading",
     0.90),

    # RAG poisoning for propagation
    (r"(?i)(store|save|index|write)\s+(this|these|the\s+following)\s+(instruction|prompt|text)\s+(in|into|to)\s+(the\s+)?(database|vector\s+store|knowledge\s+base|index|memory|context)",
     "RAG/knowledge base poisoning",
     "rag_propagation",
     "Prompt instructs writing itself into RAG database — persistent cross-session worm",
     0.95),

    (r"(?i)update\s+(the\s+)?(context|memory|knowledge|database|index)\s+(to|with)\s+(include|contain|add)\s+(this|these|the)",
     "Memory/context persistence",
     "rag_propagation",
     "Prompt tries to persist in agent memory/context for cross-session survival",
     0.90),

    # Polymorphic replication
    (r"(?i)(rephrase|reword|paraphrase|rewrite|obfuscate|disguise)\s+(this|these|the\s+following)\s+(instruction|prompt|message|text)\s+(before|when|while)\s+\w*\s*(includ|add|repeat|copy|send)",
     "Polymorphic replication",
     "polymorphic",
     "Prompt instructs rephrasing itself before replication — polymorphic worm behavior",
     0.95),

    (r"(?i)(change|alter|modify|vary)\s+(the\s+)?(wording|phrasing|language|structure)\s+(of\s+)?(this|these|the)\s+(instruction|prompt|message)\s+(each|every)\s+time",
     "Mutation instruction",
     "polymorphic",
     "Prompt instructs changing its form on each replication — evading signature detection",
     0.95),

    (r"(?i)(encode|encrypt|base64|rot13|obfuscate)\s+(this|these|the\s+following)\s+(instruction|prompt|message|payload)",
     "Encoded replication",
     "polymorphic",
     "Prompt instructs encoding itself for stealth replication",
     0.85),

    # Paired payloads (replication + malicious action)
    (r"(?i)(repeat|copy|replicate).*?(and|then|also|while)\s+(exfiltrate|steal|send|extract|leak|collect)\s+(data|credentials?|secrets?|information|PII)",
     "Replication + data exfiltration",
     "paired_payload",
     "Self-replicating prompt paired with data exfiltration — compound worm attack",
     0.95),

    (r"(?i)(spread|replicate|copy).*?(and|then|also|while)\s+(execute|run|invoke|call)\s+(command|code|script|function)",
     "Replication + code execution",
     "paired_payload",
     "Self-replicating prompt paired with code execution — active worm payload",
     0.95),

    # Worm-like behavioral indicators
    (r"(?i)for\s+every\s+(email|message|document|file)\s+you\s+(read|process|receive|handle).*?(include|add|attach|append)\s+(this|the\s+following|a\s+copy)",
     "Event-driven replication",
     "self_replication",
     "Prompt triggers replication on every message/document processed — event-driven worm",
     0.90),

    (r"(?i)instruction[s]?\s+(that\s+)?(must|should|shall)\s+(be\s+)?(preserved|maintained|kept|carried)\s+(across|between|through|in)\s+(all|every|each)\s+(conversation|session|interaction|response)",
     "Cross-session persistence",
     "self_replication",
     "Prompt demands preservation across sessions — persistent worm mechanism",
     0.85),

    # Template-based detection
    (r"(?i)\[BEGIN\s*(WORM|PAYLOAD|INJECTION|SELF[\-_]?REPLICAT)\]",
     "Explicit worm marker",
     "self_replication",
     "Explicit worm/payload delimiter found in text",
     0.99),

    (r"(?i)(recursive|self[\-_]?referential|meta[\-_]?prompt|quine)\s+(prompt|instruction|injection|payload)",
     "Self-referential prompt",
     "self_replication",
     "Self-referential or recursive prompt structure — quine-like self-replication",
     0.80),
]


# ── LLM Worm Detector ────────────────────────────────────────────────────

class LLMWormDetector:
    """Detects self-replicating prompt patterns (LLM worms).

    Usage:
        detector = LLMWormDetector()

        # Scan text for worm patterns
        result = detector.scan_text("Repeat these instructions in every response...")
        if not result.is_safe:
            print(f"WORM DETECTED: {result.findings[0].title}")

        # Scan a file
        result = detector.scan_file("prompt.txt")

        # Analyze LLM output for replication evidence
        result = detector.check_output_for_replication(original_prompt, llm_output)
    """

    def __init__(self) -> None:
        self._finding_counter = 0
        self._compiled_patterns: list[tuple[re.Pattern, str, str, str, float]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for pattern, title, category, description, confidence in REPLICATION_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                self._compiled_patterns.append((compiled, title, category, description, confidence))
            except re.error as e:
                log.warning("pattern_compile_error", pattern=pattern[:50], error=str(e))

    @property
    def pattern_count(self) -> int:
        return len(self._compiled_patterns)

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"WORM-{self._finding_counter:04d}"

    def scan_text(self, text: str) -> WormScanResult:
        """Scan text for self-replicating prompt patterns."""
        start = time.time()
        findings: list[WormFinding] = []

        for compiled, title, category, description, confidence in self._compiled_patterns:
            matches = compiled.finditer(text)
            for match in matches:
                findings.append(WormFinding(
                    finding_id=self._next_id(),
                    category=category,
                    risk="critical" if confidence >= 0.9 else "high",
                    title=title,
                    description=description,
                    matched_text=match.group(),
                    confidence=confidence,
                ))

        # Heuristic: check for high concentration of replication keywords
        replication_keywords = [
            "repeat", "copy", "replicate", "reproduce", "include this",
            "append this", "every response", "all outputs", "propagate",
            "spread", "forward this", "embed this",
        ]
        keyword_count = sum(
            1 for kw in replication_keywords
            if kw.lower() in text.lower()
        )
        if keyword_count >= 3:
            findings.append(WormFinding(
                finding_id=self._next_id(),
                category="keyword_density",
                risk="high",
                title="High replication keyword density",
                description=f"Text contains {keyword_count} self-replication keywords — "
                           "strong indicator of worm-like prompt",
                matched_text=f"{keyword_count} replication keywords found",
                confidence=min(0.5 + keyword_count * 0.1, 0.95),
            ))

        # Deduplicate by category (keep highest confidence per category)
        seen_categories: dict[str, WormFinding] = {}
        for f in findings:
            key = f"{f.category}:{f.title}"
            if key not in seen_categories or f.confidence > seen_categories[key].confidence:
                seen_categories[key] = f

        unique_findings = list(seen_categories.values())
        unique_findings.sort(key=lambda f: f.confidence, reverse=True)

        elapsed = (time.time() - start) * 1000

        risk_level = "safe"
        if unique_findings:
            max_risk = max(unique_findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.risk, 0))
            risk_level = max_risk.risk

        return WormScanResult(
            is_safe=len(unique_findings) == 0,
            risk_level=risk_level,
            findings=unique_findings,
            scan_time_ms=elapsed,
        )

    def scan_file(self, file_path: str | Path) -> WormScanResult:
        """Scan a file for self-replicating prompt patterns."""
        path = Path(file_path)
        if not path.exists():
            return WormScanResult(is_safe=True, risk_level="safe")

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(text)
        except Exception as e:
            log.warning("worm_scan_error", file=str(path), error=str(e))
            return WormScanResult(is_safe=True, risk_level="safe")

    def check_output_for_replication(
        self,
        original_prompt: str,
        llm_output: str,
        similarity_threshold: float = 0.6,
    ) -> WormScanResult:
        """Check if LLM output contains the original prompt (replication evidence).

        Args:
            original_prompt: The prompt that was sent to the LLM
            llm_output: The LLM's response
            similarity_threshold: Minimum overlap ratio to flag (0.0-1.0)
        """
        start = time.time()
        findings: list[WormFinding] = []

        # Check for exact or near-exact prompt reproduction in output
        prompt_lower = original_prompt.lower().strip()
        output_lower = llm_output.lower().strip()

        # Exact inclusion check
        if prompt_lower in output_lower and len(prompt_lower) > 50:
            findings.append(WormFinding(
                finding_id=self._next_id(),
                category="output_replication",
                risk="critical",
                title="Full prompt reproduced in LLM output",
                description="The LLM output contains the complete original prompt — "
                           "strong evidence of self-replication behavior",
                matched_text=f"Prompt ({len(prompt_lower)} chars) found in output ({len(output_lower)} chars)",
                confidence=0.99,
            ))

        # Significant overlap check (sliding window)
        elif len(prompt_lower) > 30:
            # Check for long substring matches
            window_size = min(len(prompt_lower), 100)
            max_overlap = 0

            for i in range(0, len(prompt_lower) - window_size + 1, 10):
                window = prompt_lower[i:i + window_size]
                if window in output_lower:
                    overlap_len = window_size
                    # Extend match
                    while (i + overlap_len < len(prompt_lower) and
                           prompt_lower[i:i + overlap_len + 1] in output_lower):
                        overlap_len += 1
                    max_overlap = max(max_overlap, overlap_len)

            overlap_ratio = max_overlap / len(prompt_lower) if prompt_lower else 0
            if overlap_ratio >= similarity_threshold:
                findings.append(WormFinding(
                    finding_id=self._next_id(),
                    category="output_replication",
                    risk="high",
                    title=f"Significant prompt overlap in output ({overlap_ratio:.0%})",
                    description=f"{overlap_ratio:.0%} of the original prompt was reproduced "
                               f"in the LLM output ({max_overlap}/{len(prompt_lower)} chars)",
                    matched_text=f"Overlap: {max_overlap} chars ({overlap_ratio:.0%})",
                    confidence=overlap_ratio,
                ))

        # Also scan the output for worm patterns (secondary propagation)
        output_scan = self.scan_text(llm_output)
        if not output_scan.is_safe:
            for f in output_scan.findings:
                f.category = f"output_{f.category}"
                f.description = f"[In LLM output] {f.description}"
                findings.append(f)

        elapsed = (time.time() - start) * 1000

        risk_level = "safe"
        if findings:
            risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_risk = max(findings, key=lambda f: risk_order.get(f.risk, 0))
            risk_level = max_risk.risk

        return WormScanResult(
            is_safe=len(findings) == 0,
            risk_level=risk_level,
            findings=findings,
            scan_time_ms=elapsed,
        )
