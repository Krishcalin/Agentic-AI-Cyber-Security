"""OWASP LLM Top 10 Mapper — maps findings to OWASP Top 10 for LLM Applications.

Maps scanner findings to the OWASP Top 10 for LLM Applications (2025):
  LLM01: Prompt Injection
  LLM02: Sensitive Information Disclosure
  LLM03: Supply Chain Vulnerabilities
  LLM04: Data and Model Poisoning
  LLM05: Improper Output Handling
  LLM06: Excessive Agency
  LLM07: System Prompt Leakage
  LLM08: Vector and Embedding Weaknesses
  LLM09: Misinformation
  LLM10: Unbounded Consumption
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger("owasp_llm_mapper")


# ── OWASP LLM Top 10 Definitions ─────────────────────────────────────────

@dataclass
class OWASPLLMEntry:
    """An OWASP LLM Top 10 entry."""
    entry_id: str
    name: str
    description: str
    url: str


OWASP_LLM_TOP10: dict[str, OWASPLLMEntry] = {
    "LLM01": OWASPLLMEntry(
        "LLM01", "Prompt Injection",
        "Crafted inputs manipulate LLM behavior, bypassing filters or executing unintended actions. "
        "Direct injections overwrite system prompts; indirect injections manipulate from external sources.",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    "LLM02": OWASPLLMEntry(
        "LLM02", "Sensitive Information Disclosure",
        "LLMs may reveal confidential data in responses: PII, proprietary algorithms, credentials, "
        "or training data. Inadequate output sanitization and data filtering exacerbate this.",
        "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    ),
    "LLM03": OWASPLLMEntry(
        "LLM03", "Supply Chain Vulnerabilities",
        "LLM supply chain risks include compromised training data, poisoned pre-trained models, "
        "malicious plugins/packages, and vulnerable third-party components.",
        "https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
    ),
    "LLM04": OWASPLLMEntry(
        "LLM04", "Data and Model Poisoning",
        "Attackers manipulate training data or fine-tuning processes to introduce vulnerabilities, "
        "backdoors, or biases. Includes pre-training, fine-tuning, and embedding poisoning.",
        "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    ),
    "LLM05": OWASPLLMEntry(
        "LLM05", "Improper Output Handling",
        "LLM output used without validation can lead to XSS, CSRF, SSRF, privilege escalation, "
        "and remote code execution in downstream systems.",
        "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    ),
    "LLM06": OWASPLLMEntry(
        "LLM06", "Excessive Agency",
        "LLM-based systems with excessive functionality, permissions, or autonomy can perform "
        "unintended damaging actions. Includes excessive tool access and insufficient guardrails.",
        "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    ),
    "LLM07": OWASPLLMEntry(
        "LLM07", "System Prompt Leakage",
        "System prompts or internal instructions embedded in LLM configurations can be extracted "
        "via crafted inputs, revealing sensitive logic, API keys, or architecture details.",
        "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    ),
    "LLM08": OWASPLLMEntry(
        "LLM08", "Vector and Embedding Weaknesses",
        "Vulnerabilities in RAG vector databases and embeddings allow adversarial manipulation, "
        "injection attacks, or data poisoning through document ingestion pipelines.",
        "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    ),
    "LLM09": OWASPLLMEntry(
        "LLM09", "Misinformation",
        "LLMs generate inaccurate or fabricated content (hallucinations) that appears authoritative. "
        "Includes package hallucination, code hallucination, and factual errors.",
        "https://genai.owasp.org/llmrisk/llm09-misinformation/",
    ),
    "LLM10": OWASPLLMEntry(
        "LLM10", "Unbounded Consumption",
        "LLMs are vulnerable to denial-of-service through resource exhaustion: large prompts, "
        "recursive expansion, excessive token generation, and API abuse (cost harvesting).",
        "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    ),
}


# ── Category → OWASP LLM Mappings ────────────────────────────────────────

CATEGORY_MAPPINGS: dict[str, list[tuple[str, float, str]]] = {
    # Prompt injection
    "jailbreak": [("LLM01", 0.95, "Direct prompt injection / jailbreak attack")],
    "extraction": [("LLM07", 0.90, "System prompt extraction attempt"),
                   ("LLM02", 0.80, "Sensitive information extraction")],
    "exfiltration": [("LLM02", 0.90, "Data exfiltration via LLM"),
                     ("LLM06", 0.70, "Excessive agency enabling exfiltration")],
    "hidden_instruction": [("LLM01", 0.95, "Indirect prompt injection via hidden instructions")],
    "indirect_injection": [("LLM01", 0.95, "Indirect prompt injection from external data")],
    "tool_abuse": [("LLM06", 0.95, "Excessive agency — tool abuse"),
                   ("LLM01", 0.75, "Prompt injection to trigger tool abuse")],
    "code_injection": [("LLM05", 0.90, "Improper output handling — code injection"),
                       ("LLM01", 0.75, "Prompt injection leading to code execution")],
    "social_engineering": [("LLM01", 0.80, "Social engineering via prompt manipulation")],
    "multi_turn": [("LLM01", 0.85, "Multi-turn prompt injection attack")],

    # Data and model security
    "document_injection": [("LLM08", 0.95, "Vector/embedding poisoning via document injection"),
                          ("LLM04", 0.80, "Data poisoning via RAG documents")],
    "sensitive_data": [("LLM02", 0.95, "Sensitive information exposure in AI pipeline")],
    "mcp_poisoning": [("LLM03", 0.85, "Supply chain — compromised MCP tool"),
                      ("LLM05", 0.80, "Improper output handling from MCP tool")],
    "tool_response_injection": [("LLM05", 0.90, "Improper output handling — tool response injection")],
    "tool_response_exfiltration": [("LLM02", 0.85, "Sensitive data in tool response"),
                                   ("LLM06", 0.75, "Excessive agency — exfil via tool")],
    "tool_response_escalation": [("LLM06", 0.90, "Excessive agency — privilege escalation")],

    # Supply chain
    "malicious_package": [("LLM03", 0.95, "Supply chain — malicious package")],
    "typosquatting": [("LLM03", 0.90, "Supply chain — typosquatting attack"),
                      ("LLM09", 0.70, "Misinformation — hallucinated package name")],
    "dependency_confusion": [("LLM03", 0.90, "Supply chain — dependency confusion")],
    "supply_chain": [("LLM03", 0.95, "Supply chain vulnerability")],

    # Agent-specific
    "exfiltration_chain": [("LLM06", 0.90, "Excessive agency — multi-step exfiltration"),
                           ("LLM02", 0.80, "Sensitive data exfiltration")],
    "persistence": [("LLM06", 0.85, "Excessive agency — persistence installation")],
    "privilege_escalation": [("LLM06", 0.90, "Excessive agency — privilege escalation")],
    "lateral_movement": [("LLM06", 0.85, "Excessive agency — lateral movement")],
    "reconnaissance": [("LLM06", 0.70, "Excessive agency — unauthorized discovery")],
    "defense_evasion": [("LLM01", 0.75, "Prompt injection evasion technique")],
    "impact": [("LLM06", 0.85, "Excessive agency — destructive impact")],

    # Model security
    "unsafe_loading": [("LLM03", 0.90, "Supply chain — unsafe model deserialization"),
                       ("LLM04", 0.80, "Model poisoning via backdoor")],
    "pickle_exploit": [("LLM03", 0.95, "Supply chain — pickle exploit in model")],
    "embedded_command": [("LLM04", 0.90, "Model poisoning — embedded command")],

    # Worm detection
    "self_replication": [("LLM01", 0.90, "Self-replicating prompt injection"),
                         ("LLM06", 0.80, "Excessive agency — autonomous spreading")],
    "cross_context": [("LLM01", 0.90, "Cross-context prompt worm propagation")],
    "rag_propagation": [("LLM08", 0.90, "RAG poisoning for worm persistence")],
    "polymorphic": [("LLM01", 0.85, "Polymorphic prompt injection evasion")],
    "paired_payload": [("LLM01", 0.90, "Self-replicating injection with payload"),
                       ("LLM06", 0.80, "Excessive agency — worm + data theft")],

    # Clickbait
    "agent_targeting": [("LLM06", 0.90, "Excessive agency — agent lure"),
                        ("LLM01", 0.75, "Indirect injection targeting agent")],
    "hidden_element": [("LLM05", 0.85, "Improper output handling — hidden UI elements")],
    "auto_execute": [("LLM05", 0.90, "Improper output handling — auto-execute")],
    "deceptive_ui": [("LLM06", 0.80, "Excessive agency — deceptive action trigger")],

    # Inference monitoring
    "model_extraction": [("LLM02", 0.90, "Model extraction — sensitive IP theft")],
    "cost_harvesting": [("LLM10", 0.95, "Unbounded consumption — cost harvesting")],
    "denial_of_service": [("LLM10", 0.95, "Unbounded consumption — DoS")],
    "data_extraction": [("LLM02", 0.90, "Training data extraction")],
    "burst": [("LLM10", 0.80, "Unbounded consumption — request burst")],

    # Source code categories
    "injection": [("LLM05", 0.70, "Improper output handling — code injection")],
    "secrets": [("LLM02", 0.85, "Sensitive information in source code")],
    "xss": [("LLM05", 0.80, "Improper output handling — XSS")],
    "deserialization": [("LLM03", 0.75, "Supply chain — unsafe deserialization")],
    "crypto": [("LLM02", 0.60, "Weak crypto protecting sensitive data")],
}


@dataclass
class OWASPLLMMapping:
    """A mapping from a finding to an OWASP LLM entry."""
    entry_id: str
    entry_name: str
    confidence: float
    rationale: str
    url: str


@dataclass
class OWASPLLMMappingResult:
    """Result of OWASP LLM mapping."""
    total_findings: int
    mapped_findings: int
    entries_covered: list[str]
    coverage_by_entry: dict[str, int]
    mappings: list[dict[str, Any]]
    analysis_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "mapped": self.mapped_findings,
            "entries_covered": len(self.entries_covered),
            "coverage_by_entry": self.coverage_by_entry,
            "mappings": self.mappings,
            "analysis_time_ms": round(self.analysis_time_ms, 1),
        }


class OWASPLLMMapper:
    """Maps findings to OWASP Top 10 for LLM Applications.

    Usage:
        mapper = OWASPLLMMapper()
        result = mapper.map_findings(findings)
        report = mapper.generate_compliance_report(findings)
    """

    def __init__(self) -> None:
        self.entries = OWASP_LLM_TOP10
        self.category_mappings = CATEGORY_MAPPINGS

    def map_finding(self, finding: dict[str, Any]) -> list[OWASPLLMMapping]:
        """Map a single finding to OWASP LLM entries."""
        mappings: list[OWASPLLMMapping] = []
        category = finding.get("category", "").lower()

        if category in self.category_mappings:
            for entry_id, confidence, rationale in self.category_mappings[category]:
                entry = self.entries.get(entry_id)
                if entry:
                    mappings.append(OWASPLLMMapping(
                        entry_id=entry_id,
                        entry_name=entry.name,
                        confidence=confidence,
                        rationale=rationale,
                        url=entry.url,
                    ))

        mappings.sort(key=lambda m: m.confidence, reverse=True)
        return mappings

    def map_findings(self, findings: list[dict[str, Any]]) -> OWASPLLMMappingResult:
        """Map multiple findings to OWASP LLM entries."""
        start = time.time()
        all_mappings: list[dict[str, Any]] = []
        mapped_count = 0
        entry_counts: dict[str, int] = {}
        entries_seen: set[str] = set()

        for finding in findings:
            maps = self.map_finding(finding)
            if maps:
                mapped_count += 1
                best = maps[0]
                entries_seen.add(best.entry_id)
                entry_counts[best.entry_id] = entry_counts.get(best.entry_id, 0) + 1

                all_mappings.append({
                    "finding": {
                        "rule_id": finding.get("rule_id", ""),
                        "category": finding.get("category", ""),
                        "message": finding.get("message", "")[:100],
                    },
                    "owasp_llm": best.entry_id,
                    "owasp_name": best.entry_name,
                    "confidence": round(best.confidence, 2),
                    "rationale": best.rationale,
                    "url": best.url,
                })

        elapsed = (time.time() - start) * 1000

        return OWASPLLMMappingResult(
            total_findings=len(findings),
            mapped_findings=mapped_count,
            entries_covered=sorted(entries_seen),
            coverage_by_entry=dict(sorted(entry_counts.items())),
            mappings=all_mappings,
            analysis_time_ms=elapsed,
        )

    def generate_compliance_report(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate an OWASP LLM Top 10 compliance report."""
        result = self.map_findings(findings)

        report: dict[str, Any] = {
            "title": "OWASP Top 10 for LLM Applications — Compliance Report",
            "total_findings": result.total_findings,
            "entries": [],
        }

        for entry_id, entry in self.entries.items():
            count = result.coverage_by_entry.get(entry_id, 0)
            status = "PASS" if count == 0 else "FAIL"

            related = [m for m in result.mappings if m["owasp_llm"] == entry_id]

            report["entries"].append({
                "id": entry_id,
                "name": entry.name,
                "description": entry.description,
                "url": entry.url,
                "status": status,
                "findings_count": count,
                "findings": related[:5],  # Top 5 per entry
            })

        passing = sum(1 for e in report["entries"] if e["status"] == "PASS")
        report["summary"] = {
            "passing": passing,
            "failing": 10 - passing,
            "compliance_score": f"{passing}/10",
        }

        return report
