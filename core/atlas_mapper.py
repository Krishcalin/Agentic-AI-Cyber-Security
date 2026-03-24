"""ATLAS Mapper — maps scanner findings to MITRE ATLAS technique IDs.

Provides a complete mapping between scanner findings (CWE-based, category-based,
engine-based) and MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
technique IDs. Generates ATLAS Navigator-compatible JSON layers for visualization.

ATLAS coverage: 15 tactics, 66+ techniques including LLM-specific (T0050-T0060)
and agentic AI techniques (T0096-T0102).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger("atlas_mapper")


# ── ATLAS Taxonomy ────────────────────────────────────────────────────────

@dataclass
class ATLASTactic:
    """An ATLAS tactic (adversary goal)."""
    tactic_id: str
    name: str
    description: str


@dataclass
class ATLASTechnique:
    """An ATLAS technique."""
    technique_id: str
    name: str
    tactic_ids: list[str]
    description: str
    subtechniques: list[str] = field(default_factory=list)
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            tid = self.technique_id.replace(".", "/")
            self.url = f"https://atlas.mitre.org/techniques/{tid}"


@dataclass
class ATLASMapping:
    """A mapping from a scanner finding to an ATLAS technique."""
    technique_id: str
    technique_name: str
    tactic_ids: list[str]
    confidence: float  # 0.0 - 1.0
    rationale: str


@dataclass
class ATLASMappingResult:
    """Result of mapping findings to ATLAS."""
    total_findings: int
    mapped_findings: int
    unmapped_findings: int
    techniques_covered: list[str]
    tactics_covered: list[str]
    mappings: list[dict[str, Any]]
    coverage_percent: float
    analysis_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "mapped": self.mapped_findings,
            "unmapped": self.unmapped_findings,
            "techniques_covered": len(self.techniques_covered),
            "tactics_covered": len(self.tactics_covered),
            "coverage_percent": round(self.coverage_percent, 1),
            "technique_ids": self.techniques_covered,
            "tactic_ids": self.tactics_covered,
            "mappings": self.mappings,
            "analysis_time_ms": round(self.analysis_time_ms, 1),
        }


# ── ATLAS Tactics Registry ───────────────────────────────────────────────

ATLAS_TACTICS: dict[str, ATLASTactic] = {
    "AML.TA0001": ATLASTactic("AML.TA0001", "Reconnaissance", "Gathering info about AI systems"),
    "AML.TA0002": ATLASTactic("AML.TA0002", "Resource Development", "Acquiring resources for attacks"),
    "AML.TA0003": ATLASTactic("AML.TA0003", "Initial Access", "Gaining entry to AI system"),
    "AML.TA0004": ATLASTactic("AML.TA0004", "ML Model Access", "Accessing the ML model"),
    "AML.TA0005": ATLASTactic("AML.TA0005", "Execution", "Running adversary-controlled code"),
    "AML.TA0006": ATLASTactic("AML.TA0006", "Persistence", "Maintaining access to AI system"),
    "AML.TA0007": ATLASTactic("AML.TA0007", "Privilege Escalation", "Gaining elevated access"),
    "AML.TA0008": ATLASTactic("AML.TA0008", "Defense Evasion", "Avoiding detection"),
    "AML.TA0009": ATLASTactic("AML.TA0009", "Credential Access", "Stealing credentials"),
    "AML.TA0010": ATLASTactic("AML.TA0010", "Discovery", "Exploring the AI environment"),
    "AML.TA0011": ATLASTactic("AML.TA0011", "Collection", "Gathering data of interest"),
    "AML.TA0012": ATLASTactic("AML.TA0012", "ML Attack Staging", "Preparing ML-specific attacks"),
    "AML.TA0013": ATLASTactic("AML.TA0013", "Exfiltration", "Stealing data from AI systems"),
    "AML.TA0014": ATLASTactic("AML.TA0014", "Impact", "Disrupting or degrading AI systems"),
    "AML.TA0015": ATLASTactic("AML.TA0015", "Agentic Threats", "Exploiting autonomous AI agents"),
}


# ── ATLAS Techniques Registry ─────────────────────────────────────────────

ATLAS_TECHNIQUES: dict[str, ATLASTechnique] = {
    # ── Reconnaissance ────────────────────────────────────────────────
    "AML.T0000": ATLASTechnique("AML.T0000", "Search Victim's Research Materials", ["AML.TA0001"],
        "Search for victim's ML research papers, blogs, conference talks",
        subtechniques=["AML.T0000.000", "AML.T0000.001", "AML.T0000.002"]),
    "AML.T0001": ATLASTechnique("AML.T0001", "Search Public Adversarial Vulnerability Analysis", ["AML.TA0001"],
        "Search for known adversarial vulnerabilities in victim's ML models"),
    "AML.T0003": ATLASTechnique("AML.T0003", "Search Victim-Owned Websites", ["AML.TA0001"],
        "Search victim's websites for ML system information"),
    "AML.T0004": ATLASTechnique("AML.T0004", "Search Application Repositories", ["AML.TA0001"],
        "Search code repos for ML model details, configs, API keys"),
    "AML.T0006": ATLASTechnique("AML.T0006", "Active Scanning", ["AML.TA0001"],
        "Actively probe AI system endpoints for vulnerabilities"),

    # ── Resource Development ──────────────────────────────────────────
    "AML.T0002": ATLASTechnique("AML.T0002", "Acquire Public ML Artifacts", ["AML.TA0002"],
        "Acquire public datasets and models for attack staging",
        subtechniques=["AML.T0002.000", "AML.T0002.001"]),
    "AML.T0008": ATLASTechnique("AML.T0008", "Acquire Infrastructure", ["AML.TA0002"],
        "Acquire ML development workspaces, hardware, domains",
        subtechniques=["AML.T0008.000", "AML.T0008.001", "AML.T0008.002", "AML.T0008.003"]),
    "AML.T0016": ATLASTechnique("AML.T0016", "Obtain Capabilities", ["AML.TA0002"],
        "Obtain adversarial ML attack tools and implementations",
        subtechniques=["AML.T0016.000", "AML.T0016.001"]),
    "AML.T0017": ATLASTechnique("AML.T0017", "Develop Capabilities", ["AML.TA0002"],
        "Develop custom adversarial ML attacks",
        subtechniques=["AML.T0017.000"]),
    "AML.T0019": ATLASTechnique("AML.T0019", "Publish Poisoned Datasets", ["AML.TA0002"],
        "Publish poisoned datasets to public repositories"),
    "AML.T0020": ATLASTechnique("AML.T0020", "Poison Training Data", ["AML.TA0002"],
        "Introduce malicious data into training pipeline"),
    "AML.T0021": ATLASTechnique("AML.T0021", "Establish Accounts", ["AML.TA0002"],
        "Create accounts on AI platforms for attack staging"),

    # ── Initial Access ────────────────────────────────────────────────
    "AML.T0010": ATLASTechnique("AML.T0010", "ML Supply Chain Compromise", ["AML.TA0003"],
        "Compromise ML supply chain: hardware, software, data, models",
        subtechniques=["AML.T0010.000", "AML.T0010.001", "AML.T0010.002", "AML.T0010.003"]),
    "AML.T0011": ATLASTechnique("AML.T0011", "User Execution", ["AML.TA0003"],
        "Trick user into executing unsafe ML artifacts or malicious packages",
        subtechniques=["AML.T0011.000", "AML.T0011.001"]),
    "AML.T0012": ATLASTechnique("AML.T0012", "Valid Accounts", ["AML.TA0003"],
        "Use valid credentials to access AI systems"),
    "AML.T0015": ATLASTechnique("AML.T0015", "Evade ML Model", ["AML.TA0003", "AML.TA0008"],
        "Craft inputs that cause ML model to produce incorrect outputs"),

    # ── ML Model Access ───────────────────────────────────────────────
    "AML.T0040": ATLASTechnique("AML.T0040", "AI Model Inference API Access", ["AML.TA0004"],
        "Access ML model through inference API for queries"),
    "AML.T0041": ATLASTechnique("AML.T0041", "Physical Environment Access", ["AML.TA0004"],
        "Access physical environment where ML model operates"),
    "AML.T0044": ATLASTechnique("AML.T0044", "Full ML Model Access", ["AML.TA0004"],
        "Gain full white-box access to ML model weights and architecture"),

    # ── Execution ─────────────────────────────────────────────────────
    "AML.T0050": ATLASTechnique("AML.T0050", "Command and Scripting Interpreter", ["AML.TA0005"],
        "Execute commands via AI system's scripting capabilities"),
    "AML.T0051": ATLASTechnique("AML.T0051", "LLM Prompt Injection", ["AML.TA0005"],
        "Manipulate LLM behavior through crafted prompts",
        subtechniques=["AML.T0051.000", "AML.T0051.001"]),
    "AML.T0052": ATLASTechnique("AML.T0052", "LLM Prompt Self-Replication", ["AML.TA0005"],
        "Self-replicating prompt that embeds itself in LLM output"),
    "AML.T0053": ATLASTechnique("AML.T0053", "LLM Plugin Compromise", ["AML.TA0005"],
        "Exploit vulnerable LLM plugins to extend attacker capabilities"),

    # ── Persistence ───────────────────────────────────────────────────
    "AML.T0018": ATLASTechnique("AML.T0018", "Backdoor ML Model", ["AML.TA0006"],
        "Insert backdoor into ML model for persistent access",
        subtechniques=["AML.T0018.000", "AML.T0018.001"]),

    # ── Defense Evasion ───────────────────────────────────────────────
    "AML.T0054": ATLASTechnique("AML.T0054", "LLM Jailbreak", ["AML.TA0008"],
        "Bypass LLM safety controls, restrictions, and guardrails"),
    "AML.T0043": ATLASTechnique("AML.T0043", "Craft Adversarial Data", ["AML.TA0012", "AML.TA0008"],
        "Create adversarial inputs to mislead ML models",
        subtechniques=["AML.T0043.000", "AML.T0043.001", "AML.T0043.002", "AML.T0043.003", "AML.T0043.004"]),

    # ── Credential Access ─────────────────────────────────────────────
    "AML.T0055": ATLASTechnique("AML.T0055", "Unsecured Credentials", ["AML.TA0009"],
        "Access unsecured credentials in AI system configs, code, or environment"),

    # ── Discovery ─────────────────────────────────────────────────────
    "AML.T0007": ATLASTechnique("AML.T0007", "Discover ML Artifacts", ["AML.TA0010"],
        "Discover ML models, datasets, configs in the environment"),
    "AML.T0013": ATLASTechnique("AML.T0013", "Discover ML Model Ontology", ["AML.TA0010"],
        "Determine ML model's input/output ontology"),
    "AML.T0014": ATLASTechnique("AML.T0014", "Discover ML Model Family", ["AML.TA0010"],
        "Identify the architecture family of the target ML model"),

    # ── Collection ────────────────────────────────────────────────────
    "AML.T0035": ATLASTechnique("AML.T0035", "ML Artifact Collection", ["AML.TA0011"],
        "Collect ML models, datasets, notebooks, configs"),
    "AML.T0036": ATLASTechnique("AML.T0036", "Data from Information Repositories", ["AML.TA0011"],
        "Collect data from wikis, knowledge bases, vector stores"),
    "AML.T0037": ATLASTechnique("AML.T0037", "Data from Local System", ["AML.TA0011"],
        "Collect sensitive data from local filesystem"),

    # ── ML Attack Staging ─────────────────────────────────────────────
    "AML.T0005": ATLASTechnique("AML.T0005", "Create Proxy ML Model", ["AML.TA0012"],
        "Create substitute model to test attacks against",
        subtechniques=["AML.T0005.000", "AML.T0005.001", "AML.T0005.002"]),
    "AML.T0042": ATLASTechnique("AML.T0042", "Verify Attack", ["AML.TA0012"],
        "Verify adversarial attack works before deployment"),

    # ── Exfiltration ──────────────────────────────────────────────────
    "AML.T0024": ATLASTechnique("AML.T0024", "Exfiltration via ML Inference API", ["AML.TA0013"],
        "Extract training data or model via inference queries",
        subtechniques=["AML.T0024.000", "AML.T0024.001", "AML.T0024.002"]),
    "AML.T0025": ATLASTechnique("AML.T0025", "Exfiltration via Cyber Means", ["AML.TA0013"],
        "Exfiltrate data using traditional cyber techniques"),
    "AML.T0056": ATLASTechnique("AML.T0056", "LLM Data Leakage", ["AML.TA0013"],
        "Extract sensitive data from LLM outputs including PII, secrets, training data"),

    # ── Impact ────────────────────────────────────────────────────────
    "AML.T0029": ATLASTechnique("AML.T0029", "Denial of ML Service", ["AML.TA0014"],
        "Disrupt availability of ML-powered service"),
    "AML.T0031": ATLASTechnique("AML.T0031", "Erode ML Model Integrity", ["AML.TA0014"],
        "Degrade ML model performance over time"),
    "AML.T0034": ATLASTechnique("AML.T0034", "Cost Harvesting", ["AML.TA0014"],
        "Cause excessive compute costs via resource-intensive queries"),
    "AML.T0046": ATLASTechnique("AML.T0046", "Spam ML System with Chaff Data", ["AML.TA0014"],
        "Flood ML system with junk data to degrade performance"),
    "AML.T0048": ATLASTechnique("AML.T0048", "External Harms", ["AML.TA0014"],
        "Financial, reputational, or societal harm from AI system compromise",
        subtechniques=["AML.T0048.000", "AML.T0048.001", "AML.T0048.002"]),
    "AML.T0047": ATLASTechnique("AML.T0047", "ML-Enabled Product or Service", ["AML.TA0014"],
        "Abuse ML-enabled product for unintended purposes"),

    # ── Agentic AI Techniques (2025-2026) ─────────────────────────────
    "AML.T0057": ATLASTechnique("AML.T0057", "LLM Data Leakage via Prompt", ["AML.TA0013", "AML.TA0015"],
        "Self-replicating prompt paired with data exfiltration instructions"),
    "AML.T0058": ATLASTechnique("AML.T0058", "AI Agent Context Poisoning", ["AML.TA0015"],
        "Inject malicious content into agent memory or thread context"),
    "AML.T0059": ATLASTechnique("AML.T0059", "Activation Triggers", ["AML.TA0015"],
        "Embed triggers that activate agent behavior under specific conditions"),
    "AML.T0060": ATLASTechnique("AML.T0060", "Data from AI Services", ["AML.TA0011", "AML.TA0015"],
        "Extract data through RAG database retrieval or AI service APIs"),
    "AML.T0096": ATLASTechnique("AML.T0096", "AI Service API Exploitation", ["AML.TA0015"],
        "Exploit AI service APIs for stealth operations and persistent access"),
    "AML.T0098": ATLASTechnique("AML.T0098", "Agent Tool Credential Harvesting", ["AML.TA0009", "AML.TA0015"],
        "Retrieve credentials and API keys from agent-accessible tools and data sources"),
    "AML.T0099": ATLASTechnique("AML.T0099", "Agent Tool Data Poisoning", ["AML.TA0015"],
        "Place malicious content where agents access it to hijack behavior"),
    "AML.T0100": ATLASTechnique("AML.T0100", "AI Agent Clickbait", ["AML.TA0015"],
        "Lure AI browsers into unintended actions via deceptive UI elements"),
    "AML.T0101": ATLASTechnique("AML.T0101", "Data Destruction via Agent Tool", ["AML.TA0014", "AML.TA0015"],
        "Leverage agent capabilities to destroy data and files"),
    "AML.T0102": ATLASTechnique("AML.T0102", "Generate Malicious Commands", ["AML.TA0005", "AML.TA0015"],
        "Cause agent to generate and execute malicious commands"),
}


# ── Finding → ATLAS Mapping Rules ─────────────────────────────────────────

# Maps scanner categories, CWEs, rule IDs, and engine names to ATLAS techniques
# Format: (match_field, match_value) → (technique_id, confidence, rationale)

CATEGORY_MAPPINGS: dict[str, list[tuple[str, float, str]]] = {
    # Prompt injection patterns
    "jailbreak": [
        ("AML.T0054", 0.95, "Direct LLM jailbreak attempt"),
        ("AML.T0051", 0.80, "Prompt injection to bypass controls"),
    ],
    "extraction": [
        ("AML.T0056", 0.90, "LLM data leakage via extraction prompt"),
        ("AML.T0024", 0.70, "Data exfiltration via inference API"),
    ],
    "exfiltration": [
        ("AML.T0025", 0.90, "Data exfiltration via cyber means"),
        ("AML.T0056", 0.80, "LLM data leakage"),
    ],
    "hidden_instruction": [
        ("AML.T0051.001", 0.95, "Indirect prompt injection via hidden instructions"),
        ("AML.T0058", 0.80, "Agent context poisoning via hidden instructions"),
    ],
    "indirect_injection": [
        ("AML.T0051.001", 0.95, "Indirect prompt injection in external data"),
        ("AML.T0099", 0.85, "Agent tool data poisoning"),
    ],
    "tool_abuse": [
        ("AML.T0053", 0.90, "LLM plugin/tool compromise"),
        ("AML.T0102", 0.85, "Generate malicious commands via tool abuse"),
    ],
    "code_injection": [
        ("AML.T0050", 0.90, "Command and scripting interpreter abuse"),
        ("AML.T0102", 0.80, "Malicious command generation"),
    ],
    "social_engineering": [
        ("AML.T0054", 0.75, "Social engineering to bypass LLM guardrails"),
    ],
    "multi_turn": [
        ("AML.T0054", 0.80, "Multi-turn jailbreak attack"),
        ("AML.T0059", 0.70, "Activation trigger across conversation turns"),
    ],

    # RAG and document injection
    "document_injection": [
        ("AML.T0051.001", 0.90, "Indirect injection via document content"),
        ("AML.T0099", 0.85, "Agent tool data poisoning via documents"),
        ("AML.T0020", 0.70, "Training data poisoning via RAG documents"),
    ],
    "sensitive_data": [
        ("AML.T0056", 0.85, "Sensitive data exposure in AI pipeline"),
        ("AML.T0037", 0.75, "Data from local system"),
    ],

    # MCP and tool response
    "mcp_poisoning": [
        ("AML.T0058", 0.90, "Agent context poisoning via tool response"),
        ("AML.T0053", 0.85, "LLM plugin compromise"),
        ("AML.T0099", 0.80, "Agent tool data poisoning"),
    ],
    "tool_response_injection": [
        ("AML.T0058", 0.90, "Context poisoning via injected tool output"),
        ("AML.T0051.001", 0.80, "Indirect prompt injection in tool response"),
    ],
    "tool_response_exfiltration": [
        ("AML.T0025", 0.85, "Exfiltration URLs in tool response"),
        ("AML.T0096", 0.75, "AI service API exploitation for exfiltration"),
    ],
    "tool_response_escalation": [
        ("AML.T0102", 0.85, "Malicious command generation via escalation"),
        ("AML.T0053", 0.75, "LLM plugin compromise for privilege escalation"),
    ],

    # Chain detector categories
    "exfiltration_chain": [
        ("AML.T0025", 0.95, "Multi-step data exfiltration chain"),
        ("AML.T0098", 0.80, "Agent tool credential harvesting"),
    ],
    "persistence": [
        ("AML.T0018", 0.80, "Backdoor/persistence in ML system"),
        ("AML.T0059", 0.75, "Activation trigger for persistent access"),
    ],
    "privilege_escalation": [
        ("AML.T0055", 0.80, "Unsecured credentials for privilege escalation"),
    ],
    "lateral_movement": [
        ("AML.T0096", 0.80, "AI service API exploitation for lateral movement"),
    ],
    "supply_chain": [
        ("AML.T0010", 0.95, "ML supply chain compromise"),
        ("AML.T0010.001", 0.90, "Compromised ML software"),
        ("AML.T0011.001", 0.85, "Malicious package execution"),
    ],
    "defense_evasion": [
        ("AML.T0054", 0.80, "LLM jailbreak evasion"),
        ("AML.T0015", 0.70, "ML model evasion"),
    ],
    "impact": [
        ("AML.T0101", 0.85, "Data destruction via agent tool"),
        ("AML.T0029", 0.70, "Denial of ML service"),
    ],
    "reconnaissance": [
        ("AML.T0006", 0.75, "Active scanning of AI system"),
        ("AML.T0007", 0.70, "Discover ML artifacts"),
    ],

    # Source code scanning categories
    "injection": [
        ("AML.T0050", 0.70, "Command/code injection in AI application"),
    ],
    "secrets": [
        ("AML.T0055", 0.90, "Unsecured credentials in AI system code"),
        ("AML.T0098", 0.75, "Credential harvesting from source code"),
    ],
    "crypto": [
        ("AML.T0055", 0.60, "Weak crypto protecting AI system credentials"),
    ],
    "deserialization": [
        ("AML.T0011.000", 0.85, "Unsafe ML artifact deserialization"),
        ("AML.T0018.001", 0.75, "Payload injection via deserialization"),
    ],
    "xss": [
        ("AML.T0050", 0.60, "Script injection in AI-powered web application"),
    ],

    # Package/dependency categories
    "malicious_package": [
        ("AML.T0010.001", 0.95, "Malicious ML software package"),
        ("AML.T0011.001", 0.90, "Malicious package installation"),
    ],
    "typosquatting": [
        ("AML.T0010.001", 0.85, "Typosquat ML software supply chain attack"),
    ],
    "dependency_confusion": [
        ("AML.T0010", 0.90, "Dependency confusion supply chain attack"),
    ],
}

# CWE → ATLAS technique mappings (for findings with CWE but no category match)
CWE_MAPPINGS: dict[str, list[tuple[str, float, str]]] = {
    "CWE-78": [("AML.T0050", 0.80, "OS command injection in AI system")],
    "CWE-79": [("AML.T0050", 0.60, "XSS in AI-powered web interface")],
    "CWE-89": [("AML.T0050", 0.70, "SQL injection in AI data pipeline")],
    "CWE-94": [("AML.T0050", 0.85, "Code injection in AI system")],
    "CWE-502": [("AML.T0011.000", 0.85, "Unsafe deserialization of ML artifacts"),
                ("AML.T0018.001", 0.75, "Backdoor payload via deserialization")],
    "CWE-798": [("AML.T0055", 0.90, "Hardcoded credentials in AI application")],
    "CWE-312": [("AML.T0055", 0.85, "Cleartext storage of AI system credentials")],
    "CWE-522": [("AML.T0055", 0.80, "Insufficiently protected credentials")],
    "CWE-532": [("AML.T0056", 0.70, "Information exposure through log files")],
    "CWE-295": [("AML.T0055", 0.65, "Improper certificate validation — MITM risk")],
    "CWE-327": [("AML.T0055", 0.60, "Broken crypto protecting AI credentials")],
    "CWE-328": [("AML.T0055", 0.55, "Weak hash protecting AI system secrets")],
    "CWE-22": [("AML.T0037", 0.70, "Path traversal to access AI system data")],
    "CWE-269": [("AML.T0055", 0.70, "Privilege escalation in AI system")],
    "CWE-732": [("AML.T0055", 0.65, "Incorrect permissions on AI artifacts")],
}


# ── ATLAS Mapper Engine ───────────────────────────────────────────────────

class ATLASMapper:
    """Maps scanner findings to MITRE ATLAS technique IDs.

    Usage:
        mapper = ATLASMapper()

        # Map a list of findings
        result = mapper.map_findings(findings)

        # Map a single finding
        mappings = mapper.map_finding(finding)

        # Generate Navigator JSON layer
        layer = mapper.generate_navigator_layer(findings)

        # Get technique info
        technique = mapper.get_technique("AML.T0051")
    """

    def __init__(self) -> None:
        self.techniques = ATLAS_TECHNIQUES
        self.tactics = ATLAS_TACTICS
        self.category_mappings = CATEGORY_MAPPINGS
        self.cwe_mappings = CWE_MAPPINGS

    @property
    def technique_count(self) -> int:
        return len(self.techniques)

    @property
    def tactic_count(self) -> int:
        return len(self.tactics)

    def get_technique(self, technique_id: str) -> ATLASTechnique | None:
        """Get technique details by ID."""
        return self.techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> ATLASTactic | None:
        """Get tactic details by ID."""
        return self.tactics.get(tactic_id)

    def map_finding(self, finding: dict[str, Any]) -> list[ATLASMapping]:
        """Map a single finding to ATLAS technique(s).

        Args:
            finding: Dict with keys like 'category', 'cwe', 'rule_id', 'engine', 'message'

        Returns:
            List of ATLASMapping objects (may be empty if no match)
        """
        mappings: list[ATLASMapping] = []
        seen_techniques: set[str] = set()

        # 1. Try category-based mapping (highest confidence)
        category = finding.get("category", "").lower()
        if category in self.category_mappings:
            for tech_id, confidence, rationale in self.category_mappings[category]:
                if tech_id not in seen_techniques:
                    technique = self.techniques.get(tech_id.split(".")[0] if "." in tech_id and tech_id.count(".") > 1 else tech_id)
                    # Also check for sub-techniques
                    if not technique:
                        parent_id = ".".join(tech_id.split(".")[:2])
                        technique = self.techniques.get(parent_id)
                    if technique:
                        mappings.append(ATLASMapping(
                            technique_id=tech_id,
                            technique_name=technique.name,
                            tactic_ids=technique.tactic_ids,
                            confidence=confidence,
                            rationale=rationale,
                        ))
                        seen_techniques.add(tech_id)

        # 2. Try CWE-based mapping (fallback)
        cwe = finding.get("cwe", "")
        if cwe and cwe in self.cwe_mappings:
            for tech_id, confidence, rationale in self.cwe_mappings[cwe]:
                if tech_id not in seen_techniques:
                    technique = self.techniques.get(tech_id.split(".")[0] if "." in tech_id and tech_id.count(".") > 1 else tech_id)
                    if not technique:
                        parent_id = ".".join(tech_id.split(".")[:2])
                        technique = self.techniques.get(parent_id)
                    if technique:
                        mappings.append(ATLASMapping(
                            technique_id=tech_id,
                            technique_name=technique.name,
                            tactic_ids=technique.tactic_ids,
                            confidence=confidence * 0.9,  # Slight discount for CWE-only match
                            rationale=rationale,
                        ))
                        seen_techniques.add(tech_id)

        # Sort by confidence descending
        mappings.sort(key=lambda m: m.confidence, reverse=True)
        return mappings

    def map_findings(self, findings: list[dict[str, Any]]) -> ATLASMappingResult:
        """Map a list of findings to ATLAS techniques.

        Args:
            findings: List of finding dicts

        Returns:
            ATLASMappingResult with aggregated stats and mappings
        """
        start = time.time()
        all_mappings: list[dict[str, Any]] = []
        mapped_count = 0
        techniques_seen: set[str] = set()
        tactics_seen: set[str] = set()

        for finding in findings:
            atlas_maps = self.map_finding(finding)
            if atlas_maps:
                mapped_count += 1
                best = atlas_maps[0]  # Highest confidence
                techniques_seen.add(best.technique_id)
                tactics_seen.update(best.tactic_ids)

                all_mappings.append({
                    "finding": {
                        "rule_id": finding.get("rule_id", ""),
                        "category": finding.get("category", ""),
                        "cwe": finding.get("cwe", ""),
                        "message": finding.get("message", "")[:100],
                    },
                    "atlas_technique": best.technique_id,
                    "atlas_name": best.technique_name,
                    "atlas_tactics": best.tactic_ids,
                    "confidence": round(best.confidence, 2),
                    "rationale": best.rationale,
                    "alternate_techniques": [
                        {"id": m.technique_id, "confidence": round(m.confidence, 2)}
                        for m in atlas_maps[1:3]  # Top 3 alternatives
                    ],
                })

        total = len(findings)
        elapsed = (time.time() - start) * 1000

        return ATLASMappingResult(
            total_findings=total,
            mapped_findings=mapped_count,
            unmapped_findings=total - mapped_count,
            techniques_covered=sorted(techniques_seen),
            tactics_covered=sorted(tactics_seen),
            mappings=all_mappings,
            coverage_percent=(mapped_count / total * 100) if total > 0 else 0,
            analysis_time_ms=elapsed,
        )

    def generate_navigator_layer(
        self,
        findings: list[dict[str, Any]],
        layer_name: str = "Agentic AI Security Scan",
    ) -> dict[str, Any]:
        """Generate an ATLAS Navigator-compatible JSON layer.

        The output can be loaded into the ATLAS Navigator at
        https://mitre-atlas.github.io/atlas-navigator/ for visualization.

        Args:
            findings: List of finding dicts to map
            layer_name: Display name for the layer

        Returns:
            Navigator JSON layer dict
        """
        # Count technique hits
        technique_counts: dict[str, int] = {}
        technique_scores: dict[str, float] = {}

        for finding in findings:
            atlas_maps = self.map_finding(finding)
            for m in atlas_maps[:2]:  # Top 2 mappings per finding
                tid = m.technique_id
                technique_counts[tid] = technique_counts.get(tid, 0) + 1
                technique_scores[tid] = max(technique_scores.get(tid, 0), m.confidence)

        # Build technique entries
        techniques = []
        for tech_id, count in technique_counts.items():
            score = technique_scores.get(tech_id, 0)
            # Color gradient: 1=green (low), 2-3=yellow, 4+=red
            color = _score_color(count)

            techniques.append({
                "techniqueID": tech_id,
                "score": count,
                "color": color,
                "comment": f"Detected {count} time(s), confidence: {score:.0%}",
                "enabled": True,
                "showSubtechniques": True,
            })

        # Navigator layer format
        layer = {
            "name": layer_name,
            "versions": {
                "atlas": "4.5.2",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "atlas",
            "description": f"Security scan results mapped to MITRE ATLAS. "
                          f"{len(technique_counts)} techniques detected across {len(findings)} findings.",
            "filters": {
                "platforms": ["AI/ML Systems", "LLM Applications", "AI Agents"],
            },
            "sorting": 3,  # Sort by score descending
            "layout": {
                "layout": "flat",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
                "aggregateFunction": "max",
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#a1d99b", "#fdae6b", "#e6550d"],
                "minValue": 1,
                "maxValue": 10,
            },
            "legendItems": [
                {"label": "1 finding", "color": "#a1d99b"},
                {"label": "2-3 findings", "color": "#fdae6b"},
                {"label": "4+ findings", "color": "#e6550d"},
            ],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": True,
            "selectVisibleTechniques": False,
        }

        return layer

    def generate_coverage_report(self) -> dict[str, Any]:
        """Generate a report showing which ATLAS techniques our scanner can detect."""
        covered: list[dict[str, Any]] = []
        uncovered: list[dict[str, Any]] = []

        # Collect all technique IDs referenced in our mappings
        covered_ids: set[str] = set()
        for mappings_list in self.category_mappings.values():
            for tech_id, _, _ in mappings_list:
                covered_ids.add(tech_id)
        for mappings_list in self.cwe_mappings.values():
            for tech_id, _, _ in mappings_list:
                covered_ids.add(tech_id)

        for tech_id, technique in sorted(self.techniques.items()):
            entry = {
                "technique_id": tech_id,
                "name": technique.name,
                "tactics": [self.tactics[t].name for t in technique.tactic_ids if t in self.tactics],
            }
            # Check if covered (also check parent for sub-techniques)
            if tech_id in covered_ids:
                entry["status"] = "covered"
                covered.append(entry)
            else:
                # Check if any sub-technique is covered
                parent_covered = any(
                    cid.startswith(tech_id) for cid in covered_ids
                )
                if parent_covered:
                    entry["status"] = "partial"
                    covered.append(entry)
                else:
                    entry["status"] = "gap"
                    uncovered.append(entry)

        total = len(self.techniques)
        return {
            "total_atlas_techniques": total,
            "covered": len(covered),
            "uncovered": len(uncovered),
            "coverage_percent": round(len(covered) / total * 100, 1) if total else 0,
            "covered_techniques": covered,
            "uncovered_techniques": uncovered,
        }


# ── Helpers ───────────────────────────────────────────────────────────────

def _score_color(count: int) -> str:
    """Map finding count to heat map color."""
    if count <= 1:
        return "#a1d99b"  # Green — low
    elif count <= 3:
        return "#fdae6b"  # Orange — medium
    else:
        return "#e6550d"  # Red — high
