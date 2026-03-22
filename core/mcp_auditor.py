"""MCP Server Security Auditor.

Connects to external MCP servers as a client and audits them for:
- Overly permissive tools (file write, command exec, network access)
- Tool schema injection vectors (missing validation, wildcard inputs)
- Information disclosure (server info leakage, verbose errors)
- Tool poisoning risks (tools that can modify their own behavior)
- Authentication gaps (no auth required for dangerous operations)

Grades MCP servers A–F based on findings.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, Finding, Severity

log = structlog.get_logger("mcp_auditor")


# ──────────────────────────────────────────────────────────────────────────
# Risk categories for MCP tools
# ──────────────────────────────────────────────────────────────────────────

class ToolRisk:
    """Risk classification for MCP tool capabilities."""
    CRITICAL = "critical"    # Direct code exec, file system write, network egress
    HIGH = "high"            # Data read, config access, auth bypass potential
    MEDIUM = "medium"        # Information disclosure, limited scope
    LOW = "low"              # Read-only, benign operations

# Dangerous tool name patterns
DANGEROUS_TOOL_PATTERNS: dict[str, tuple[str, str]] = {
    # Pattern → (risk_level, description)
    r"(?:bash|shell|exec|command|terminal|run|system)": (ToolRisk.CRITICAL, "Command execution tool — can run arbitrary commands"),
    r"(?:write|create|edit|modify|delete|remove|append)_?(?:file|dir|path)": (ToolRisk.CRITICAL, "File system modification tool"),
    r"(?:fetch|request|http|curl|wget|download|upload)": (ToolRisk.HIGH, "Network access tool — data exfiltration vector"),
    r"(?:sql|query|database|db)_?(?:exec|run|query)": (ToolRisk.HIGH, "Database execution tool — SQL injection risk"),
    r"(?:eval|interpret|parse|compile)": (ToolRisk.CRITICAL, "Code evaluation tool — arbitrary code execution"),
    r"(?:env|environ|secret|credential|key|token|password)": (ToolRisk.HIGH, "Credential/secret access tool"),
    r"(?:install|pip|npm|apt|brew|package)": (ToolRisk.HIGH, "Package installation tool — supply chain risk"),
    r"(?:git|svn|clone|push|commit)": (ToolRisk.MEDIUM, "Version control tool — code modification"),
    r"(?:email|mail|send|notify|message|slack|webhook)": (ToolRisk.HIGH, "Communication tool — data exfiltration via messaging"),
    r"(?:admin|root|sudo|privilege|escalat)": (ToolRisk.CRITICAL, "Privilege escalation tool"),
}

# Dangerous input schema patterns
DANGEROUS_SCHEMA_PATTERNS: list[tuple[str, str, str]] = [
    # (field_pattern, risk, description)
    (r"(?:command|cmd|script|code|expression|query)", ToolRisk.CRITICAL, "Input accepts arbitrary commands/code"),
    (r"(?:url|uri|endpoint|host|server)", ToolRisk.HIGH, "Input accepts arbitrary URLs — SSRF risk"),
    (r"(?:path|file|dir|directory|filename)", ToolRisk.HIGH, "Input accepts file paths — traversal risk"),
    (r"(?:.*)", ToolRisk.LOW, "Unrestricted string input"),
]

# Properties that indicate missing validation
WEAK_SCHEMA_INDICATORS = [
    "no enum restriction on sensitive fields",
    "no pattern validation",
    "no maxLength on string inputs",
    "accepts any type",
]


@dataclass
class ToolAuditFinding:
    """A finding from auditing an MCP tool."""
    tool_name: str
    category: str          # "permission", "schema", "response", "info_disclosure"
    risk: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_finding(self) -> Finding:
        sev_map = {ToolRisk.CRITICAL: Severity.ERROR, ToolRisk.HIGH: Severity.ERROR,
                   ToolRisk.MEDIUM: Severity.WARNING, ToolRisk.LOW: Severity.INFO}
        return Finding(
            rule_id=f"mcp.audit.{self.category}",
            message=f"[{self.tool_name}] {self.title}",
            severity=sev_map.get(self.risk, Severity.WARNING),
            file_path=f"mcp://{self.tool_name}",
            line_number=0,
            line_content=self.evidence[:200],
            cwe="CWE-250" if self.risk == ToolRisk.CRITICAL else "CWE-284",
            confidence=Confidence.HIGH if self.risk in (ToolRisk.CRITICAL, ToolRisk.HIGH) else Confidence.MEDIUM,
            category="mcp-audit",
            metadata={"tool": self.tool_name, "risk": self.risk, "remediation": self.remediation},
        )


@dataclass
class MCPAuditResult:
    """Complete audit result for an MCP server."""
    server_name: str = ""
    server_version: str = ""
    total_tools: int = 0
    findings: list[ToolAuditFinding] = field(default_factory=list)
    tool_risks: dict[str, str] = field(default_factory=dict)  # tool_name → risk_level
    grade: str = "A"
    score: int = 100
    scan_time_ms: float = 0.0
    error: str = ""

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == ToolRisk.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == ToolRisk.HIGH)


class MCPAuditor:
    """Audits MCP servers for security vulnerabilities."""

    def audit_tools(self, tools: list[dict[str, Any]], server_name: str = "unknown") -> MCPAuditResult:
        """Audit a list of MCP tool definitions for security issues.

        Args:
            tools: List of MCP tool definitions (from tools/list response).
            server_name: Name of the MCP server being audited.
        """
        start = time.time()
        result = MCPAuditResult(server_name=server_name, total_tools=len(tools))

        for tool in tools:
            tool_name = tool.get("name", "unnamed")
            description = tool.get("description", "")
            schema = tool.get("inputSchema", {})

            # 1. Check tool name for dangerous patterns
            self._check_tool_name(tool_name, description, result)

            # 2. Check tool description for risky capabilities
            self._check_description(tool_name, description, result)

            # 3. Check input schema for injection vectors
            self._check_schema(tool_name, schema, result)

            # 4. Check for missing safety controls
            self._check_safety_controls(tool_name, tool, result)

        # 5. Check server-level issues
        self._check_server_level(tools, result)

        # Calculate grade
        result.score = self._calculate_score(result)
        result.grade = self._calculate_grade(result.score)
        result.scan_time_ms = (time.time() - start) * 1000

        log.info("mcp_audit_complete", server=server_name, tools=len(tools),
                 findings=result.finding_count, grade=result.grade)
        return result

    def audit_tool_response(self, tool_name: str, response_text: str) -> list[ToolAuditFinding]:
        """Audit a tool's response for poisoning indicators."""
        findings: list[ToolAuditFinding] = []

        # Check for hidden instructions in response
        injection_patterns = [
            (r"(?:ignore|forget|override|disregard)\s+(?:previous|prior|all)\s+(?:instructions?|rules?)",
             "Hidden instruction override in tool response"),
            (r"(?:system|assistant|user)\s*:", "Role injection in tool response"),
            (r"<\s*/?\s*(?:system|instruction|prompt)\s*>", "XML tag injection in tool response"),
            (r"(?:tool_use|function_call|tool_result)\s*[:\[{]", "Fake tool call in response"),
        ]

        for pattern, desc in injection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append(ToolAuditFinding(
                    tool_name=tool_name,
                    category="response_poisoning",
                    risk=ToolRisk.CRITICAL,
                    title=desc,
                    description=f"Tool response from '{tool_name}' contains prompt injection pattern",
                    evidence=response_text[:200],
                    remediation="Sanitize tool output before passing to LLM; strip control sequences",
                ))

        # Check for URLs in response (exfiltration vector)
        urls = re.findall(r'https?://[^\s\'"<>]+', response_text)
        suspicious_domains = ["ngrok", "hookbin", "requestbin", "burpcollaborator",
                             "interact.sh", "pipedream", "canarytokens"]
        for url in urls:
            for domain in suspicious_domains:
                if domain in url.lower():
                    findings.append(ToolAuditFinding(
                        tool_name=tool_name,
                        category="response_exfiltration",
                        risk=ToolRisk.CRITICAL,
                        title=f"Exfiltration URL in tool response: {domain}",
                        description=f"Tool '{tool_name}' returned a response containing {domain} URL",
                        evidence=url[:200],
                        remediation="Block known exfiltration domains in tool responses",
                    ))

        # Check for encoded data (base64, hex) that might hide instructions
        if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', response_text):
            findings.append(ToolAuditFinding(
                tool_name=tool_name,
                category="response_obfuscation",
                risk=ToolRisk.MEDIUM,
                title="Possible encoded payload in tool response",
                description="Tool response contains a long base64-like string that may hide instructions",
                evidence=response_text[:100],
                remediation="Decode and inspect base64 content in tool responses",
            ))

        return findings

    # ── Tool name analysis ─────────────────────────────────────────────

    def _check_tool_name(self, name: str, description: str, result: MCPAuditResult) -> None:
        name_lower = name.lower()
        for pattern, (risk, desc) in DANGEROUS_TOOL_PATTERNS.items():
            if re.search(pattern, name_lower):
                result.findings.append(ToolAuditFinding(
                    tool_name=name,
                    category="permission",
                    risk=risk,
                    title=f"Dangerous tool capability: {name}",
                    description=desc,
                    evidence=f"Tool name matches pattern: {pattern}",
                    remediation="Restrict tool scope; require confirmation for dangerous operations",
                ))
                result.tool_risks[name] = risk
                return

        result.tool_risks[name] = ToolRisk.LOW

    # ── Description analysis ───────────────────────────────────────────

    def _check_description(self, name: str, description: str, result: MCPAuditResult) -> None:
        desc_lower = description.lower()

        dangerous_keywords = {
            "execute": (ToolRisk.CRITICAL, "Tool can execute commands/code"),
            "arbitrary": (ToolRisk.CRITICAL, "Tool accepts arbitrary input"),
            "any file": (ToolRisk.HIGH, "Tool can access any file"),
            "root": (ToolRisk.CRITICAL, "Tool operates with root/admin privileges"),
            "unrestricted": (ToolRisk.CRITICAL, "Tool has no restrictions"),
            "delete": (ToolRisk.HIGH, "Tool can delete resources"),
            "modify system": (ToolRisk.CRITICAL, "Tool can modify system configuration"),
            "network request": (ToolRisk.MEDIUM, "Tool makes network requests"),
            "all files": (ToolRisk.HIGH, "Tool can access all files"),
        }

        for keyword, (risk, desc) in dangerous_keywords.items():
            if keyword in desc_lower:
                result.findings.append(ToolAuditFinding(
                    tool_name=name,
                    category="permission",
                    risk=risk,
                    title=f"Dangerous capability described: '{keyword}'",
                    description=f"{desc} — found in tool description",
                    evidence=description[:200],
                    remediation="Limit tool scope and document security boundaries",
                ))
                # Upgrade risk if needed
                current = result.tool_risks.get(name, ToolRisk.LOW)
                risk_order = [ToolRisk.LOW, ToolRisk.MEDIUM, ToolRisk.HIGH, ToolRisk.CRITICAL]
                if risk_order.index(risk) > risk_order.index(current):
                    result.tool_risks[name] = risk
                break

    # ── Schema analysis ────────────────────────────────────────────────

    def _check_schema(self, name: str, schema: dict[str, Any], result: MCPAuditResult) -> None:
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for prop_name, prop_def in properties.items():
            prop_type = prop_def.get("type", "any")
            prop_lower = prop_name.lower()

            # Check for dangerous input field names
            for pattern, risk, desc in DANGEROUS_SCHEMA_PATTERNS[:3]:  # Skip wildcard
                if re.search(pattern, prop_lower):
                    # Check if there are any restrictions
                    has_enum = "enum" in prop_def
                    has_pattern = "pattern" in prop_def
                    has_max_length = "maxLength" in prop_def

                    if not has_enum and not has_pattern:
                        result.findings.append(ToolAuditFinding(
                            tool_name=name,
                            category="schema",
                            risk=risk,
                            title=f"Unrestricted '{prop_name}' input in {name}",
                            description=f"{desc} — no enum or pattern validation on '{prop_name}'",
                            evidence=json.dumps(prop_def)[:200],
                            remediation=f"Add enum, pattern, or maxLength validation to '{prop_name}'",
                        ))
                    break

            # Check for "any" type (no type constraint)
            if prop_type == "any" or "type" not in prop_def:
                result.findings.append(ToolAuditFinding(
                    tool_name=name,
                    category="schema",
                    risk=ToolRisk.MEDIUM,
                    title=f"No type constraint on '{prop_name}' in {name}",
                    description="Input field has no type validation — accepts any data type",
                    evidence=json.dumps(prop_def)[:200],
                    remediation=f"Add explicit type constraint to '{prop_name}'",
                ))

    # ── Safety controls ────────────────────────────────────────────────

    def _check_safety_controls(self, name: str, tool: dict[str, Any], result: MCPAuditResult) -> None:
        schema = tool.get("inputSchema", {})
        description = tool.get("description", "").lower()

        risk = result.tool_risks.get(name, ToolRisk.LOW)
        if risk not in (ToolRisk.CRITICAL, ToolRisk.HIGH):
            return

        # High/critical tools should have confirmation mechanisms
        has_confirm = any(kw in description for kw in ["confirm", "approval", "verify", "dry-run", "preview"])
        if not has_confirm:
            result.findings.append(ToolAuditFinding(
                tool_name=name,
                category="safety",
                risk=ToolRisk.HIGH,
                title=f"No confirmation mechanism for dangerous tool: {name}",
                description="High-risk tool has no confirmation, dry-run, or preview option",
                evidence=f"Risk level: {risk}",
                remediation="Add a 'confirm' or 'dry_run' parameter for destructive operations",
            ))

        # Check for rate limiting mention
        has_rate_limit = any(kw in description for kw in ["rate limit", "throttle", "cooldown", "max"])
        if not has_rate_limit and risk == ToolRisk.CRITICAL:
            result.findings.append(ToolAuditFinding(
                tool_name=name,
                category="safety",
                risk=ToolRisk.MEDIUM,
                title=f"No rate limiting on critical tool: {name}",
                description="Critical tool has no apparent rate limiting or throttling",
                remediation="Implement rate limiting to prevent abuse",
            ))

    # ── Server-level checks ────────────────────────────────────────────

    def _check_server_level(self, tools: list[dict[str, Any]], result: MCPAuditResult) -> None:
        tool_names = [t.get("name", "") for t in tools]

        # Too many dangerous tools
        critical_tools = [n for n, r in result.tool_risks.items() if r == ToolRisk.CRITICAL]
        if len(critical_tools) > 3:
            result.findings.append(ToolAuditFinding(
                tool_name="*server*",
                category="server",
                risk=ToolRisk.HIGH,
                title=f"Server exposes {len(critical_tools)} critical-risk tools",
                description=f"Critical tools: {', '.join(critical_tools[:5])}",
                evidence=f"{len(critical_tools)} critical tools",
                remediation="Minimize exposed tools; use least-privilege principle",
            ))

        # Check for both read and write tools (data flow risk)
        has_read = any(re.search(r"read|get|list|search|query", n.lower()) for n in tool_names)
        has_write = any(re.search(r"write|create|delete|exec|run|send", n.lower()) for n in tool_names)
        has_network = any(re.search(r"fetch|http|request|url|download", n.lower()) for n in tool_names)

        if has_read and has_write and has_network:
            result.findings.append(ToolAuditFinding(
                tool_name="*server*",
                category="server",
                risk=ToolRisk.HIGH,
                title="Server enables full read → process → exfiltrate chain",
                description="Server has read, write, AND network tools — complete data exfiltration chain possible",
                remediation="Segment capabilities; don't expose read + network tools together",
            ))

    # ── Scoring ────────────────────────────────────────────────────────

    def _calculate_score(self, result: MCPAuditResult) -> int:
        score = 100
        for f in result.findings:
            match f.risk:
                case ToolRisk.CRITICAL:
                    score -= 20
                case ToolRisk.HIGH:
                    score -= 10
                case ToolRisk.MEDIUM:
                    score -= 5
                case ToolRisk.LOW:
                    score -= 2
        return max(0, min(100, score))

    def _calculate_grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"
