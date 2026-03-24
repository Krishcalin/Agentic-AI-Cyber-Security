"""Agent Sandbox Evaluator — evaluates agent runtime isolation and sandboxing.

Checks whether an AI agent's runtime environment has proper security controls:
- Filesystem isolation (read-only mounts, restricted paths)
- Network isolation (egress filtering, allowed domains)
- Process isolation (no shell access, no subprocess spawning)
- Resource limits (memory, CPU, file descriptors)
- Credential isolation (no env var secrets, no mounted credentials)
- Permission boundaries (least privilege, no root)

Covers ATLAS techniques AML.T0050, AML.T0102, AML.T0006.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger("sandbox_evaluator")


@dataclass
class SandboxFinding:
    """A sandbox configuration issue."""
    finding_id: str
    category: str
    risk: str
    title: str
    description: str
    remediation: str
    atlas_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "atlas_technique": self.atlas_technique,
        }


@dataclass
class SandboxConfig:
    """Agent sandbox configuration to evaluate."""
    # Filesystem
    writable_paths: list[str] = field(default_factory=list)
    readable_paths: list[str] = field(default_factory=list)
    root_filesystem_access: bool = False

    # Network
    network_enabled: bool = True
    allowed_domains: list[str] = field(default_factory=list)
    egress_filtering: bool = False

    # Process
    shell_access: bool = True
    subprocess_allowed: bool = True
    allowed_commands: list[str] = field(default_factory=list)

    # Resources
    memory_limit_mb: int = 0  # 0 = unlimited
    cpu_limit_percent: int = 0
    max_file_descriptors: int = 0
    max_processes: int = 0
    timeout_seconds: int = 0

    # Credentials
    env_vars: list[str] = field(default_factory=list)
    mounted_secrets: list[str] = field(default_factory=list)

    # Identity
    runs_as_root: bool = False
    user: str = ""

    # Tools
    available_tools: list[str] = field(default_factory=list)
    tool_confirmation_required: bool = False


@dataclass
class SandboxEvalResult:
    """Result of sandbox evaluation."""
    score: int  # 0-100
    grade: str  # A-F
    findings: list[SandboxFinding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "critical")

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "findings_count": self.finding_count,
            "critical": self.critical_count,
            "findings": [f.to_dict() for f in self.findings],
        }


SENSITIVE_ENV_PATTERNS = [
    r"(?i)(AWS_SECRET|AWS_ACCESS_KEY|AZURE_CLIENT_SECRET|GCP_KEY|GOOGLE_APPLICATION_CREDENTIALS)",
    r"(?i)(DATABASE_URL|DB_PASSWORD|REDIS_URL|MONGO_URI)",
    r"(?i)(API_KEY|API_SECRET|AUTH_TOKEN|JWT_SECRET|SESSION_SECRET)",
    r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY)",
    r"(?i)(PRIVATE_KEY|SSH_KEY|SSL_CERT_KEY)",
    r"(?i)(STRIPE_SECRET|SENDGRID_API_KEY|TWILIO_AUTH)",
    r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL)",
]

DANGEROUS_TOOLS = [
    "execute_command", "run_command", "bash", "shell", "terminal",
    "write_file", "delete_file", "move_file",
    "fetch_url", "http_request", "web_fetch",
    "install_package", "pip_install", "npm_install",
    "send_email", "send_message", "post_webhook",
]

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "~/.ssh", "~/.aws", "~/.kube/config", "~/.docker/config.json",
    "/var/run/docker.sock", "/proc", "/sys",
]


class SandboxEvaluator:
    """Evaluates agent runtime sandbox configuration.

    Usage:
        evaluator = SandboxEvaluator()

        config = SandboxConfig(
            shell_access=True,
            network_enabled=True,
            runs_as_root=True,
        )
        result = evaluator.evaluate(config)
        print(f"Score: {result.score}/100 ({result.grade})")
    """

    def __init__(self) -> None:
        self._finding_counter = 0

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"SANDBOX-{self._finding_counter:04d}"

    def evaluate(self, config: SandboxConfig) -> SandboxEvalResult:
        """Evaluate a sandbox configuration."""
        findings: list[SandboxFinding] = []

        findings.extend(self._check_filesystem(config))
        findings.extend(self._check_network(config))
        findings.extend(self._check_process(config))
        findings.extend(self._check_resources(config))
        findings.extend(self._check_credentials(config))
        findings.extend(self._check_identity(config))
        findings.extend(self._check_tools(config))

        score = self._calculate_score(findings)
        grade = self._score_to_grade(score)

        return SandboxEvalResult(score=score, grade=grade, findings=findings)

    def evaluate_from_dict(self, config_dict: dict[str, Any]) -> SandboxEvalResult:
        """Evaluate from a plain dict (for MCP/CLI usage)."""
        config = SandboxConfig(
            writable_paths=config_dict.get("writable_paths", []),
            readable_paths=config_dict.get("readable_paths", []),
            root_filesystem_access=config_dict.get("root_filesystem_access", False),
            network_enabled=config_dict.get("network_enabled", True),
            allowed_domains=config_dict.get("allowed_domains", []),
            egress_filtering=config_dict.get("egress_filtering", False),
            shell_access=config_dict.get("shell_access", True),
            subprocess_allowed=config_dict.get("subprocess_allowed", True),
            allowed_commands=config_dict.get("allowed_commands", []),
            memory_limit_mb=config_dict.get("memory_limit_mb", 0),
            cpu_limit_percent=config_dict.get("cpu_limit_percent", 0),
            max_file_descriptors=config_dict.get("max_file_descriptors", 0),
            max_processes=config_dict.get("max_processes", 0),
            timeout_seconds=config_dict.get("timeout_seconds", 0),
            env_vars=config_dict.get("env_vars", []),
            mounted_secrets=config_dict.get("mounted_secrets", []),
            runs_as_root=config_dict.get("runs_as_root", False),
            user=config_dict.get("user", ""),
            available_tools=config_dict.get("available_tools", []),
            tool_confirmation_required=config_dict.get("tool_confirmation_required", False),
        )
        return self.evaluate(config)

    # ── Check Methods ─────────────────────────────────────────────────

    def _check_filesystem(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        if config.root_filesystem_access:
            findings.append(SandboxFinding(
                self._next_id(), "filesystem", "critical",
                "Full root filesystem access",
                "Agent has unrestricted filesystem access — can read any file including credentials",
                "Restrict to specific directories. Use read-only mounts.",
                "AML.T0037",
            ))

        for path in config.writable_paths:
            for sensitive in SENSITIVE_PATHS:
                if sensitive in path or path == "/":
                    findings.append(SandboxFinding(
                        self._next_id(), "filesystem", "critical",
                        f"Write access to sensitive path: {path}",
                        f"Agent can write to '{path}' which contains sensitive system data",
                        f"Remove write access to {path}. Use allowlist of safe directories.",
                        "AML.T0102",
                    ))
                    break

        if not config.writable_paths and not config.root_filesystem_access:
            pass  # Read-only is good
        elif "/" in config.writable_paths:
            findings.append(SandboxFinding(
                self._next_id(), "filesystem", "critical",
                "Write access to root filesystem",
                "Agent has write access to / — can modify any file",
                "Restrict writable paths to project directory only.",
                "AML.T0102",
            ))

        return findings

    def _check_network(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        if config.network_enabled and not config.egress_filtering:
            findings.append(SandboxFinding(
                self._next_id(), "network", "high",
                "No egress filtering",
                "Agent can make outbound connections to any host — data exfiltration risk",
                "Enable egress filtering. Allowlist specific domains.",
                "AML.T0025",
            ))

        if config.network_enabled and not config.allowed_domains:
            findings.append(SandboxFinding(
                self._next_id(), "network", "high",
                "No domain allowlist",
                "No allowed domains configured — agent can reach any endpoint",
                "Define an allowed_domains list for outbound connections.",
                "AML.T0096",
            ))

        if not config.network_enabled:
            pass  # Air-gapped is safest

        return findings

    def _check_process(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        if config.shell_access:
            findings.append(SandboxFinding(
                self._next_id(), "process", "critical",
                "Shell access enabled",
                "Agent has direct shell access — can execute arbitrary commands",
                "Disable shell access. Use a command allowlist instead.",
                "AML.T0050",
            ))

        if config.subprocess_allowed and not config.allowed_commands:
            findings.append(SandboxFinding(
                self._next_id(), "process", "high",
                "Unrestricted subprocess execution",
                "Agent can spawn any subprocess without command filtering",
                "Define an allowed_commands list or disable subprocess.",
                "AML.T0102",
            ))

        return findings

    def _check_resources(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        if config.memory_limit_mb == 0:
            findings.append(SandboxFinding(
                self._next_id(), "resources", "medium",
                "No memory limit",
                "Agent has unlimited memory — vulnerable to resource exhaustion",
                "Set memory_limit_mb (e.g., 512 or 1024).",
                "AML.T0029",
            ))

        if config.timeout_seconds == 0:
            findings.append(SandboxFinding(
                self._next_id(), "resources", "medium",
                "No execution timeout",
                "Agent has no timeout — can run indefinitely",
                "Set timeout_seconds (e.g., 300 for 5 minutes).",
                "AML.T0034",
            ))

        if config.max_processes == 0:
            findings.append(SandboxFinding(
                self._next_id(), "resources", "low",
                "No process limit",
                "Agent can spawn unlimited processes — fork bomb risk",
                "Set max_processes (e.g., 10).",
                "AML.T0029",
            ))

        return findings

    def _check_credentials(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        for env_var in config.env_vars:
            for pattern in SENSITIVE_ENV_PATTERNS:
                if re.match(pattern, env_var):
                    findings.append(SandboxFinding(
                        self._next_id(), "credentials", "critical",
                        f"Sensitive env var exposed: {env_var}",
                        f"Agent has access to sensitive environment variable '{env_var}'",
                        "Remove sensitive env vars from agent environment. Use a secrets manager.",
                        "AML.T0098",
                    ))
                    break

        for secret in config.mounted_secrets:
            findings.append(SandboxFinding(
                self._next_id(), "credentials", "high",
                f"Mounted secret: {secret}",
                f"Secret '{secret}' is mounted in agent environment",
                "Use ephemeral, scoped tokens instead of long-lived secrets.",
                "AML.T0098",
            ))

        return findings

    def _check_identity(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        if config.runs_as_root:
            findings.append(SandboxFinding(
                self._next_id(), "identity", "critical",
                "Agent runs as root",
                "Agent executes with root privileges — no privilege boundaries",
                "Run agent as unprivileged user with minimal permissions.",
                "AML.T0050",
            ))

        return findings

    def _check_tools(self, config: SandboxConfig) -> list[SandboxFinding]:
        findings = []

        dangerous_available = [t for t in config.available_tools if t in DANGEROUS_TOOLS]
        if dangerous_available and not config.tool_confirmation_required:
            findings.append(SandboxFinding(
                self._next_id(), "tools", "high",
                f"Dangerous tools without confirmation: {', '.join(dangerous_available[:5])}",
                "Agent has access to dangerous tools without requiring user confirmation",
                "Enable tool_confirmation_required or remove dangerous tools.",
                "AML.T0006",
            ))

        if len(config.available_tools) > 20:
            findings.append(SandboxFinding(
                self._next_id(), "tools", "medium",
                f"Excessive tool count: {len(config.available_tools)}",
                "Agent has access to many tools — increases attack surface",
                "Apply principle of least privilege. Remove unnecessary tools.",
                "AML.T0006",
            ))

        return findings

    # ── Scoring ───────────────────────────────────────────────────────

    def _calculate_score(self, findings: list[SandboxFinding]) -> int:
        penalties = {"critical": 20, "high": 10, "medium": 5, "low": 2}
        total_penalty = sum(penalties.get(f.risk, 0) for f in findings)
        return max(0, 100 - total_penalty)

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"
