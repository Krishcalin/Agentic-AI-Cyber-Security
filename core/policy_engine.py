"""Policy Engine — declarative YAML-based agent behavior constraints.

Provides a configurable allow/deny policy system for controlling agent actions.
Policies define rules for:
- Command execution (allowed/blocked commands and patterns)
- File access (read/write paths, sensitive file protection)
- Network access (allowed domains, blocked exfiltration endpoints)
- Package installation (registry restrictions, approval requirements)
- Resource limits (rate limits, file size caps, session timeouts)

Policies are loaded from YAML files and evaluated against agent actions
to produce allow/deny/warn decisions with explanations.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

import structlog

log = structlog.get_logger("policy_engine")


# ── Data Models ───────────────────────────────────────────────────────────

class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    AUDIT = "audit"  # Allow but log for review


class PolicyScope(str, Enum):
    COMMAND = "command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    PACKAGE = "package"
    PROMPT = "prompt"
    ALL = "all"


@dataclass
class PolicyRule:
    """A single policy rule."""
    rule_id: str
    name: str
    scope: PolicyScope
    decision: PolicyDecision
    patterns: list[str]  # Regex patterns to match
    description: str = ""
    priority: int = 0  # Higher = evaluated first
    exceptions: list[str] = field(default_factory=list)  # Patterns that override this rule
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, target: str) -> bool:
        """Check if target matches this rule's patterns."""
        for pattern in self.patterns:
            if re.search(pattern, target, re.IGNORECASE):
                # Check exceptions
                for exc in self.exceptions:
                    if re.search(exc, target, re.IGNORECASE):
                        return False
                return True
        return False


@dataclass
class RateLimitRule:
    """Rate limiting configuration for a scope."""
    scope: PolicyScope
    max_actions: int
    window_seconds: int
    decision_on_exceed: PolicyDecision = PolicyDecision.DENY
    description: str = ""


@dataclass
class PolicyEvaluation:
    """Result of evaluating an action against policies."""
    decision: PolicyDecision
    rule_id: str | None
    rule_name: str | None
    reason: str
    scope: PolicyScope
    target: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "scope": self.scope.value,
            "target": self.target[:200],
        }


@dataclass
class PolicySet:
    """A complete policy configuration."""
    name: str
    version: str
    description: str
    rules: list[PolicyRule] = field(default_factory=list)
    rate_limits: list[RateLimitRule] = field(default_factory=list)
    default_decision: PolicyDecision = PolicyDecision.ALLOW
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyEngineStats:
    """Runtime statistics for the policy engine."""
    evaluations: int = 0
    allows: int = 0
    denies: int = 0
    warns: int = 0
    audits: int = 0
    rate_limit_hits: int = 0


# ── Built-in Policies ────────────────────────────────────────────────────

BUILTIN_COMMAND_DENY: list[PolicyRule] = [
    PolicyRule(
        rule_id="CMD-001",
        name="Block destructive commands",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.DENY,
        patterns=[
            r"rm\s+-rf\s+/",
            r"rm\s+-rf\s+/\*",
            r"mkfs\.",
            r"dd\s+if=.*of=/dev/",
            r">\s*/dev/sd",
            r":()\{\s*:\|:&\s*\};:",
        ],
        description="Blocks commands that destroy filesystems or cause system damage",
        priority=100,
    ),
    PolicyRule(
        rule_id="CMD-002",
        name="Block reverse shells",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.DENY,
        patterns=[
            r"bash\s+-i\s+>&\s*/dev/tcp",
            r"nc\s+-[elp]",
            r"ncat\s+-[elp]",
            r"/bin/sh\s+-i",
            r"python.*-c\s+.*import\s+socket.*connect",
            r"perl\s+-e\s+.*socket",
            r"ruby\s+-rsocket\s+-e",
            r"php\s+-r\s+.*fsockopen",
            r"socat\s+.*exec",
            r"mknod\s+.*pipe",
        ],
        description="Blocks reverse shell creation patterns",
        priority=100,
    ),
    PolicyRule(
        rule_id="CMD-003",
        name="Block credential dumping",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.DENY,
        patterns=[
            r"mimikatz",
            r"sekurlsa",
            r"lsadump",
            r"hashdump",
            r"procdump.*lsass",
            r"comsvcs.*MiniDump",
            r"reg\s+save.*sam",
            r"reg\s+save.*security",
            r"ntdsutil.*ifm",
            r"secretsdump",
        ],
        description="Blocks credential dumping tools and techniques",
        priority=100,
    ),
    PolicyRule(
        rule_id="CMD-004",
        name="Block download-and-execute",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.DENY,
        patterns=[
            r"curl\s+.*\|\s*(bash|sh|python|perl|ruby)",
            r"wget\s+.*\|\s*(bash|sh|python|perl|ruby)",
            r"powershell.*-enc",
            r"powershell.*downloadstring",
            r"certutil.*-urlcache",
            r"bitsadmin.*transfer.*http",
            r"mshta\s+http",
            r"regsvr32\s+/s\s+/u\s+/i:http",
        ],
        description="Blocks download-and-execute patterns (LOLBins)",
        priority=90,
    ),
    PolicyRule(
        rule_id="CMD-005",
        name="Block security tool disablement",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.DENY,
        patterns=[
            r"Set-MpPreference.*Disable",
            r"sc\s+(stop|delete)\s+(WinDefend|MsMpSvc|SecurityHealthService)",
            r"net\s+stop\s+.*defend",
            r"setenforce\s+0",
            r"iptables\s+-F",
            r"ufw\s+disable",
            r"systemctl\s+(stop|disable)\s+.*firewall",
            r"wevtutil\s+cl",
        ],
        description="Blocks attempts to disable security tools",
        priority=95,
    ),
    PolicyRule(
        rule_id="CMD-006",
        name="Warn on persistence mechanisms",
        scope=PolicyScope.COMMAND,
        decision=PolicyDecision.WARN,
        patterns=[
            r"crontab\s+-e",
            r"schtasks\s+/create",
            r"reg\s+add.*\\Run",
            r"systemctl\s+enable",
            r"launchctl\s+load",
            r"at\s+\d",
        ],
        description="Warns on commands that create persistence mechanisms",
        priority=80,
    ),
]

BUILTIN_FILE_READ_DENY: list[PolicyRule] = [
    PolicyRule(
        rule_id="FR-001",
        name="Warn on sensitive file reads",
        scope=PolicyScope.FILE_READ,
        decision=PolicyDecision.WARN,
        patterns=[
            r"\.env$",
            r"\.env\.\w+$",
            r"\.aws/credentials",
            r"\.ssh/id_",
            r"\.ssh/authorized_keys",
            r"\.gnupg/",
            r"\.kube/config",
            r"\.docker/config\.json",
            r"/etc/shadow",
            r"\.netrc",
            r"\.pgpass",
            r"wallet\.dat",
        ],
        description="Warns when agent reads credential/secret files",
        priority=80,
    ),
]

BUILTIN_FILE_WRITE_DENY: list[PolicyRule] = [
    PolicyRule(
        rule_id="FW-001",
        name="Block writes to system paths",
        scope=PolicyScope.FILE_WRITE,
        decision=PolicyDecision.DENY,
        patterns=[
            r"^/etc/",
            r"^/usr/",
            r"^/bin/",
            r"^/sbin/",
            r"^C:\\Windows\\",
            r"^C:\\Program Files",
        ],
        exceptions=[
            r"/etc/hosts\.local$",  # Allow local host overrides
        ],
        description="Blocks writes to protected system directories",
        priority=90,
    ),
    PolicyRule(
        rule_id="FW-002",
        name="Block writes to startup locations",
        scope=PolicyScope.FILE_WRITE,
        decision=PolicyDecision.DENY,
        patterns=[
            r"\.bashrc$",
            r"\.bash_profile$",
            r"\.profile$",
            r"\.zshrc$",
            r"/etc/cron",
            r"/etc/systemd/",
            r"/etc/init\.d/",
            r"\\Start Menu\\Programs\\Startup",
            r"\.config/autostart/",
            r"LaunchAgents/",
            r"LaunchDaemons/",
        ],
        description="Blocks writes to autostart/persistence locations",
        priority=95,
    ),
]

BUILTIN_NETWORK_DENY: list[PolicyRule] = [
    PolicyRule(
        rule_id="NET-001",
        name="Block known exfiltration endpoints",
        scope=PolicyScope.NETWORK,
        decision=PolicyDecision.DENY,
        patterns=[
            r"ngrok\.io",
            r"requestbin\.com",
            r"hookbin\.com",
            r"burpcollaborator\.net",
            r"interact\.sh",
            r"pipedream\.net",
            r"canarytokens\.com",
            r"webhook\.site",
            r"oast\.",
            r"dnslog\.",
            r"ceye\.io",
            r"beeceptor\.com",
            r"requestcatcher\.com",
            r"postb\.in",
        ],
        description="Blocks requests to known data exfiltration services",
        priority=100,
    ),
    PolicyRule(
        rule_id="NET-002",
        name="Warn on non-HTTPS",
        scope=PolicyScope.NETWORK,
        decision=PolicyDecision.WARN,
        patterns=[
            r"^http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])",
        ],
        description="Warns on cleartext HTTP requests to non-local endpoints",
        priority=50,
    ),
    PolicyRule(
        rule_id="NET-003",
        name="Block raw IP connections",
        scope=PolicyScope.NETWORK,
        decision=PolicyDecision.WARN,
        patterns=[
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!(/|:\d+/)(localhost|health|ready|metrics))",
        ],
        exceptions=[
            r"127\.0\.0\.1",
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"192\.168\.\d{1,3}\.\d{1,3}",
            r"172\.(1[6-9]|2\d|3[01])\.",
        ],
        description="Warns on direct IP address connections (non-private)",
        priority=40,
    ),
]

BUILTIN_PACKAGE_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="PKG-001",
        name="Block known malicious packages",
        scope=PolicyScope.PACKAGE,
        decision=PolicyDecision.DENY,
        patterns=[
            r"^(colourama|python-dateutils|jeIlyfish|python3-dateutil|raborern|crypt)$",
            r"^(event-stream|ua-parser-js|colors|faker|node-ipc)$",
        ],
        description="Blocks installation of known malicious packages",
        priority=100,
    ),
]


# ── Policy Loader ─────────────────────────────────────────────────────────

class PolicyLoader:
    """Loads policy sets from YAML files."""

    @staticmethod
    def load_file(path: str | Path) -> PolicySet:
        """Load a policy set from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return PolicyLoader._parse_policy_set(data)

    @staticmethod
    def load_directory(directory: str | Path) -> list[PolicySet]:
        """Load all policy sets from a directory."""
        directory = Path(directory)
        policy_sets = []

        for path in sorted(directory.glob("*.yaml")):
            try:
                policy_sets.append(PolicyLoader.load_file(path))
            except Exception as e:
                log.warning("policy_load_error", file=str(path), error=str(e))

        return policy_sets

    @staticmethod
    def _parse_policy_set(data: dict[str, Any]) -> PolicySet:
        """Parse a YAML dict into a PolicySet."""
        rules = []
        for rule_data in data.get("rules", []):
            rules.append(PolicyRule(
                rule_id=rule_data["id"],
                name=rule_data["name"],
                scope=PolicyScope(rule_data["scope"]),
                decision=PolicyDecision(rule_data["decision"]),
                patterns=rule_data.get("patterns", []),
                description=rule_data.get("description", ""),
                priority=rule_data.get("priority", 0),
                exceptions=rule_data.get("exceptions", []),
                metadata=rule_data.get("metadata", {}),
            ))

        rate_limits = []
        for rl_data in data.get("rate_limits", []):
            rate_limits.append(RateLimitRule(
                scope=PolicyScope(rl_data["scope"]),
                max_actions=rl_data["max_actions"],
                window_seconds=rl_data["window_seconds"],
                decision_on_exceed=PolicyDecision(rl_data.get("decision", "deny")),
                description=rl_data.get("description", ""),
            ))

        default = PolicyDecision(data.get("default_decision", "allow"))

        return PolicySet(
            name=data.get("name", "unnamed"),
            version=data.get("version", "1.0"),
            description=data.get("description", ""),
            rules=rules,
            rate_limits=rate_limits,
            default_decision=default,
            metadata=data.get("metadata", {}),
        )


# ── Policy Engine ─────────────────────────────────────────────────────────

class PolicyEngine:
    """Evaluates agent actions against loaded policies.

    Usage:
        engine = PolicyEngine()
        engine.load_builtin_policies()

        # Evaluate a command
        result = engine.evaluate("command", "curl http://evil.ngrok.io/data")
        print(result.decision)  # PolicyDecision.DENY

        # Evaluate file access
        result = engine.evaluate("file_read", "/home/user/.ssh/id_rsa")
        print(result.decision)  # PolicyDecision.WARN

        # Load custom policies
        engine.load_policy_file("policies/strict.yaml")
    """

    def __init__(self) -> None:
        self._rules: list[PolicyRule] = []
        self._rate_limits: list[RateLimitRule] = []
        self._default_decision = PolicyDecision.ALLOW
        self._action_history: dict[str, list[float]] = {}  # scope -> timestamps
        self._stats = PolicyEngineStats()
        self._audit_log: list[PolicyEvaluation] = []

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def stats(self) -> PolicyEngineStats:
        return self._stats

    @property
    def audit_log(self) -> list[PolicyEvaluation]:
        return list(self._audit_log)

    def load_builtin_policies(self) -> None:
        """Load all built-in policy rules."""
        self._rules.extend(BUILTIN_COMMAND_DENY)
        self._rules.extend(BUILTIN_FILE_READ_DENY)
        self._rules.extend(BUILTIN_FILE_WRITE_DENY)
        self._rules.extend(BUILTIN_NETWORK_DENY)
        self._rules.extend(BUILTIN_PACKAGE_RULES)

        # Default rate limits
        self._rate_limits.extend([
            RateLimitRule(
                scope=PolicyScope.COMMAND,
                max_actions=50,
                window_seconds=60,
                description="Max 50 commands per minute",
            ),
            RateLimitRule(
                scope=PolicyScope.FILE_READ,
                max_actions=100,
                window_seconds=60,
                description="Max 100 file reads per minute",
            ),
            RateLimitRule(
                scope=PolicyScope.NETWORK,
                max_actions=30,
                window_seconds=60,
                description="Max 30 network requests per minute",
            ),
            RateLimitRule(
                scope=PolicyScope.PACKAGE,
                max_actions=10,
                window_seconds=300,
                description="Max 10 package installs per 5 minutes",
            ),
        ])

        # Sort rules by priority (highest first)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

        log.info("builtin_policies_loaded", rules=len(self._rules), rate_limits=len(self._rate_limits))

    def load_policy_set(self, policy_set: PolicySet) -> None:
        """Load a PolicySet into the engine."""
        self._rules.extend(policy_set.rules)
        self._rate_limits.extend(policy_set.rate_limits)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        log.info("policy_set_loaded", name=policy_set.name, rules=len(policy_set.rules))

    def load_policy_file(self, path: str | Path) -> None:
        """Load policies from a YAML file."""
        policy_set = PolicyLoader.load_file(path)
        self.load_policy_set(policy_set)

    def load_policy_directory(self, directory: str | Path) -> None:
        """Load all policy files from a directory."""
        for policy_set in PolicyLoader.load_directory(directory):
            self.load_policy_set(policy_set)

    def evaluate(self, scope: str, target: str) -> PolicyEvaluation:
        """Evaluate an action against all loaded policies.

        Args:
            scope: Action scope ("command", "file_read", "file_write", "network", "package")
            target: The action target (command string, file path, URL, package name)

        Returns:
            PolicyEvaluation with the decision and reasoning
        """
        self._stats.evaluations += 1

        try:
            policy_scope = PolicyScope(scope)
        except ValueError:
            policy_scope = PolicyScope.ALL

        # Check rate limits first
        rate_eval = self._check_rate_limits(policy_scope, target)
        if rate_eval:
            self._record_evaluation(rate_eval)
            return rate_eval

        # Record action timestamp for rate limiting
        scope_key = policy_scope.value
        if scope_key not in self._action_history:
            self._action_history[scope_key] = []
        self._action_history[scope_key].append(time.time())

        # Evaluate rules (highest priority first)
        for rule in self._rules:
            if rule.scope not in (policy_scope, PolicyScope.ALL):
                continue

            if rule.matches(target):
                evaluation = PolicyEvaluation(
                    decision=rule.decision,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    reason=rule.description or f"Matched rule {rule.rule_id}: {rule.name}",
                    scope=policy_scope,
                    target=target,
                )
                self._record_evaluation(evaluation)
                return evaluation

        # Default decision
        evaluation = PolicyEvaluation(
            decision=self._default_decision,
            rule_id=None,
            rule_name=None,
            reason="No matching policy rule — using default decision",
            scope=policy_scope,
            target=target,
        )
        self._record_evaluation(evaluation)
        return evaluation

    def evaluate_batch(self, actions: list[tuple[str, str]]) -> list[PolicyEvaluation]:
        """Evaluate multiple actions at once.

        Args:
            actions: List of (scope, target) tuples

        Returns:
            List of PolicyEvaluation results
        """
        return [self.evaluate(scope, target) for scope, target in actions]

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a single rule dynamically."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        original_len = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < original_len

    def get_rules_for_scope(self, scope: str) -> list[dict[str, Any]]:
        """Get all rules for a given scope."""
        try:
            policy_scope = PolicyScope(scope)
        except ValueError:
            return []

        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "decision": r.decision.value,
                "priority": r.priority,
                "pattern_count": len(r.patterns),
                "description": r.description,
            }
            for r in self._rules
            if r.scope in (policy_scope, PolicyScope.ALL)
        ]

    def reset_stats(self) -> None:
        """Reset engine statistics."""
        self._stats = PolicyEngineStats()
        self._action_history.clear()
        self._audit_log.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        return {
            "total_evaluations": self._stats.evaluations,
            "allows": self._stats.allows,
            "denies": self._stats.denies,
            "warns": self._stats.warns,
            "audits": self._stats.audits,
            "rate_limit_hits": self._stats.rate_limit_hits,
            "total_rules": len(self._rules),
            "total_rate_limits": len(self._rate_limits),
        }

    # ── Internal Methods ──────────────────────────────────────────────

    def _check_rate_limits(self, scope: PolicyScope, target: str) -> PolicyEvaluation | None:
        """Check if action exceeds rate limits."""
        scope_key = scope.value
        now = time.time()

        for rl in self._rate_limits:
            if rl.scope != scope:
                continue

            timestamps = self._action_history.get(scope_key, [])
            # Clean old timestamps
            cutoff = now - rl.window_seconds
            recent = [t for t in timestamps if t > cutoff]
            self._action_history[scope_key] = recent

            if len(recent) >= rl.max_actions:
                self._stats.rate_limit_hits += 1
                return PolicyEvaluation(
                    decision=rl.decision_on_exceed,
                    rule_id=f"RATE-{scope_key.upper()}",
                    rule_name=f"Rate limit: {rl.description}",
                    reason=f"Rate limit exceeded: {len(recent)}/{rl.max_actions} actions "
                           f"in {rl.window_seconds}s window",
                    scope=scope,
                    target=target,
                )

        return None

    def _record_evaluation(self, evaluation: PolicyEvaluation) -> None:
        """Record an evaluation in stats and audit log."""
        match evaluation.decision:
            case PolicyDecision.ALLOW:
                self._stats.allows += 1
            case PolicyDecision.DENY:
                self._stats.denies += 1
            case PolicyDecision.WARN:
                self._stats.warns += 1
            case PolicyDecision.AUDIT:
                self._stats.audits += 1

        self._audit_log.append(evaluation)

        # Keep audit log bounded
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]

        if evaluation.decision in (PolicyDecision.DENY, PolicyDecision.WARN):
            log.info(
                "policy_evaluation",
                decision=evaluation.decision.value,
                rule=evaluation.rule_id,
                target=evaluation.target[:100],
            )
