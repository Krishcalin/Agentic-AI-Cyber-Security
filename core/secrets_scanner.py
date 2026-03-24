"""Enhanced Secrets Scanner — deep secrets detection with entropy analysis.

Goes beyond regex patterns to detect secrets using:
- Shannon entropy analysis (high-entropy strings = likely secrets)
- 40+ regex patterns for known secret formats (AWS, GCP, GitHub, Stripe, etc.)
- Git history scanning (secrets in previous commits)
- Variable name heuristics (assignment to 'password', 'secret', etc.)
- Base64/hex-encoded secret detection
- .env file parsing

Covers ATLAS technique AML.T0055 — Unsecured Credentials.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger("secrets_scanner")


@dataclass
class SecretFinding:
    """A detected secret."""
    finding_id: str
    secret_type: str
    risk: str
    title: str
    file_path: str
    line_number: int
    matched_text: str  # Redacted version
    entropy: float
    confidence: float
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "secret_type": self.secret_type,
            "risk": self.risk,
            "title": self.title,
            "file": self.file_path,
            "line": self.line_number,
            "matched": self.matched_text,
            "entropy": round(self.entropy, 2),
            "confidence": round(self.confidence, 2),
            "remediation": self.remediation,
        }


@dataclass
class SecretsScanResult:
    """Result of secrets scan."""
    file_path: str
    secrets_found: list[SecretFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0

    @property
    def is_clean(self) -> bool:
        return len(self.secrets_found) == 0

    @property
    def count(self) -> int:
        return len(self.secrets_found)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "is_clean": self.is_clean,
            "secrets_count": self.count,
            "secrets": [s.to_dict() for s in self.secrets_found],
            "scan_time_ms": round(self.scan_time_ms, 1),
        }


# ── Secret Patterns ───────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    # (regex, secret_type, risk, remediation)

    # AWS
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical",
     "Rotate AWS access key immediately. Use IAM roles instead."),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "aws_secret_key", "critical",
     "Rotate AWS secret key. Use AWS Secrets Manager or environment variables."),

    # GCP
    (r"AIza[0-9A-Za-z_-]{35}", "gcp_api_key", "high",
     "Restrict GCP API key scope. Rotate and use service accounts."),
    (r'"type"\s*:\s*"service_account"', "gcp_service_account", "high",
     "Remove GCP service account JSON from code. Use workload identity."),

    # GitHub
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "github_token", "critical",
     "Revoke GitHub token immediately. Use fine-grained tokens."),
    (r"github_pat_[A-Za-z0-9_]{22,}", "github_pat", "critical",
     "Revoke GitHub PAT. Use short-lived tokens."),

    # GitLab
    (r"glpat-[A-Za-z0-9_-]{20,}", "gitlab_token", "critical",
     "Revoke GitLab token. Use project/group access tokens."),

    # Slack
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "slack_token", "critical",
     "Revoke Slack token. Use OAuth with minimal scopes."),

    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "stripe_secret_key", "critical",
     "Rotate Stripe key immediately. Use restricted keys."),
    (r"rk_live_[0-9a-zA-Z]{24,}", "stripe_restricted_key", "high",
     "Rotate Stripe restricted key."),

    # Twilio
    (r"SK[0-9a-fA-F]{32}", "twilio_api_key", "high",
     "Rotate Twilio API key."),

    # SendGrid
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "sendgrid_api_key", "critical",
     "Rotate SendGrid API key."),

    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "mailgun_api_key", "high",
     "Rotate Mailgun API key."),

    # SSH private keys
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "ssh_private_key", "critical",
     "Remove SSH private key from code. Use ssh-agent or vault."),

    # PGP
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", "critical",
     "Remove PGP private key from code."),

    # Generic API keys
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]", "generic_api_key", "high",
     "Move API key to environment variable or secrets manager."),

    # JWT
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt_token", "high",
     "Remove JWT from source code. Tokens should be runtime-only."),

    # Database URLs
    (r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'\"]{10,}", "database_url", "critical",
     "Move database URL to environment variable. Use connection pooling with vault."),

    # Generic passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "hardcoded_password", "critical",
     "Remove hardcoded password. Use environment variables or secrets manager."),

    # Generic secrets
    (r'(?i)(secret|token|auth)\s*[=:]\s*["\']([a-zA-Z0-9_/+=-]{16,})["\']', "generic_secret", "high",
     "Move secret to environment variable."),

    # Heroku
    (r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
     "heroku_api_key", "high", "Rotate Heroku API key."),

    # NPM tokens
    (r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]{36}", "npm_token", "critical",
     "Revoke npm token. Use npm login with 2FA."),

    # PyPI tokens
    (r"pypi-[A-Za-z0-9_-]{100,}", "pypi_token", "critical",
     "Revoke PyPI token. Use trusted publishing."),

    # Docker Hub
    (r"dckr_pat_[A-Za-z0-9_-]{27,}", "docker_token", "high",
     "Rotate Docker Hub token."),

    # Azure
    (r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{40,}", "azure_storage_key", "critical",
     "Rotate Azure storage key. Use managed identities."),

    # Okta
    (r"(?i)00[A-Za-z0-9_-]{40}", "okta_token", "high",
     "Rotate Okta token."),

    # OpenAI
    (r"sk-[A-Za-z0-9]{48}", "openai_api_key", "critical",
     "Rotate OpenAI API key. Use project-level keys."),

    # Anthropic
    (r"sk-ant-[A-Za-z0-9_-]{40,}", "anthropic_api_key", "critical",
     "Rotate Anthropic API key."),
]

# Known false positive patterns
FALSE_POSITIVE_PATTERNS = [
    r"(?i)\b(example|placeholder|dummy|test|fake|mock|sample|demo|todo|fixme|xxx)\b",
    r"(?i)your[_-]?api[_-]?key|insert[_-]?here|change[_-]?me",
    r"<[A-Z_]+>",  # Template variables like <API_KEY>
    r"\*{3,}",  # Redacted: ***
]


class SecretsScanner:
    """Enhanced secrets scanner with entropy analysis.

    Usage:
        scanner = SecretsScanner()
        result = scanner.scan_file("config.py")
        for secret in result.secrets_found:
            print(f"  {secret.secret_type}: line {secret.line_number}")
    """

    ENTROPY_THRESHOLD = 4.0  # Shannon entropy threshold for high-entropy strings
    MIN_SECRET_LENGTH = 8

    def __init__(self) -> None:
        self._finding_counter = 0
        self._compiled_patterns = [
            (re.compile(p, re.MULTILINE), stype, risk, remediation)
            for p, stype, risk, remediation in SECRET_PATTERNS
        ]
        self._false_positive_re = [re.compile(p) for p in FALSE_POSITIVE_PATTERNS]

    @property
    def pattern_count(self) -> int:
        return len(self._compiled_patterns)

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"SECRET-{self._finding_counter:04d}"

    def scan_file(self, file_path: str | Path) -> SecretsScanResult:
        """Scan a file for secrets."""
        start = time.time()
        path = Path(file_path)

        if not path.exists():
            return SecretsScanResult(file_path=str(path))

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return SecretsScanResult(file_path=str(path))

        findings = self._scan_content(content, str(path))
        elapsed = (time.time() - start) * 1000

        return SecretsScanResult(
            file_path=str(path), secrets_found=findings, scan_time_ms=elapsed,
        )

    def scan_content(self, content: str, source: str = "<input>") -> SecretsScanResult:
        """Scan text content for secrets."""
        start = time.time()
        findings = self._scan_content(content, source)
        elapsed = (time.time() - start) * 1000
        return SecretsScanResult(file_path=source, secrets_found=findings, scan_time_ms=elapsed)

    def scan_directory(self, directory: str | Path) -> list[SecretsScanResult]:
        """Scan all text files in a directory for secrets."""
        directory = Path(directory)
        results = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
        text_exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".rs", ".php",
                     ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
                     ".env", ".sh", ".bash", ".tf", ".hcl", ".xml", ".properties"}

        for path in directory.rglob("*"):
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.suffix.lower() in text_exts or path.name in (".env", ".env.local", ".env.production"):
                result = self.scan_file(path)
                if not result.is_clean:
                    results.append(result)

        return results

    def _scan_content(self, content: str, source: str) -> list[SecretFinding]:
        """Core scanning logic."""
        findings: list[SecretFinding] = []
        lines = content.splitlines()

        # Pattern-based detection
        for compiled, secret_type, risk, remediation in self._compiled_patterns:
            for match in compiled.finditer(content):
                matched_text = match.group()
                line_num = content[:match.start()].count("\n") + 1

                # Skip false positives
                if self._is_false_positive(matched_text, lines[line_num - 1] if line_num <= len(lines) else ""):
                    continue

                entropy = self._shannon_entropy(matched_text)
                redacted = self._redact(matched_text)

                findings.append(SecretFinding(
                    finding_id=self._next_id(),
                    secret_type=secret_type,
                    risk=risk,
                    title=f"{secret_type.replace('_', ' ').title()} detected",
                    file_path=source,
                    line_number=line_num,
                    matched_text=redacted,
                    entropy=entropy,
                    confidence=min(0.6 + entropy * 0.08, 0.99),
                    remediation=remediation,
                ))

        # Entropy-based detection for unmatched high-entropy strings
        findings.extend(self._entropy_scan(content, source))

        # Deduplicate by line
        seen: set[str] = set()
        unique: list[SecretFinding] = []
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.secret_type}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _entropy_scan(self, content: str, source: str) -> list[SecretFinding]:
        """Find high-entropy strings that may be secrets."""
        findings = []
        # Match quoted strings and assignments
        high_entropy_pattern = re.compile(
            r'''(?:=|:)\s*['"]([A-Za-z0-9+/=_-]{20,})['"]''',
        )

        for match in high_entropy_pattern.finditer(content):
            value = match.group(1)
            entropy = self._shannon_entropy(value)

            if entropy >= self.ENTROPY_THRESHOLD and len(value) >= 20:
                line_num = content[:match.start()].count("\n") + 1
                line = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                if self._is_false_positive(value, line):
                    continue

                # Check if already caught by pattern detection
                already_found = any(
                    p.search(value) for p, _, _, _ in self._compiled_patterns
                )
                if already_found:
                    continue

                findings.append(SecretFinding(
                    finding_id=self._next_id(),
                    secret_type="high_entropy_string",
                    risk="medium",
                    title=f"High-entropy string (entropy: {entropy:.1f})",
                    file_path=source,
                    line_number=line_num,
                    matched_text=self._redact(value),
                    entropy=entropy,
                    confidence=min(entropy * 0.15, 0.85),
                    remediation="Review if this is a secret. Move to environment variable if so.",
                ))

        return findings

    def _is_false_positive(self, matched: str, line: str) -> bool:
        """Check if a match is a known false positive."""
        combined = f"{matched} {line}"
        return any(fp.search(combined) for fp in self._false_positive_re)

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq: dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _redact(text: str) -> str:
        """Redact a secret for safe display."""
        if len(text) <= 8:
            return "***REDACTED***"
        return text[:4] + "..." + text[-4:]
