"""JavaScript/TypeScript deep analyzer — context-aware vulnerability detection.

Goes beyond regex pattern matching by understanding code structure:
- Distinguishes literal vs variable arguments in dangerous calls
- Detects template literal interpolation in SQL/XSS contexts
- Tracks variable assignments for credential detection
- Understands call chains and property assignments

No external dependencies — uses regex+heuristics for structural analysis.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

import structlog

from core.models import Confidence, FileResult, Finding, Severity

log = structlog.get_logger("js_ast_analyzer")


# ── Patterns for structural analysis ────────────────────────────────────

# Match variable/const/let assignments
_ASSIGN_RE = re.compile(
    r"(?:(?:const|let|var)\s+)?(\w+)\s*=\s*(.+?)(?:;|\s*$)", re.MULTILINE
)

# Template literal with interpolation
_TEMPLATE_INTERP_RE = re.compile(r"\$\{([^}]+)\}")

# String literal (single, double, or backtick without interpolation)
_STRING_LITERAL_RE = re.compile(r"""^(?:"[^"]*"|'[^']*'|`[^$`]*`)$""")

# Credential-like variable names
_CREDENTIAL_NAMES = re.compile(
    r"(?i)(password|passwd|secret|api_?key|auth_?token|access_?token|private_?key|"
    r"client_?secret|jwt_?secret|encryption_?key|signing_?key)"
)

# Comment patterns
_LINE_COMMENT_RE = re.compile(r"^\s*//")
_BLOCK_COMMENT_START = re.compile(r"/\*")
_BLOCK_COMMENT_END = re.compile(r"\*/")


class JSASTAnalyzer:
    """Deep analysis for JavaScript/TypeScript beyond regex patterns."""

    def analyze_file(self, file_path: str) -> FileResult:
        """Analyze a JS/TS file."""
        result = FileResult(file_path=file_path, language="javascript")
        start = time.time()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.error = str(e)
            return result

        suffix = Path(file_path).suffix.lower()
        language = "typescript" if suffix in (".ts", ".tsx") else "javascript"
        result.language = language
        result.lines_scanned = len(source.splitlines())

        findings = self.analyze_source(source, language, file_path)
        result.findings = findings
        result.scan_time_ms = (time.time() - start) * 1000

        log.debug("js_ast_analyzed", file=file_path, findings=len(findings),
                  time_ms=round(result.scan_time_ms, 1))
        return result

    def analyze_source(
        self, source: str, language: str = "javascript", filename: str = "<string>"
    ) -> list[Finding]:
        """Analyze JS/TS source code."""
        lines = source.splitlines()
        # Strip comments for analysis
        clean_lines = self._strip_comments(lines)

        findings: list[Finding] = []
        findings.extend(self._check_dangerous_calls(clean_lines, lines, filename))
        findings.extend(self._check_sql_injection(clean_lines, lines, filename))
        findings.extend(self._check_xss(clean_lines, lines, filename))
        findings.extend(self._check_credentials(clean_lines, lines, filename))
        findings.extend(self._check_crypto(clean_lines, lines, filename))
        findings.extend(self._check_tls(clean_lines, lines, filename))
        return findings

    # ── Dangerous Calls ─────────────────────────────────────────────────

    def _check_dangerous_calls(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            # eval() with non-literal arg
            m = re.search(r"\beval\s*\((.+?)\)", stripped)
            if m:
                arg = m.group(1).strip()
                if not _STRING_LITERAL_RE.match(arg):
                    findings.append(self._finding(
                        "javascript.ast.eval-dynamic", "eval() with dynamic input — code injection",
                        Severity.ERROR, "CWE-95", filename, i, raw_lines,
                        confidence=Confidence.HIGH,
                    ))

            # new Function() with non-literal
            m = re.search(r"\bnew\s+Function\s*\((.+?)\)", stripped)
            if m:
                arg = m.group(1).strip()
                if not _STRING_LITERAL_RE.match(arg):
                    findings.append(self._finding(
                        "javascript.ast.new-function", "new Function() with dynamic input — code injection",
                        Severity.ERROR, "CWE-95", filename, i, raw_lines,
                    ))

            # child_process.exec/execSync with template literal or variable
            m = re.search(r"(?:exec|execSync)\s*\(\s*(`[^`]*\$\{|[a-zA-Z_]\w*)", stripped)
            if m:
                findings.append(self._finding(
                    "javascript.ast.command-injection",
                    "child_process exec with dynamic input — command injection",
                    Severity.ERROR, "CWE-78", filename, i, raw_lines,
                ))

            # vm.runInContext / vm.runInNewContext
            if re.search(r"vm\.\s*(?:runIn(?:New)?Context|compileFunction)\s*\(", stripped):
                findings.append(self._finding(
                    "javascript.ast.vm-exec", "vm code execution — sandbox escape risk",
                    Severity.WARNING, "CWE-94", filename, i, raw_lines,
                ))

            # setTimeout/setInterval with string first arg
            m = re.search(r"(?:setTimeout|setInterval)\s*\(\s*(['\"`])", stripped)
            if m and m.group(1) != "`":
                findings.append(self._finding(
                    "javascript.ast.settimeout-string",
                    "setTimeout/setInterval with string — implicit eval",
                    Severity.WARNING, "CWE-95", filename, i, raw_lines,
                    confidence=Confidence.MEDIUM,
                ))

        return findings

    # ── SQL Injection ───────────────────────────────────────────────────

    def _check_sql_injection(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()

            # .query() / .execute() / .raw() with template literal containing ${...}
            m = re.search(
                r"\.(?:query|execute|raw)\s*\(\s*`([^`]*)`",
                stripped,
            )
            if m:
                template_body = m.group(1)
                interps = _TEMPLATE_INTERP_RE.findall(template_body)
                # Only flag if interpolation contains a variable (not a literal)
                for interp in interps:
                    interp = interp.strip()
                    if not re.match(r"^\d+$", interp) and not _STRING_LITERAL_RE.match(interp):
                        findings.append(self._finding(
                            "javascript.ast.sql-template-literal",
                            "SQL query with template literal interpolation — SQL injection",
                            Severity.ERROR, "CWE-89", filename, i, raw_lines,
                        ))
                        break

            # .query() / .execute() with string concatenation
            if re.search(
                r"\.(?:query|execute)\s*\(\s*['\"].*\+\s*[a-zA-Z_]", stripped
            ):
                findings.append(self._finding(
                    "javascript.ast.sql-concat",
                    "SQL query with string concatenation — SQL injection",
                    Severity.ERROR, "CWE-89", filename, i, raw_lines,
                ))

        return findings

    # ── XSS ─────────────────────────────────────────────────────────────

    def _check_xss(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()

            # innerHTML assignment with non-literal RHS
            m = re.search(r"\.innerHTML\s*=\s*(.+?)(?:;|$)", stripped)
            if m:
                rhs = m.group(1).strip()
                if not _STRING_LITERAL_RE.match(rhs):
                    findings.append(self._finding(
                        "javascript.ast.innerhtml-dynamic",
                        "innerHTML with dynamic value — XSS risk",
                        Severity.ERROR, "CWE-79", filename, i, raw_lines,
                    ))

            # document.write with variable arg
            m = re.search(r"document\.write(?:ln)?\s*\(\s*(\w+)", stripped)
            if m:
                arg = m.group(1)
                if arg not in ("true", "false", "null", "undefined"):
                    findings.append(self._finding(
                        "javascript.ast.document-write",
                        "document.write() with variable — XSS risk",
                        Severity.ERROR, "CWE-79", filename, i, raw_lines,
                    ))

            # dangerouslySetInnerHTML with variable
            if re.search(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{", stripped):
                findings.append(self._finding(
                    "javascript.ast.dangerously-set-html",
                    "dangerouslySetInnerHTML — XSS risk if user input",
                    Severity.WARNING, "CWE-79", filename, i, raw_lines,
                    confidence=Confidence.MEDIUM,
                ))

            # res.send() with template literal containing user-like vars
            m = re.search(r"res\.(?:send|write)\s*\(\s*`([^`]*)`", stripped)
            if m:
                body = m.group(1)
                if _TEMPLATE_INTERP_RE.search(body):
                    findings.append(self._finding(
                        "javascript.ast.response-xss",
                        "Response with template literal interpolation — XSS risk",
                        Severity.WARNING, "CWE-79", filename, i, raw_lines,
                        confidence=Confidence.MEDIUM,
                    ))

        return findings

    # ── Hardcoded Credentials ───────────────────────────────────────────

    def _check_credentials(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()

            # Variable assignment: const password = "secret123"
            m = re.search(
                r"(?:const|let|var|this\.)\s*(\w+)\s*=\s*(['\"])(.{4,}?)\2",
                stripped,
            )
            if m:
                var_name = m.group(1)
                value = m.group(3)
                if _CREDENTIAL_NAMES.search(var_name):
                    # Skip obvious placeholders
                    if not re.search(r"(?i)(example|placeholder|todo|xxx|change.me)", value):
                        findings.append(self._finding(
                            "javascript.ast.hardcoded-credential",
                            f"Hardcoded credential in '{var_name}'",
                            Severity.ERROR, "CWE-798", filename, i, raw_lines,
                        ))

            # Object property: { password: "secret" }
            m = re.search(
                r"(\w+)\s*:\s*(['\"])(.{4,}?)\2",
                stripped,
            )
            if m:
                key = m.group(1)
                value = m.group(3)
                if _CREDENTIAL_NAMES.search(key):
                    if not re.search(r"(?i)(example|placeholder|todo|xxx|change.me)", value):
                        # Avoid duplicate if already caught by variable assignment
                        if not re.search(r"(?:const|let|var)\s+" + re.escape(key), stripped):
                            findings.append(self._finding(
                                "javascript.ast.hardcoded-credential",
                                f"Hardcoded credential in property '{key}'",
                                Severity.WARNING, "CWE-798", filename, i, raw_lines,
                                confidence=Confidence.MEDIUM,
                            ))

        return findings

    # ── Crypto Issues ───────────────────────────────────────────────────

    def _check_crypto(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()

            # crypto.createHash('md5') or ('sha1')
            m = re.search(r"createHash\s*\(\s*['\"](\w+)['\"]", stripped)
            if m:
                algo = m.group(1).lower()
                if algo in ("md5", "sha1"):
                    findings.append(self._finding(
                        "javascript.ast.weak-hash",
                        f"Weak hash algorithm: {algo} — use SHA-256+",
                        Severity.WARNING, "CWE-328", filename, i, raw_lines,
                    ))

            # Math.random() in security-sensitive context
            if "Math.random()" in stripped:
                # Check if line has security-like context
                if re.search(r"(?i)(token|key|secret|auth|session|nonce|salt|id|uuid)", stripped):
                    findings.append(self._finding(
                        "javascript.ast.math-random-security",
                        "Math.random() in security context — use crypto.getRandomValues()",
                        Severity.WARNING, "CWE-330", filename, i, raw_lines,
                        confidence=Confidence.MEDIUM,
                    ))

        return findings

    # ── TLS / Network ───────────────────────────────────────────────────

    def _check_tls(
        self, clean_lines: list[str], raw_lines: list[str], filename: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(clean_lines, 1):
            stripped = line.strip()

            # rejectUnauthorized: false
            if re.search(r"rejectUnauthorized\s*:\s*false", stripped):
                findings.append(self._finding(
                    "javascript.ast.tls-reject-disabled",
                    "TLS certificate verification disabled — MITM risk",
                    Severity.ERROR, "CWE-295", filename, i, raw_lines,
                ))

            # NODE_TLS_REJECT_UNAUTHORIZED = "0"
            if re.search(r"NODE_TLS_REJECT_UNAUTHORIZED.*['\"]0['\"]", stripped):
                findings.append(self._finding(
                    "javascript.ast.tls-env-disabled",
                    "TLS verification disabled via env variable",
                    Severity.ERROR, "CWE-295", filename, i, raw_lines,
                ))

        return findings

    # ── Helpers ──────────────────────────────────────────────────────────

    def _strip_comments(self, lines: list[str]) -> list[str]:
        """Remove comments, preserving line numbers."""
        result: list[str] = []
        in_block = False

        for line in lines:
            if in_block:
                end = _BLOCK_COMMENT_END.search(line)
                if end:
                    in_block = False
                    result.append(line[end.end():])
                else:
                    result.append("")
                continue

            # Remove line comments
            if _LINE_COMMENT_RE.match(line):
                result.append("")
                continue

            # Handle block comment start
            start = _BLOCK_COMMENT_START.search(line)
            if start:
                end = _BLOCK_COMMENT_END.search(line, start.end())
                if end:
                    # Single-line block comment
                    cleaned = line[:start.start()] + line[end.end():]
                    result.append(cleaned)
                else:
                    in_block = True
                    result.append(line[:start.start()])
                continue

            result.append(line)

        return result

    def _finding(
        self,
        rule_id: str,
        message: str,
        severity: Severity,
        cwe: str,
        filename: str,
        line_num: int,
        raw_lines: list[str],
        confidence: Confidence = Confidence.HIGH,
    ) -> Finding:
        line_content = raw_lines[line_num - 1].rstrip() if 0 < line_num <= len(raw_lines) else ""
        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            file_path=filename,
            line_number=line_num,
            line_content=line_content,
            cwe=cwe,
            confidence=confidence,
            language="javascript",
            category="ast",
        )
