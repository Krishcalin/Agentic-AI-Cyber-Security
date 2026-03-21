"""AST-based vulnerability detection for Python source code.

Uses the built-in `ast` module for deep structural analysis — detects
dangerous function calls, unsafe patterns, and code injection vectors
that regex-based scanning would miss or false-positive on.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, FileResult, Finding, Severity

log = structlog.get_logger("ast_analyzer")


@dataclass
class DangerousCall:
    """A dangerous function call pattern to detect in AST."""
    func_names: list[str]           # e.g., ["eval", "exec"]
    module_attr: str = ""           # e.g., "os.system"
    severity: Severity = Severity.ERROR
    message: str = ""
    cwe: str = ""
    rule_id: str = ""
    requires_user_input: bool = False   # Only flag if arg comes from tainted source
    confidence: Confidence = Confidence.HIGH


# ──────────────────────────────────────────────────────────────────────────
# Built-in dangerous call database
# ──────────────────────────────────────────────────────────────────────────

DANGEROUS_CALLS: list[DangerousCall] = [
    # Code execution
    DangerousCall(
        func_names=["eval"], rule_id="python.ast.eval",
        message="eval() call detected — arbitrary code execution risk",
        cwe="CWE-95", severity=Severity.ERROR,
    ),
    DangerousCall(
        func_names=["exec"], rule_id="python.ast.exec",
        message="exec() call detected — arbitrary code execution risk",
        cwe="CWE-95", severity=Severity.ERROR,
    ),
    DangerousCall(
        func_names=["compile"], rule_id="python.ast.compile",
        message="compile() with dynamic input — code execution vector",
        cwe="CWE-95", severity=Severity.WARNING, confidence=Confidence.MEDIUM,
    ),
    DangerousCall(
        func_names=["__import__"], rule_id="python.ast.dynamic-import",
        message="Dynamic __import__() — verify source is trusted",
        cwe="CWE-502", severity=Severity.WARNING, confidence=Confidence.MEDIUM,
    ),

    # Command injection
    DangerousCall(
        module_attr="os.system", func_names=[], rule_id="python.ast.os-system",
        message="os.system() call — command injection risk",
        cwe="CWE-78", severity=Severity.ERROR,
    ),
    DangerousCall(
        module_attr="os.popen", func_names=[], rule_id="python.ast.os-popen",
        message="os.popen() call — command injection risk",
        cwe="CWE-78", severity=Severity.ERROR,
    ),
    DangerousCall(
        module_attr="os.exec", func_names=[], rule_id="python.ast.os-exec",
        message="os.exec*() call — direct process execution",
        cwe="CWE-78", severity=Severity.WARNING,
    ),
    DangerousCall(
        module_attr="commands.getoutput", func_names=[], rule_id="python.ast.commands-getoutput",
        message="commands.getoutput() — deprecated and unsafe",
        cwe="CWE-78", severity=Severity.ERROR,
    ),

    # Deserialization
    DangerousCall(
        module_attr="pickle.loads", func_names=[], rule_id="python.ast.pickle-loads",
        message="pickle.loads() — arbitrary code execution via deserialization",
        cwe="CWE-502", severity=Severity.ERROR,
    ),
    DangerousCall(
        module_attr="pickle.load", func_names=[], rule_id="python.ast.pickle-load",
        message="pickle.load() — arbitrary code execution via deserialization",
        cwe="CWE-502", severity=Severity.ERROR,
    ),
    DangerousCall(
        module_attr="yaml.load", func_names=[], rule_id="python.ast.yaml-load-unsafe",
        message="yaml.load() without SafeLoader — code execution risk",
        cwe="CWE-502", severity=Severity.ERROR,
    ),
    DangerousCall(
        module_attr="marshal.loads", func_names=[], rule_id="python.ast.marshal-loads",
        message="marshal.loads() — unsafe deserialization",
        cwe="CWE-502", severity=Severity.WARNING,
    ),
    DangerousCall(
        module_attr="shelve.open", func_names=[], rule_id="python.ast.shelve-open",
        message="shelve uses pickle internally — deserialization risk",
        cwe="CWE-502", severity=Severity.WARNING,
    ),

    # Cryptography
    DangerousCall(
        module_attr="hashlib.md5", func_names=[], rule_id="python.ast.md5",
        message="MD5 hash — cryptographically broken",
        cwe="CWE-328", severity=Severity.WARNING,
    ),
    DangerousCall(
        module_attr="hashlib.sha1", func_names=[], rule_id="python.ast.sha1",
        message="SHA1 hash — cryptographically weak",
        cwe="CWE-328", severity=Severity.WARNING,
    ),

    # Tempfile
    DangerousCall(
        module_attr="tempfile.mktemp", func_names=[], rule_id="python.ast.mktemp",
        message="tempfile.mktemp() is insecure — race condition",
        cwe="CWE-377", severity=Severity.WARNING,
    ),

    # XML
    DangerousCall(
        module_attr="xml.etree.ElementTree.parse", func_names=[],
        rule_id="python.ast.xxe-etree",
        message="xml.etree.ElementTree.parse() — XXE risk without defused parser",
        cwe="CWE-611", severity=Severity.WARNING, confidence=Confidence.MEDIUM,
    ),
]


class ASTAnalyzer:
    """Analyzes Python source code using the AST for deep vulnerability detection."""

    def __init__(self) -> None:
        self._imports: dict[str, str] = {}     # alias → full module path
        self._assignments: dict[str, ast.AST] = {}  # variable → value node
        self._functions: dict[str, ast.FunctionDef] = {}  # func_name → node

    def analyze_file(self, file_path: str) -> FileResult:
        """Analyze a Python file using AST parsing."""
        result = FileResult(file_path=file_path, language="python")
        start = time.time()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.error = str(e)
            return result

        result.lines_scanned = len(source.splitlines())

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            result.error = f"SyntaxError: {e}"
            log.debug("ast_parse_failed", file=file_path, error=str(e))
            return result

        self._imports = {}
        self._assignments = {}
        self._functions = {}

        # First pass: collect imports, assignments, function defs
        self._collect_metadata(tree)

        # Second pass: detect dangerous patterns
        findings = self._analyze_tree(tree, file_path, source)
        result.findings = findings
        result.scan_time_ms = (time.time() - start) * 1000

        log.debug("ast_analyzed", file=file_path, findings=len(findings),
                  time_ms=f"{result.scan_time_ms:.1f}")
        return result

    def analyze_source(self, source: str, filename: str = "<string>") -> FileResult:
        """Analyze a Python source string."""
        result = FileResult(file_path=filename, language="python")
        result.lines_scanned = len(source.splitlines())

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            result.error = f"SyntaxError: {e}"
            return result

        self._imports = {}
        self._assignments = {}
        self._functions = {}
        self._collect_metadata(tree)
        result.findings = self._analyze_tree(tree, filename, source)
        return result

    def _collect_metadata(self, tree: ast.AST) -> None:
        """First pass: collect imports, assignments, function definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imports[name] = alias.name

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    self._imports[name] = f"{module}.{alias.name}"

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._assignments[target.id] = node.value

            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self._functions[node.name] = node

    def _analyze_tree(self, tree: ast.AST, file_path: str, source: str) -> list[Finding]:
        """Second pass: walk AST and detect vulnerabilities."""
        findings: list[Finding] = []
        lines = source.splitlines()

        for node in ast.walk(tree):
            # Check dangerous function calls
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, file_path, lines))

            # Check subprocess with shell=True
            if isinstance(node, ast.Call):
                findings.extend(self._check_subprocess_shell(node, file_path, lines))

            # Check string formatting in SQL-like contexts
            if isinstance(node, ast.Call):
                findings.extend(self._check_sql_formatting(node, file_path, lines))

            # Check assert used for security
            if isinstance(node, ast.Assert):
                findings.extend(self._check_security_assert(node, file_path, lines))

            # Check hardcoded credentials in assignments
            if isinstance(node, ast.Assign):
                findings.extend(self._check_hardcoded_creds(node, file_path, lines))

            # Check SSL verify=False in keyword args
            if isinstance(node, ast.Call):
                findings.extend(self._check_ssl_verify(node, file_path, lines))

        return findings

    def _check_call(self, node: ast.Call, file_path: str, lines: list[str]) -> list[Finding]:
        """Check function calls against dangerous call database."""
        findings: list[Finding]  = []
        call_name = self._resolve_call_name(node)

        for dc in DANGEROUS_CALLS:
            matched = False

            # Match simple function names (eval, exec)
            if dc.func_names:
                if isinstance(node.func, ast.Name) and node.func.id in dc.func_names:
                    matched = True

            # Match module.attr calls (os.system, pickle.loads)
            if dc.module_attr and call_name:
                if call_name == dc.module_attr or call_name.endswith(f".{dc.module_attr.split('.')[-1]}"):
                    # Verify the module is actually imported
                    parts = dc.module_attr.split(".")
                    if len(parts) >= 2:
                        module = parts[0]
                        if module in self._imports or call_name == dc.module_attr:
                            matched = True

            if matched:
                # Special case: yaml.load — check if SafeLoader is used
                if dc.rule_id == "python.ast.yaml-load-unsafe":
                    if self._has_safe_loader(node):
                        continue

                line_num = getattr(node, "lineno", 0)
                line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

                # Check if argument is dynamic (not just a literal)
                has_dynamic_arg = self._has_dynamic_argument(node)
                confidence = dc.confidence
                if not has_dynamic_arg and dc.func_names:
                    confidence = Confidence.LOW  # Likely safe if arg is a literal

                findings.append(Finding(
                    rule_id=dc.rule_id,
                    message=dc.message,
                    severity=dc.severity,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line_content.rstrip(),
                    cwe=dc.cwe,
                    confidence=confidence,
                    language="python",
                    category="ast",
                ))

        return findings

    def _check_subprocess_shell(self, node: ast.Call, file_path: str, lines: list[str]) -> list[Finding]:
        """Detect subprocess calls with shell=True."""
        call_name = self._resolve_call_name(node)
        if not call_name:
            return []

        subprocess_funcs = ["subprocess.call", "subprocess.run", "subprocess.Popen",
                           "subprocess.check_output", "subprocess.check_call"]
        if call_name not in subprocess_funcs:
            return []

        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    line_num = getattr(node, "lineno", 0)
                    line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

                    # Check if the command argument is a string literal or dynamic
                    severity = Severity.WARNING
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        severity = Severity.ERROR  # Dynamic command + shell=True = critical

                    return [Finding(
                        rule_id="python.ast.subprocess-shell",
                        message="subprocess with shell=True — command injection risk",
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content.rstrip(),
                        cwe="CWE-78",
                        confidence=Confidence.HIGH,
                        language="python",
                        category="ast",
                    )]
        return []

    def _check_sql_formatting(self, node: ast.Call, file_path: str, lines: list[str]) -> list[Finding]:
        """Detect SQL queries built with f-strings or .format()."""
        call_name = self._resolve_call_name(node)
        if not call_name:
            return []

        sql_methods = ["execute", "executemany", "raw"]
        method = call_name.split(".")[-1] if "." in call_name else ""
        if method not in sql_methods:
            return []

        if not node.args:
            return []

        first_arg = node.args[0]

        # f-string
        if isinstance(first_arg, ast.JoinedStr):
            # Check if any value in the f-string is a variable (not constant)
            has_variable = any(
                isinstance(v, ast.FormattedValue) and not isinstance(v.value, ast.Constant)
                for v in first_arg.values
            )
            if has_variable:
                line_num = getattr(node, "lineno", 0)
                return [Finding(
                    rule_id="python.ast.sql-fstring",
                    message="SQL query built with f-string containing variables — SQL injection",
                    severity=Severity.ERROR,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else "",
                    cwe="CWE-89",
                    owasp="A03:2021",
                    confidence=Confidence.HIGH,
                    language="python",
                    category="ast",
                )]

        # .format() call on a string
        if isinstance(first_arg, ast.Call):
            if isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                line_num = getattr(node, "lineno", 0)
                return [Finding(
                    rule_id="python.ast.sql-format",
                    message="SQL query built with .format() — SQL injection risk",
                    severity=Severity.ERROR,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else "",
                    cwe="CWE-89",
                    confidence=Confidence.HIGH,
                    language="python",
                    category="ast",
                )]

        # % formatting
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            line_num = getattr(node, "lineno", 0)
            return [Finding(
                rule_id="python.ast.sql-percent",
                message="SQL query built with % formatting — SQL injection risk",
                severity=Severity.ERROR,
                file_path=file_path,
                line_number=line_num,
                line_content=lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else "",
                cwe="CWE-89",
                confidence=Confidence.HIGH,
                language="python",
                category="ast",
            )]

        return []

    def _check_security_assert(self, node: ast.Assert, file_path: str, lines: list[str]) -> list[Finding]:
        """Detect assert used for security checks (removed with -O)."""
        line_num = getattr(node, "lineno", 0)
        line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
        security_keywords = ["auth", "permission", "access", "role", "admin", "token", "password", "login"]

        line_lower = line_content.lower()
        if any(kw in line_lower for kw in security_keywords):
            return [Finding(
                rule_id="python.ast.security-assert",
                message="assert used for security check — removed with python -O flag",
                severity=Severity.WARNING,
                file_path=file_path,
                line_number=line_num,
                line_content=line_content.rstrip(),
                cwe="CWE-617",
                confidence=Confidence.MEDIUM,
                language="python",
                category="ast",
            )]
        return []

    def _check_hardcoded_creds(self, node: ast.Assign, file_path: str, lines: list[str]) -> list[Finding]:
        """Detect hardcoded credentials in variable assignments."""
        findings: list[Finding] = []
        sensitive_names = {"password", "passwd", "secret", "api_key", "apikey",
                          "token", "private_key", "secret_key", "db_password",
                          "auth_token", "access_key"}

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(s in var_name for s in sensitive_names):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) >= 4 and val not in ("", "None", "null", "TODO", "CHANGEME", "xxx"):
                            line_num = getattr(node, "lineno", 0)
                            findings.append(Finding(
                                rule_id="python.ast.hardcoded-credential",
                                message=f"Hardcoded credential in '{target.id}' — use environment variables",
                                severity=Severity.ERROR,
                                file_path=file_path,
                                line_number=line_num,
                                line_content=lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else "",
                                cwe="CWE-798",
                                owasp="A07:2021",
                                confidence=Confidence.MEDIUM,
                                language="python",
                                category="ast",
                            ))
        return findings

    def _check_ssl_verify(self, node: ast.Call, file_path: str, lines: list[str]) -> list[Finding]:
        """Detect verify=False in HTTP requests."""
        for kw in node.keywords:
            if kw.arg == "verify":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    line_num = getattr(node, "lineno", 0)
                    return [Finding(
                        rule_id="python.ast.ssl-verify-disabled",
                        message="SSL/TLS verification disabled (verify=False) — MITM risk",
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=lines[line_num - 1].rstrip() if 0 < line_num <= len(lines) else "",
                        cwe="CWE-295",
                        owasp="A07:2021",
                        confidence=Confidence.HIGH,
                        language="python",
                        category="ast",
                    )]
        return []

    # ── Helpers ────────────────────────────────────────────────────────────

    def _resolve_call_name(self, node: ast.Call) -> str:
        """Resolve the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _has_dynamic_argument(self, node: ast.Call) -> bool:
        """Check if a call has any non-literal argument."""
        for arg in node.args:
            if not isinstance(arg, ast.Constant):
                return True
        return False

    def _has_safe_loader(self, node: ast.Call) -> bool:
        """Check if yaml.load() call has Loader=SafeLoader."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                    return True
                if isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                    return True
        return False
