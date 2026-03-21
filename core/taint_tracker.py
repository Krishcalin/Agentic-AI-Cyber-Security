"""Taint tracking engine for cross-function data flow analysis.

Tracks user-controlled input (sources) through variable assignments
and function calls to dangerous operations (sinks), detecting
injection vulnerabilities that require data flow awareness.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, FileResult, Finding, Severity

log = structlog.get_logger("taint_tracker")


# ──────────────────────────────────────────────────────────────────────────
# Source and Sink definitions
# ──────────────────────────────────────────────────────────────────────────

# Sources: where user-controlled data enters the program
TAINT_SOURCES: dict[str, str] = {
    # Flask
    "request.args": "Flask query parameters",
    "request.form": "Flask form data",
    "request.data": "Flask raw body",
    "request.json": "Flask JSON body",
    "request.values": "Flask combined args+form",
    "request.headers": "Flask request headers",
    "request.cookies": "Flask cookies",
    "request.files": "Flask file upload",
    "request.get_json": "Flask JSON body",
    # Django
    "request.GET": "Django GET parameters",
    "request.POST": "Django POST parameters",
    "request.body": "Django raw body",
    "request.META": "Django request metadata",
    # FastAPI
    # (params come as function arguments, detected by framework detection)
    # General
    "input": "Python input() builtin",
    "sys.argv": "Command-line arguments",
    "sys.stdin": "Standard input",
    "os.environ": "Environment variables",
    "os.getenv": "Environment variable",
}

# Source function calls that return tainted data
SOURCE_FUNCTIONS: set[str] = {
    "input", "raw_input",
    "os.getenv", "os.environ.get",
    "request.args.get", "request.form.get", "request.values.get",
    "request.cookies.get", "request.headers.get",
    "request.get_json",
}

# Sinks: dangerous functions where tainted data causes vulnerabilities
@dataclass
class Sink:
    func_pattern: str      # Dotted function name pattern
    vuln_type: str         # "sql_injection", "command_injection", etc.
    message: str
    cwe: str
    severity: Severity = Severity.ERROR
    arg_index: int = 0     # Which argument is dangerous (0 = first)


TAINT_SINKS: list[Sink] = [
    # SQL Injection
    Sink("cursor.execute", "sql_injection", "Tainted data flows to SQL query — SQL injection", "CWE-89"),
    Sink("cursor.executemany", "sql_injection", "Tainted data flows to SQL query — SQL injection", "CWE-89"),
    Sink(".execute", "sql_injection", "Tainted data flows to database execute — SQL injection", "CWE-89"),
    Sink(".raw", "sql_injection", "Tainted data flows to raw SQL query", "CWE-89"),

    # Command Injection
    Sink("os.system", "command_injection", "Tainted data flows to os.system() — command injection", "CWE-78"),
    Sink("os.popen", "command_injection", "Tainted data flows to os.popen() — command injection", "CWE-78"),
    Sink("subprocess.call", "command_injection", "Tainted data flows to subprocess — command injection", "CWE-78"),
    Sink("subprocess.run", "command_injection", "Tainted data flows to subprocess — command injection", "CWE-78"),
    Sink("subprocess.Popen", "command_injection", "Tainted data flows to subprocess — command injection", "CWE-78"),
    Sink("subprocess.check_output", "command_injection", "Tainted data flows to subprocess — command injection", "CWE-78"),

    # Code Injection
    Sink("eval", "code_injection", "Tainted data flows to eval() — code injection", "CWE-95"),
    Sink("exec", "code_injection", "Tainted data flows to exec() — code injection", "CWE-95"),

    # Path Traversal
    Sink("open", "path_traversal", "Tainted data flows to open() — path traversal risk", "CWE-22"),
    Sink("os.path.join", "path_traversal", "Tainted data in file path — path traversal risk", "CWE-22"),
    Sink("pathlib.Path", "path_traversal", "Tainted data in Path() — path traversal risk", "CWE-22"),

    # LDAP Injection
    Sink("ldap.search", "ldap_injection", "Tainted data flows to LDAP search — injection risk", "CWE-90"),

    # XSS (server-side)
    Sink("Markup", "xss", "Tainted data flows to Markup() — XSS risk", "CWE-79"),
    Sink("render_template_string", "xss", "Tainted data in template string — XSS risk", "CWE-79"),

    # Deserialization
    Sink("pickle.loads", "deserialization", "Tainted data flows to pickle.loads() — code execution", "CWE-502"),
    Sink("yaml.load", "deserialization", "Tainted data flows to yaml.load() — code execution", "CWE-502"),
]


class TaintTracker:
    """Tracks tainted data from sources to sinks through Python AST."""

    def __init__(self) -> None:
        self._tainted_vars: set[str] = set()
        self._var_origins: dict[str, str] = {}   # var → source description
        self._functions: dict[str, ast.FunctionDef] = {}
        self._imports: dict[str, str] = {}

    def analyze_file(self, file_path: str) -> FileResult:
        """Run taint analysis on a Python file."""
        result = FileResult(file_path=file_path, language="python")
        start = time.time()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.error = str(e)
            return result

        result.lines_scanned = len(source.splitlines())
        findings = self.analyze_source(source, file_path)
        result.findings = findings
        result.scan_time_ms = (time.time() - start) * 1000

        log.debug("taint_analyzed", file=file_path, findings=len(findings),
                  tainted_vars=len(self._tainted_vars))
        return result

    def analyze_source(self, source: str, filename: str = "<string>") -> list[Finding]:
        """Run taint analysis on source code string."""
        self._tainted_vars = set()
        self._var_origins = {}
        self._functions = {}
        self._imports = {}

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return []

        lines = source.splitlines()

        # Pass 1: collect imports and function defs
        self._collect_metadata(tree)

        # Pass 2: identify tainted variables (sources)
        self._identify_sources(tree)

        # Pass 3: propagate taint through assignments
        self._propagate_taint(tree)

        # Pass 4: check if tainted data reaches sinks
        findings = self._check_sinks(tree, filename, lines)

        return findings

    def _collect_metadata(self, tree: ast.AST) -> None:
        """Collect imports and function definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    self._imports[alias.asname or alias.name] = f"{module}.{alias.name}"
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self._functions[node.name] = node

    def _identify_sources(self, tree: ast.AST) -> None:
        """Identify variables that receive tainted data from sources."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = node.value
                source_desc = self._is_source(value)
                if source_desc:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self._tainted_vars.add(target.id)
                            self._var_origins[target.id] = source_desc

            # Function parameters in web handlers are tainted
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                # Detect Flask/Django/FastAPI route handler params
                for decorator in node.decorator_list:
                    if self._is_route_decorator(decorator):
                        for arg in node.args.args:
                            if arg.arg not in ("self", "cls"):
                                self._tainted_vars.add(arg.arg)
                                self._var_origins[arg.arg] = "route handler parameter"

    def _propagate_taint(self, tree: ast.AST) -> None:
        """Propagate taint through variable assignments (multi-pass)."""
        changed = True
        max_passes = 5
        passes = 0

        while changed and passes < max_passes:
            changed = False
            passes += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    if self._value_is_tainted(node.value):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id not in self._tainted_vars:
                                self._tainted_vars.add(target.id)
                                self._var_origins[target.id] = "propagated"
                                changed = True

    def _check_sinks(self, tree: ast.AST, filename: str, lines: list[str]) -> list[Finding]:
        """Check if tainted data reaches any sink."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._resolve_call_name(node)
            if not call_name:
                continue

            for sink in TAINT_SINKS:
                if not self._matches_sink(call_name, sink.func_pattern):
                    continue

                # Check if the relevant argument is tainted
                arg_idx = sink.arg_index
                if arg_idx < len(node.args):
                    arg = node.args[arg_idx]
                    if self._is_tainted_expr(arg):
                        tainted_name = self._get_tainted_name(arg)
                        origin = self._var_origins.get(tainted_name, "user input")
                        line_num = getattr(node, "lineno", 0)
                        line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

                        findings.append(Finding(
                            rule_id=f"python.taint.{sink.vuln_type}",
                            message=f"{sink.message} (source: {origin})",
                            severity=sink.severity,
                            file_path=filename,
                            line_number=line_num,
                            line_content=line_content.rstrip(),
                            cwe=sink.cwe,
                            confidence=Confidence.HIGH,
                            language="python",
                            category="taint",
                            metadata={"source": origin, "sink": call_name, "tainted_var": tainted_name},
                        ))

        return findings

    # ── Source detection ───────────────────────────────────────────────────

    def _is_source(self, node: ast.AST) -> str:
        """Check if an AST node represents a taint source. Returns description or empty string."""
        # Direct source attribute access: request.args, sys.argv, etc.
        if isinstance(node, ast.Attribute):
            full = self._resolve_attr(node)
            for source_pattern, desc in TAINT_SOURCES.items():
                if full == source_pattern or full.endswith(source_pattern):
                    return desc

        # Source function calls: input(), os.getenv(), request.args.get()
        if isinstance(node, ast.Call):
            call_name = self._resolve_call_name(node)
            if call_name in SOURCE_FUNCTIONS:
                return f"{call_name}()"
            for source_pattern, desc in TAINT_SOURCES.items():
                if call_name.startswith(source_pattern):
                    return desc

        # Subscript: request.args["key"], os.environ["VAR"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                full = self._resolve_attr(node.value)
                for source_pattern, desc in TAINT_SOURCES.items():
                    if full == source_pattern or full.endswith(source_pattern):
                        return desc

        return ""

    def _value_is_tainted(self, node: ast.AST) -> bool:
        """Check if an expression is tainted."""
        return self._is_tainted_expr(node)

    def _is_tainted_expr(self, node: ast.AST) -> bool:
        """Recursively check if an expression contains tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self._tainted_vars

        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id in self._tainted_vars
            return self._is_tainted_expr(node.value)

        # f-strings
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted_expr(v) for v in node.values)

        if isinstance(node, ast.FormattedValue):
            return self._is_tainted_expr(node.value)

        # Binary ops (string concat, % formatting)
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)

        # Method calls on tainted data (.strip(), .lower(), etc.)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return self._is_tainted_expr(node.func.value)
            call_name = self._resolve_call_name(node)
            # Check if any argument is tainted
            return any(self._is_tainted_expr(a) for a in node.args)

        # Subscripts: tainted_dict["key"]
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)

        return False

    def _get_tainted_name(self, node: ast.AST) -> str:
        """Get the name of the tainted variable in an expression."""
        if isinstance(node, ast.Name) and node.id in self._tainted_vars:
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                name = self._get_tainted_name(v)
                if name:
                    return name
        if isinstance(node, ast.FormattedValue):
            return self._get_tainted_name(node.value)
        if isinstance(node, ast.BinOp):
            return self._get_tainted_name(node.left) or self._get_tainted_name(node.right)
        if isinstance(node, ast.Call):
            for a in node.args:
                name = self._get_tainted_name(a)
                if name:
                    return name
        return ""

    # ── Helpers ────────────────────────────────────────────────────────────

    def _resolve_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._resolve_attr(node.func)
        return ""

    def _resolve_attr(self, node: ast.Attribute) -> str:
        parts = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _matches_sink(self, call_name: str, pattern: str) -> bool:
        """Check if a call matches a sink pattern."""
        if call_name == pattern:
            return True
        if pattern.startswith(".") and call_name.endswith(pattern):
            return True
        if "." in pattern and call_name.endswith(pattern.split(".")[-1]):
            return True
        return False

    def _is_route_decorator(self, decorator: ast.AST) -> bool:
        """Check if a decorator is a web framework route decorator."""
        if isinstance(decorator, ast.Call):
            name = self._resolve_call_name(decorator)
            route_patterns = ["app.route", "app.get", "app.post", "app.put", "app.delete",
                            "router.get", "router.post", "blueprint.route"]
            return any(name.endswith(p) for p in route_patterns)
        if isinstance(decorator, ast.Attribute):
            return decorator.attr in ("route", "get", "post", "put", "delete", "patch")
        return False
