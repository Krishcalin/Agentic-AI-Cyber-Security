"""Cross-file taint tracking — traces data flow across Python modules.

Extends single-file TaintTracker to detect vulnerabilities where user input
enters in one file (e.g., a route handler) and reaches a sink in another
file (e.g., a database query) via function calls and imports.

Flow:
  1. Build module map (file paths → Python module names)
  2. Per-file summary (exported functions, taint sources, return taint status)
  3. Cross-file propagation (follow imports, propagate taint across boundaries)
  4. Cross-file sink detection (find sinks reached by cross-file tainted data)
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from core.models import Confidence, FileResult, Finding, Severity
from core.taint_tracker import SOURCE_FUNCTIONS, TAINT_SINKS, TAINT_SOURCES

log = structlog.get_logger("cross_file_taint")


@dataclass
class FunctionTaintInfo:
    """Taint summary for a single function."""
    name: str
    params_tainted: list[int] = field(default_factory=list)
    returns_tainted: bool = False
    taint_source: str = ""
    param_names: list[str] = field(default_factory=list)


@dataclass
class FileTaintSummary:
    """Taint summary for a single file."""
    file_path: str
    module_name: str
    functions: dict[str, FunctionTaintInfo] = field(default_factory=dict)
    module_tainted_vars: dict[str, str] = field(default_factory=dict)
    imports_from_project: dict[str, str] = field(default_factory=dict)  # local_alias → module.func
    calls_to_imported: list[tuple[str, list[str]]] = field(default_factory=list)  # (func_name, arg_names)


class CrossFileTaintTracker:
    """Tracks tainted data flow across Python files in a project."""

    MAX_PROPAGATION_PASSES = 10

    def __init__(self) -> None:
        self._module_map: dict[str, str] = {}  # dotted.module → file_path
        self._file_to_module: dict[str, str] = {}  # file_path → dotted.module
        self._summaries: dict[str, FileTaintSummary] = {}  # file_path → summary
        # Cross-file taint: function_fqn → is param N tainted from caller
        self._cross_tainted_params: dict[str, set[int]] = {}

    def analyze_project(
        self,
        directory: str,
        exclude: list[str] | None = None,
    ) -> list[Finding]:
        """Run cross-file taint analysis on a Python project."""
        start = time.time()
        exclude = exclude or []

        # Phase 1: Build module map
        self._build_module_map(directory, exclude)
        if len(self._module_map) < 2:
            return []  # Need at least 2 files for cross-file analysis

        # Phase 2: Per-file summaries
        for file_path in self._file_to_module:
            self._analyze_file_summary(file_path)

        # Phase 3: Cross-file taint propagation
        self._propagate_cross_file()

        # Phase 4: Detect cross-file sinks
        findings = self._detect_cross_file_sinks()

        elapsed = (time.time() - start) * 1000
        log.info(
            "cross_file_taint_complete",
            files=len(self._summaries),
            findings=len(findings),
            time_ms=round(elapsed, 1),
        )
        return findings

    # ── Phase 1: Module Map ─────────────────────────────────────────────

    def _build_module_map(self, directory: str, exclude: list[str]) -> None:
        """Map Python files to their module paths."""
        self._module_map.clear()
        self._file_to_module.clear()
        base = Path(directory).resolve()

        for py_file in base.rglob("*.py"):
            # Skip excluded directories
            rel = py_file.relative_to(base)
            if any(part in exclude for part in rel.parts):
                continue
            if py_file.name.startswith("__"):
                continue

            # Convert path to module name: foo/bar/baz.py → foo.bar.baz
            parts = list(rel.with_suffix("").parts)
            module_name = ".".join(parts)

            file_str = str(py_file)
            self._module_map[module_name] = file_str
            self._file_to_module[file_str] = module_name

        log.debug("module_map_built", modules=len(self._module_map))

    # ── Phase 2: Per-file Summaries ─────────────────────────────────────

    def _analyze_file_summary(self, file_path: str) -> None:
        """Extract taint-relevant information from a single file."""
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=file_path)
        except (OSError, SyntaxError):
            return

        module_name = self._file_to_module.get(file_path, "")
        summary = FileTaintSummary(file_path=file_path, module_name=module_name)

        # Collect imports that resolve to project files
        self._collect_project_imports(tree, summary, module_name)

        # Analyze each function
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                info = self._analyze_function(node)
                summary.functions[node.name] = info

        # Check module-level taint sources
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                source_desc = self._check_source(node.value)
                if source_desc:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            summary.module_tainted_vars[target.id] = source_desc

        self._summaries[file_path] = summary

    def _collect_project_imports(
        self, tree: ast.AST, summary: FileTaintSummary, current_module: str
    ) -> None:
        """Resolve imports that point to other project files."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                # Handle relative imports
                module = node.module
                if node.level > 0:
                    # Relative import: resolve against current module
                    parts = current_module.split(".")
                    if node.level <= len(parts):
                        base = ".".join(parts[: -node.level]) if node.level < len(parts) else ""
                        module = f"{base}.{module}" if base else module

                for alias in node.names:
                    name = alias.asname or alias.name
                    fqn = f"{module}.{alias.name}"
                    # Check if this resolves to a project module
                    if module in self._module_map or any(
                        m.startswith(module + ".") for m in self._module_map
                    ):
                        summary.imports_from_project[name] = fqn

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if alias.name in self._module_map:
                        summary.imports_from_project[name] = alias.name

    def _analyze_function(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionTaintInfo:
        """Analyze a function for taint characteristics."""
        info = FunctionTaintInfo(
            name=func.name,
            param_names=[a.arg for a in func.args.args if a.arg not in ("self", "cls")],
        )

        # Check if function is a route handler (params are tainted)
        for decorator in func.decorator_list:
            if self._is_route_decorator(decorator):
                info.taint_source = "route handler"
                # In Flask, the 'request' object is the source, not the function params
                break

        # Collect tainted variables within the function
        local_tainted: set[str] = set()

        # Check for taint sources in assignments
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                source_desc = self._check_source(node.value)
                if source_desc:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            local_tainted.add(target.id)

        # Check if function returns tainted data
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value:
                if self._expr_uses_vars(node.value, local_tainted):
                    info.returns_tainted = True
                    info.taint_source = info.taint_source or "tainted local"

        # Check which params flow to return value or dangerous calls
        param_set = set(info.param_names)
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value:
                for i, param in enumerate(info.param_names):
                    if self._expr_uses_vars(node.value, {param}):
                        info.params_tainted.append(i)

        return info

    # ── Phase 3: Cross-file Propagation ─────────────────────────────────

    def _propagate_cross_file(self) -> None:
        """Propagate taint information across file boundaries."""
        changed = True
        passes = 0

        while changed and passes < self.MAX_PROPAGATION_PASSES:
            changed = False
            passes += 1

            for file_path, summary in self._summaries.items():
                for local_name, fqn in summary.imports_from_project.items():
                    # Resolve the imported function
                    parts = fqn.rsplit(".", 1)
                    if len(parts) != 2:
                        continue
                    mod_path, func_name = parts

                    # Find the source file
                    source_file = self._module_map.get(mod_path)
                    if not source_file or source_file not in self._summaries:
                        continue

                    source_summary = self._summaries[source_file]
                    func_info = source_summary.functions.get(func_name)
                    if not func_info:
                        continue

                    # If the imported function returns tainted data,
                    # mark callers' variables as tainted
                    if func_info.returns_tainted:
                        self._mark_callers_tainted(summary, local_name, func_info)
                        for caller_func in summary.functions.values():
                            if self._function_calls(caller_func.name, summary, local_name):
                                if not caller_func.returns_tainted:
                                    caller_func.returns_tainted = True
                                    caller_func.taint_source = f"cross-file from {mod_path}.{func_name}"
                                    changed = True

                    # Propagate tainted params: if callers of this file's functions
                    # pass tainted data, propagate to the imported function's params
                    tainted_args = self._find_tainted_call_args(
                        file_path, summary, local_name
                    )
                    for arg_idx in tainted_args:
                        if arg_idx < len(func_info.param_names):
                            param_name = func_info.param_names[arg_idx]
                            if arg_idx not in func_info.params_tainted:
                                func_info.params_tainted.append(arg_idx)
                                changed = True

        log.debug("cross_file_propagation", passes=passes)

    def _mark_callers_tainted(
        self, summary: FileTaintSummary, func_name: str, func_info: FunctionTaintInfo
    ) -> None:
        """Mark variables assigned from a tainted function call."""
        # Parse the file to find calls to func_name and track assignments
        try:
            source = Path(summary.file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if self._call_matches(node.value, func_name):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            summary.module_tainted_vars[target.id] = (
                                f"return from {func_name}()"
                            )

    def _function_calls(
        self, caller_name: str, summary: FileTaintSummary, callee_name: str
    ) -> bool:
        """Check if a function in this file calls the given function."""
        try:
            source = Path(summary.file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return False

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                if node.name == caller_name:
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call) and self._call_matches(child, callee_name):
                            return True
        return False

    # ── Phase 4: Cross-file Sink Detection ──────────────────────────────

    def _detect_cross_file_sinks(self) -> list[Finding]:
        """Detect sinks reached by cross-file tainted data."""
        findings: list[Finding] = []

        for file_path, summary in self._summaries.items():
            try:
                source = Path(file_path).read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=file_path)
                lines = source.splitlines()
            except (OSError, SyntaxError):
                continue

            # Build set of tainted vars from:
            # 1. Module-level tainted vars
            # 2. Function params that receive tainted args from callers
            tainted_in_file = set(summary.module_tainted_vars.keys())

            # Check each function for params that receive cross-file tainted data
            for func_node in ast.walk(tree):
                if not isinstance(func_node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue

                func_info = summary.functions.get(func_node.name)
                if not func_info:
                    continue

                # Params tainted by cross-file callers
                local_tainted = set()
                for idx in func_info.params_tainted:
                    if idx < len(func_info.param_names):
                        local_tainted.add(func_info.param_names[idx])

                # Also check: is this function called with tainted args from another file?
                local_tainted |= self._get_cross_file_tainted_params(
                    func_info, summary
                )

                if not local_tainted and not tainted_in_file:
                    continue

                all_tainted = local_tainted | tainted_in_file

                # Propagate within function
                all_tainted = self._propagate_within_function(func_node, all_tainted)

                # Check sinks
                for node in ast.walk(func_node):
                    if not isinstance(node, ast.Call):
                        continue

                    call_name = self._resolve_call_name(node)
                    if not call_name:
                        continue

                    for sink in TAINT_SINKS:
                        if not self._matches_sink(call_name, sink.func_pattern):
                            continue

                        if sink.arg_index < len(node.args):
                            arg = node.args[sink.arg_index]
                            if self._expr_uses_vars(arg, all_tainted):
                                tainted_var = self._get_var_name(arg)
                                line_num = getattr(node, "lineno", 0)
                                line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

                                findings.append(Finding(
                                    rule_id=f"python.cross-file-taint.{sink.vuln_type}",
                                    message=f"Cross-file taint: {sink.message}",
                                    severity=Severity.ERROR,
                                    file_path=file_path,
                                    line_number=line_num,
                                    line_content=line_content.rstrip(),
                                    cwe=sink.cwe,
                                    confidence=Confidence.HIGH,
                                    language="python",
                                    category="cross-file-taint",
                                    metadata={
                                        "sink": call_name,
                                        "tainted_var": tainted_var,
                                        "flow_type": "cross-file",
                                    },
                                ))

        return findings

    def _get_cross_file_tainted_params(
        self, func_info: FunctionTaintInfo, summary: FileTaintSummary
    ) -> set[str]:
        """Check if any callers pass tainted data to this function's params."""
        tainted_params: set[str] = set()

        # Look at all other files that import from this file's module
        for other_path, other_summary in self._summaries.items():
            if other_path == summary.file_path:
                continue

            for local_name, fqn in other_summary.imports_from_project.items():
                if fqn.endswith(f".{func_info.name}"):
                    # This file imports our function. Check if it calls it with tainted args.
                    tainted_args = self._find_tainted_call_args(
                        other_path, other_summary, local_name
                    )
                    for idx in tainted_args:
                        if idx < len(func_info.param_names):
                            tainted_params.add(func_info.param_names[idx])

        return tainted_params

    def _find_tainted_call_args(
        self, file_path: str, summary: FileTaintSummary, func_name: str
    ) -> set[int]:
        """Find which argument positions are tainted when calling func_name."""
        tainted_indices: set[int] = set()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return tainted_indices

        # Collect all tainted vars in this file
        file_tainted = set(summary.module_tainted_vars.keys())

        # Also check function-local tainted vars
        for func_node in ast.walk(tree):
            if not isinstance(func_node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue

            func_info = summary.functions.get(func_node.name)
            local_tainted = set(file_tainted)

            # Route handler params are tainted
            if func_info and func_info.taint_source == "route handler":
                for p in func_info.param_names:
                    local_tainted.add(p)

            # Function params marked as tainted by cross-file callers
            if func_info:
                for idx in func_info.params_tainted:
                    if idx < len(func_info.param_names):
                        local_tainted.add(func_info.param_names[idx])

            # Check for taint sources within the function
            for node in ast.walk(func_node):
                if isinstance(node, ast.Assign):
                    source_desc = self._check_source(node.value)
                    if source_desc:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                local_tainted.add(target.id)

            # Find calls to func_name and check args
            for node in ast.walk(func_node):
                if isinstance(node, ast.Call) and self._call_matches(node, func_name):
                    for i, arg in enumerate(node.args):
                        if self._expr_uses_vars(arg, local_tainted):
                            tainted_indices.add(i)

        return tainted_indices

    def _propagate_within_function(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, tainted: set[str]
    ) -> set[str]:
        """Propagate taint within a function body."""
        result = set(tainted)
        changed = True
        passes = 0
        while changed and passes < 5:
            changed = False
            passes += 1
            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    if self._expr_uses_vars(node.value, result):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id not in result:
                                result.add(target.id)
                                changed = True
        return result

    # ── Helpers ──────────────────────────────────────────────────────────

    def _check_source(self, node: ast.AST) -> str:
        """Check if an AST node is a taint source."""
        if isinstance(node, ast.Attribute):
            full = self._resolve_attr(node)
            for src, desc in TAINT_SOURCES.items():
                if full == src or full.endswith(src):
                    return desc

        if isinstance(node, ast.Call):
            name = self._resolve_call_name(node)
            if name in SOURCE_FUNCTIONS:
                return f"{name}()"
            for src, desc in TAINT_SOURCES.items():
                if name.startswith(src):
                    return desc

        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
            full = self._resolve_attr(node.value)
            for src, desc in TAINT_SOURCES.items():
                if full == src or full.endswith(src):
                    return desc

        return ""

    def _expr_uses_vars(self, node: ast.AST, var_names: set[str]) -> bool:
        """Check if an expression uses any of the given variable names."""
        if isinstance(node, ast.Name):
            return node.id in var_names
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id in var_names
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_uses_vars(v, var_names) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_uses_vars(node.value, var_names)
        if isinstance(node, ast.BinOp):
            return self._expr_uses_vars(node.left, var_names) or self._expr_uses_vars(node.right, var_names)
        if isinstance(node, ast.Call):
            return any(self._expr_uses_vars(a, var_names) for a in node.args)
        if isinstance(node, ast.Subscript):
            return self._expr_uses_vars(node.value, var_names)
        return False

    def _get_var_name(self, node: ast.AST) -> str:
        """Get variable name from expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return node.value.id
        if isinstance(node, ast.Call):
            for a in node.args:
                name = self._get_var_name(a)
                if name:
                    return name
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                name = self._get_var_name(v)
                if name:
                    return name
        return ""

    def _call_matches(self, node: ast.AST, func_name: str) -> bool:
        """Check if a Call node calls the given function name."""
        if not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Name):
            return node.func.id == func_name
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == func_name
        return False

    def _matches_sink(self, call_name: str, pattern: str) -> bool:
        """Check if a call matches a sink pattern."""
        if call_name == pattern:
            return True
        if pattern.startswith(".") and call_name.endswith(pattern):
            return True
        if "." in pattern and call_name.endswith(pattern.split(".")[-1]):
            return True
        return False

    def _resolve_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._resolve_attr(node.func)
        return ""

    def _resolve_attr(self, node: ast.Attribute) -> str:
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _is_route_decorator(self, decorator: ast.AST) -> bool:
        """Check if a decorator is a web framework route."""
        if isinstance(decorator, ast.Call):
            name = self._resolve_call_name(decorator)
            return any(name.endswith(p) for p in [
                "app.route", "app.get", "app.post", "app.put", "app.delete",
                "router.get", "router.post", "blueprint.route",
            ])
        if isinstance(decorator, ast.Attribute):
            return decorator.attr in ("route", "get", "post", "put", "delete", "patch")
        return False
