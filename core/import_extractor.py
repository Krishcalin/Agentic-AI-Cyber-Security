"""Extract package imports from source files across multiple languages."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import structlog

log = structlog.get_logger("import_extractor")


@dataclass
class ExtractedImport:
    """A single extracted import statement."""
    package_name: str        # Top-level package (e.g., "requests", "flask")
    full_import: str         # Full import string (e.g., "from flask import Flask")
    file_path: str = ""
    line_number: int = 0
    registry: str = "pypi"   # pypi, npm, crates, maven, rubygems


class ImportExtractor:
    """Extracts package imports from source files."""

    def extract_from_file(self, file_path: str) -> list[ExtractedImport]:
        """Extract imports from a single file."""
        path = Path(file_path)
        if not path.exists():
            return []

        suffix = path.suffix.lower()
        name = path.name.lower()

        match suffix:
            case ".py":
                return self._extract_python(file_path)
            case ".js" | ".ts" | ".jsx" | ".tsx" | ".mjs":
                return self._extract_javascript(file_path)
            case ".go":
                return self._extract_go(file_path)
            case ".java":
                return self._extract_java(file_path)
            case ".rb":
                return self._extract_ruby(file_path)
            case ".rs":
                return self._extract_rust(file_path)
            case _:
                pass

        # Dependency files
        if name == "requirements.txt":
            return self._extract_requirements_txt(file_path)
        if name == "package.json":
            return self._extract_package_json(file_path)
        if name == "go.mod":
            return self._extract_go_mod(file_path)
        if name == "cargo.toml":
            return self._extract_cargo_toml(file_path)
        if name == "gemfile":
            return self._extract_gemfile(file_path)

        return []

    # ── Python ─────────────────────────────────────────────────────────────

    PYTHON_STDLIB = {
        "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
        "asyncore", "atexit", "base64", "bdb", "binascii", "binhex",
        "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
        "cmath", "cmd", "code", "codecs", "codeop", "collections",
        "colorsys", "compileall", "concurrent", "configparser", "contextlib",
        "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
        "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
        "difflib", "dis", "distutils", "doctest", "email", "encodings",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
        "getpass", "gettext", "glob", "grp", "gzip", "hashlib", "heapq",
        "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp",
        "importlib", "inspect", "io", "ipaddress", "itertools", "json",
        "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
        "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
        "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
        "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
        "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
        "plistlib", "poplib", "posix", "posixpath", "pprint",
        "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
        "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
        "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
        "selectors", "shelve", "shlex", "shutil", "signal", "site",
        "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "sqlite3",
        "ssl", "stat", "statistics", "string", "stringprep", "struct",
        "subprocess", "sunau", "symtable", "sys", "sysconfig", "syslog",
        "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
        "textwrap", "threading", "time", "timeit", "tkinter", "token",
        "tokenize", "tomllib", "trace", "traceback", "tracemalloc",
        "tty", "turtle", "turtledemo", "types", "typing", "unicodedata",
        "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave",
        "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
        "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
        "_thread", "__future__",
    }

    def _extract_python(self, file_path: str) -> list[ExtractedImport]:
        """Extract imports using Python AST for accuracy."""
        imports: list[ExtractedImport] = []
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return imports

        lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in self.PYTHON_STDLIB:
                        line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        imports.append(ExtractedImport(
                            package_name=top,
                            full_import=line.strip(),
                            file_path=file_path,
                            line_number=node.lineno,
                            registry="pypi",
                        ))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    if top not in self.PYTHON_STDLIB:
                        line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                        imports.append(ExtractedImport(
                            package_name=top,
                            full_import=line.strip(),
                            file_path=file_path,
                            line_number=node.lineno,
                            registry="pypi",
                        ))

        # Deduplicate by package name
        seen: set[str] = set()
        unique: list[ExtractedImport] = []
        for imp in imports:
            if imp.package_name not in seen:
                seen.add(imp.package_name)
                unique.append(imp)

        return unique

    # ── JavaScript / TypeScript ────────────────────────────────────────────

    NODE_BUILTINS = {
        "assert", "buffer", "child_process", "cluster", "console", "constants",
        "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
        "https", "inspector", "module", "net", "os", "path", "perf_hooks",
        "process", "punycode", "querystring", "readline", "repl", "stream",
        "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
        "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
        "node:assert", "node:buffer", "node:crypto", "node:fs", "node:http",
        "node:https", "node:net", "node:os", "node:path", "node:stream",
        "node:url", "node:util", "node:zlib",
    }

    def _extract_javascript(self, file_path: str) -> list[ExtractedImport]:
        """Extract imports from JavaScript/TypeScript files."""
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        # require() calls
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # require('package') or require("package")
            for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", line):
                pkg = m.group(1)
                if not pkg.startswith(".") and not pkg.startswith("/") and pkg not in self.NODE_BUILTINS:
                    top = pkg.split("/")[0]
                    if top.startswith("@"):
                        top = "/".join(pkg.split("/")[:2])
                    imports.append(ExtractedImport(
                        package_name=top, full_import=stripped,
                        file_path=file_path, line_number=i, registry="npm",
                    ))

            # import ... from 'package'
            for m in re.finditer(r"""(?:import|export)\s+.*?from\s+['"]([^'"]+)['"]""", line):
                pkg = m.group(1)
                if not pkg.startswith(".") and not pkg.startswith("/") and pkg not in self.NODE_BUILTINS:
                    top = pkg.split("/")[0]
                    if top.startswith("@"):
                        top = "/".join(pkg.split("/")[:2])
                    imports.append(ExtractedImport(
                        package_name=top, full_import=stripped,
                        file_path=file_path, line_number=i, registry="npm",
                    ))

        seen: set[str] = set()
        return [i for i in imports if i.package_name not in seen and not seen.add(i.package_name)]

    # ── Go ─────────────────────────────────────────────────────────────────

    def _extract_go(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r'\s*"([^"]+)"', line)
            if m:
                pkg = m.group(1)
                if "." in pkg and "/" in pkg:  # External packages have domain
                    imports.append(ExtractedImport(
                        package_name=pkg, full_import=line.strip(),
                        file_path=file_path, line_number=i, registry="go",
                    ))
        return imports

    # ── Java ───────────────────────────────────────────────────────────────

    def _extract_java(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        java_stdlib = {"java.", "javax.", "sun.", "com.sun.", "jdk."}
        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r'\s*import\s+(static\s+)?([a-zA-Z0-9_.]+)', line)
            if m:
                pkg = m.group(2)
                if not any(pkg.startswith(s) for s in java_stdlib):
                    group = ".".join(pkg.split(".")[:2])
                    imports.append(ExtractedImport(
                        package_name=group, full_import=line.strip(),
                        file_path=file_path, line_number=i, registry="maven",
                    ))
        return imports

    # ── Ruby ───────────────────────────────────────────────────────────────

    def _extract_ruby(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r"""\s*require\s+['"]([^'"]+)['"]""", line)
            if m:
                imports.append(ExtractedImport(
                    package_name=m.group(1), full_import=line.strip(),
                    file_path=file_path, line_number=i, registry="rubygems",
                ))
        return imports

    # ── Rust ───────────────────────────────────────────────────────────────

    def _extract_rust(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        rust_stdlib = {"std", "core", "alloc"}
        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r'\s*(?:use|extern\s+crate)\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
            if m:
                pkg = m.group(1)
                if pkg not in rust_stdlib:
                    imports.append(ExtractedImport(
                        package_name=pkg, full_import=line.strip(),
                        file_path=file_path, line_number=i, registry="crates",
                    ))
        return imports

    # ── Dependency files ───────────────────────────────────────────────────

    def _extract_requirements_txt(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        for i, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip version specifiers
            pkg = re.split(r'[>=<!\[;]', line)[0].strip()
            if pkg:
                imports.append(ExtractedImport(
                    package_name=pkg, full_import=line,
                    file_path=file_path, line_number=i, registry="pypi",
                ))
        return imports

    def _extract_package_json(self, file_path: str) -> list[ExtractedImport]:
        import json
        imports: list[ExtractedImport] = []
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return imports

        for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg in data.get(dep_key, {}):
                imports.append(ExtractedImport(
                    package_name=pkg, full_import=f"{pkg}: {data[dep_key][pkg]}",
                    file_path=file_path, registry="npm",
                ))
        return imports

    def _extract_go_mod(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r'\s+([a-zA-Z0-9._/\-]+)\s+v', line)
            if m:
                imports.append(ExtractedImport(
                    package_name=m.group(1), full_import=line.strip(),
                    file_path=file_path, line_number=i, registry="go",
                ))
        return imports

    def _extract_cargo_toml(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        in_deps = False
        for i, line in enumerate(content.splitlines(), 1):
            if re.match(r'\[.*dependencies.*\]', line):
                in_deps = True
                continue
            if line.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps:
                m = re.match(r'([a-zA-Z0-9_\-]+)\s*=', line)
                if m:
                    imports.append(ExtractedImport(
                        package_name=m.group(1), full_import=line.strip(),
                        file_path=file_path, line_number=i, registry="crates",
                    ))
        return imports

    def _extract_gemfile(self, file_path: str) -> list[ExtractedImport]:
        imports: list[ExtractedImport] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return imports

        for i, line in enumerate(content.splitlines(), 1):
            m = re.match(r"""\s*gem\s+['"]([^'"]+)['"]""", line)
            if m:
                imports.append(ExtractedImport(
                    package_name=m.group(1), full_import=line.strip(),
                    file_path=file_path, line_number=i, registry="rubygems",
                ))
        return imports
