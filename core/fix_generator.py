"""Auto-fix engine — generates CWE-mapped code remediation patches.

Transforms detected vulnerabilities into patched code using
pattern-based templates. Produces unified diff output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from core.models import Finding

log = structlog.get_logger("fix_generator")


@dataclass
class Fix:
    """A single auto-fix for a finding."""
    finding: Finding
    original_line: str
    fixed_line: str
    explanation: str
    cwe: str = ""
    confidence: str = "high"    # How confident the fix is correct
    requires_import: str = ""   # Additional import needed

    @property
    def has_fix(self) -> bool:
        return self.fixed_line != self.original_line and self.fixed_line != ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.finding.rule_id,
            "file": self.finding.file_path,
            "line": self.finding.line_number,
            "original": self.original_line,
            "fixed": self.fixed_line,
            "explanation": self.explanation,
            "cwe": self.cwe,
            "requires_import": self.requires_import,
        }


@dataclass
class FixResult:
    """Collection of fixes for a scan."""
    fixes: list[Fix] = field(default_factory=list)
    unfixable: list[Finding] = field(default_factory=list)

    @property
    def fix_count(self) -> int:
        return len(self.fixes)

    @property
    def unfixable_count(self) -> int:
        return len(self.unfixable)

    def generate_diff(self, file_path: str) -> str:
        """Generate a unified diff for fixes in a specific file."""
        file_fixes = [f for f in self.fixes if f.finding.file_path == file_path]
        if not file_fixes:
            return ""

        lines: list[str] = []
        lines.append(f"--- a/{file_path}")
        lines.append(f"+++ b/{file_path}")

        for fix in sorted(file_fixes, key=lambda f: f.finding.line_number):
            ln = fix.finding.line_number
            lines.append(f"@@ -{ln},1 +{ln},1 @@")
            lines.append(f"-{fix.original_line}")
            lines.append(f"+{fix.fixed_line}")

        return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────
# Fix templates — organized by CWE
# ──────────────────────────────────────────────────────────────────────────

class FixTemplates:
    """CWE-mapped fix templates for automatic code remediation."""

    @staticmethod
    def fix_finding(finding: Finding) -> Fix | None:
        """Attempt to generate a fix for a finding. Returns None if unfixable."""
        line = finding.line_content
        if not line:
            return None

        # Route to the appropriate fixer by CWE or rule pattern
        fixers = [
            FixTemplates._fix_sql_injection,
            FixTemplates._fix_command_injection,
            FixTemplates._fix_eval_exec,
            FixTemplates._fix_pickle,
            FixTemplates._fix_yaml_load,
            FixTemplates._fix_weak_hash,
            FixTemplates._fix_weak_random,
            FixTemplates._fix_ssl_verify,
            FixTemplates._fix_hardcoded_secret,
            FixTemplates._fix_debug_mode,
            FixTemplates._fix_csrf_exempt,
            FixTemplates._fix_tempfile,
            FixTemplates._fix_chmod_world_writable,
            FixTemplates._fix_subprocess_shell,
            FixTemplates._fix_os_system,
            FixTemplates._fix_os_popen,
            FixTemplates._fix_xss_innerhtml,
            FixTemplates._fix_document_write,
            FixTemplates._fix_tls_reject,
            FixTemplates._fix_cors_wildcard,
            FixTemplates._fix_math_random,
            FixTemplates._fix_weak_jwt,
            FixTemplates._fix_ecb_mode,
            FixTemplates._fix_assert_security,
            FixTemplates._fix_broad_except,
            FixTemplates._fix_xml_parse,
        ]

        for fixer in fixers:
            fix = fixer(finding, line)
            if fix and fix.has_fix:
                return fix

        return None

    # ── SQL Injection (CWE-89) ─────────────────────────────────────────

    @staticmethod
    def _fix_sql_injection(finding: Finding, line: str) -> Fix | None:
        if "CWE-89" not in finding.cwe and "sql" not in finding.rule_id.lower():
            return None

        # f-string → parameterized
        m = re.search(r'\.execute\s*\(\s*f["\'](.+?)["\']', line)
        if m:
            # Extract variable names from f-string
            vars_found = re.findall(r'\{(\w+)\}', m.group(1))
            if vars_found:
                placeholders = ", ".join(["%s"] * len(vars_found))
                sql_template = re.sub(r'\{(\w+)\}', '%s', m.group(1))
                params = ", ".join(vars_found)
                indent = len(line) - len(line.lstrip())
                fixed = f'{" " * indent}{line.split(".execute")[0].strip()}.execute("{sql_template}", ({params},))'
                return Fix(
                    finding=finding, original_line=line, fixed_line=fixed,
                    explanation="Use parameterized query instead of f-string to prevent SQL injection",
                    cwe="CWE-89", confidence="high",
                )

        # % formatting → parameterized
        if "%" in line and ".execute" in line:
            indent = len(line) - len(line.lstrip())
            fixed = re.sub(
                r'\.execute\s*\(\s*(["\'])(.+?)\1\s*%\s*(\w+)',
                r'.execute("\2", (\3,))',
                line,
            )
            if fixed != line:
                return Fix(
                    finding=finding, original_line=line, fixed_line=fixed,
                    explanation="Use parameterized query instead of % formatting",
                    cwe="CWE-89", confidence="medium",
                )

        return None

    # ── Command Injection (CWE-78) ─────────────────────────────────────

    @staticmethod
    def _fix_os_system(finding: Finding, line: str) -> Fix | None:
        if "os.system" not in line and "os-system" not in finding.rule_id:
            return None

        m = re.search(r'os\.system\s*\(\s*(.+?)\s*\)', line)
        if m:
            cmd_arg = m.group(1)
            indent = " " * (len(line) - len(line.lstrip()))
            fixed = f'{indent}subprocess.run({cmd_arg}, shell=False, check=True)'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace os.system() with subprocess.run() using list args",
                cwe="CWE-78", confidence="medium",
                requires_import="import subprocess",
            )
        return None

    @staticmethod
    def _fix_os_popen(finding: Finding, line: str) -> Fix | None:
        if "os.popen" not in line:
            return None

        m = re.search(r'os\.popen\s*\(\s*(.+?)\s*\)', line)
        if m:
            cmd_arg = m.group(1)
            indent = " " * (len(line) - len(line.lstrip()))
            fixed = f'{indent}subprocess.run({cmd_arg}, capture_output=True, text=True, check=True)'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace os.popen() with subprocess.run() with capture_output",
                cwe="CWE-78", confidence="medium",
                requires_import="import subprocess",
            )
        return None

    @staticmethod
    def _fix_subprocess_shell(finding: Finding, line: str) -> Fix | None:
        if "shell=True" not in line:
            return None

        fixed = line.replace("shell=True", "shell=False")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Set shell=False and pass command as a list to prevent injection",
            cwe="CWE-78", confidence="high",
        )

    @staticmethod
    def _fix_command_injection(finding: Finding, line: str) -> Fix | None:
        return None  # Handled by specific os.system/popen/subprocess fixers

    # ── Code Injection (CWE-95) ────────────────────────────────────────

    @staticmethod
    def _fix_eval_exec(finding: Finding, line: str) -> Fix | None:
        if "eval(" not in line and "exec(" not in line:
            return None

        if "eval(" in line:
            indent = " " * (len(line) - len(line.lstrip()))
            fixed = f'{indent}# SECURITY: eval() removed — use ast.literal_eval() for safe parsing'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace eval() with ast.literal_eval() for safe literal parsing, or remove entirely",
                cwe="CWE-95", confidence="medium",
                requires_import="import ast",
            )

        if "exec(" in line:
            indent = " " * (len(line) - len(line.lstrip()))
            fixed = f'{indent}# SECURITY: exec() removed — dynamic code execution is dangerous'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Remove exec() — use structured alternatives instead of dynamic code execution",
                cwe="CWE-95", confidence="medium",
            )

        return None

    # ── Deserialization (CWE-502) ──────────────────────────────────────

    @staticmethod
    def _fix_pickle(finding: Finding, line: str) -> Fix | None:
        if "pickle.load" not in line and "pickle.loads" not in line:
            return None

        if "pickle.loads" in line:
            fixed = line.replace("pickle.loads(", "json.loads(")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace pickle.loads() with json.loads() for safe deserialization",
                cwe="CWE-502", confidence="medium",
                requires_import="import json",
            )
        if "pickle.load" in line:
            fixed = line.replace("pickle.load(", "json.load(")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace pickle.load() with json.load() for safe deserialization",
                cwe="CWE-502", confidence="medium",
                requires_import="import json",
            )
        return None

    @staticmethod
    def _fix_yaml_load(finding: Finding, line: str) -> Fix | None:
        if "yaml.load(" not in line:
            return None

        if "SafeLoader" in line or "safe_load" in line:
            return None

        fixed = line.replace("yaml.load(", "yaml.safe_load(")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Replace yaml.load() with yaml.safe_load() to prevent code execution",
            cwe="CWE-502", confidence="high",
        )

    # ── Weak Cryptography (CWE-328) ────────────────────────────────────

    @staticmethod
    def _fix_weak_hash(finding: Finding, line: str) -> Fix | None:
        if "hashlib.md5" in line:
            fixed = line.replace("hashlib.md5", "hashlib.sha256")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace MD5 with SHA-256 (or SHA-512 for password hashing)",
                cwe="CWE-328", confidence="high",
            )
        if "hashlib.sha1" in line:
            fixed = line.replace("hashlib.sha1", "hashlib.sha256")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace SHA-1 with SHA-256",
                cwe="CWE-328", confidence="high",
            )
        if "createHash" in line and ("'md5'" in line or '"md5"' in line):
            fixed = line.replace("'md5'", "'sha256'").replace('"md5"', '"sha256"')
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace MD5 with SHA-256",
                cwe="CWE-328", confidence="high",
            )
        if "createHash" in line and ("'sha1'" in line or '"sha1"' in line):
            fixed = line.replace("'sha1'", "'sha256'").replace('"sha1"', '"sha256"')
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Replace SHA-1 with SHA-256",
                cwe="CWE-328", confidence="high",
            )
        return None

    @staticmethod
    def _fix_weak_random(finding: Finding, line: str) -> Fix | None:
        if "random.random" not in line and "random.randint" not in line and "random.choice" not in line:
            return None

        fixed = line.replace("random.random()", "secrets.token_hex(16)")
        fixed = fixed.replace("random.randint", "secrets.randbelow")
        if fixed != line:
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Use secrets module instead of random for security-sensitive values",
                cwe="CWE-330", confidence="medium",
                requires_import="import secrets",
            )
        return None

    @staticmethod
    def _fix_ecb_mode(finding: Finding, line: str) -> Fix | None:
        if "MODE_ECB" not in line:
            return None

        fixed = line.replace("MODE_ECB", "MODE_GCM")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Replace ECB mode with GCM (authenticated encryption)",
            cwe="CWE-327", confidence="high",
        )

    # ── SSL/TLS (CWE-295) ─────────────────────────────────────────────

    @staticmethod
    def _fix_ssl_verify(finding: Finding, line: str) -> Fix | None:
        if "verify=False" in line:
            fixed = line.replace("verify=False", "verify=True")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Enable SSL/TLS certificate verification",
                cwe="CWE-295", confidence="high",
            )
        if "CERT_NONE" in line:
            fixed = line.replace("CERT_NONE", "CERT_REQUIRED")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Require certificate verification",
                cwe="CWE-295", confidence="high",
            )
        if "check_hostname=False" in line or "check_hostname = False" in line:
            fixed = line.replace("check_hostname=False", "check_hostname=True")
            fixed = fixed.replace("check_hostname = False", "check_hostname = True")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Enable hostname checking for TLS connections",
                cwe="CWE-295", confidence="high",
            )
        return None

    @staticmethod
    def _fix_tls_reject(finding: Finding, line: str) -> Fix | None:
        if "NODE_TLS_REJECT_UNAUTHORIZED" in line and "0" in line:
            fixed = line.replace('"0"', '"1"').replace("'0'", "'1'").replace("= 0", "= 1").replace("=0", "=1")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Enable TLS certificate rejection for unauthorized certificates",
                cwe="CWE-295", confidence="high",
            )
        if "rejectUnauthorized" in line and "false" in line.lower():
            fixed = line.replace("false", "true").replace("False", "True")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Enable rejectUnauthorized for TLS connections",
                cwe="CWE-295", confidence="high",
            )
        return None

    # ── Hardcoded Secrets (CWE-798) ────────────────────────────────────

    @staticmethod
    def _fix_hardcoded_secret(finding: Finding, line: str) -> Fix | None:
        if "CWE-798" not in finding.cwe and "secret" not in finding.rule_id and "password" not in finding.rule_id:
            return None

        # Python: variable = "secret" → variable = os.environ.get("VARIABLE")
        m = re.match(r'^(\s*)([\w_]+)\s*=\s*["\'][^"\']+["\']', line)
        if m:
            indent, var_name = m.group(1), m.group(2)
            env_name = var_name.upper()
            fixed = f'{indent}{var_name} = os.environ.get("{env_name}")'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation=f"Move secret to environment variable {env_name}",
                cwe="CWE-798", confidence="medium",
                requires_import="import os",
            )

        # JS: const variable = "secret" → const variable = process.env.VARIABLE
        m = re.match(r'^(\s*)(const|let|var)\s+([\w_]+)\s*=\s*["\'][^"\']+["\']', line)
        if m:
            indent, decl, var_name = m.group(1), m.group(2), m.group(3)
            env_name = re.sub(r'([A-Z])', r'_\1', var_name).upper().lstrip("_")
            fixed = f'{indent}{decl} {var_name} = process.env.{env_name}'
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation=f"Move secret to environment variable {env_name}",
                cwe="CWE-798", confidence="medium",
            )

        return None

    # ── Debug Mode (CWE-489) ──────────────────────────────────────────

    @staticmethod
    def _fix_debug_mode(finding: Finding, line: str) -> Fix | None:
        if "DEBUG" not in line.upper() and "debug" not in line:
            return None

        if "DEBUG = True" in line or "DEBUG=True" in line:
            fixed = line.replace("True", "False")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Disable debug mode in production",
                cwe="CWE-489", confidence="high",
            )
        if "debug=True" in line or "debug = True" in line:
            fixed = line.replace("debug=True", "debug=False").replace("debug = True", "debug = False")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Disable debug mode in production",
                cwe="CWE-489", confidence="high",
            )
        return None

    # ── CSRF (CWE-352) ────────────────────────────────────────────────

    @staticmethod
    def _fix_csrf_exempt(finding: Finding, line: str) -> Fix | None:
        if "@csrf_exempt" not in line:
            return None

        indent = " " * (len(line) - len(line.lstrip()))
        fixed = f"{indent}# SECURITY: @csrf_exempt removed — CSRF protection is required"
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Remove @csrf_exempt — implement proper CSRF token handling instead",
            cwe="CWE-352", confidence="high",
        )

    # ── Tempfile (CWE-377) ────────────────────────────────────────────

    @staticmethod
    def _fix_tempfile(finding: Finding, line: str) -> Fix | None:
        if "tempfile.mktemp" not in line:
            return None

        fixed = line.replace("tempfile.mktemp()", "tempfile.mkstemp()")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Replace mktemp() with mkstemp() to prevent race conditions",
            cwe="CWE-377", confidence="high",
        )

    # ── File Permissions (CWE-732) ────────────────────────────────────

    @staticmethod
    def _fix_chmod_world_writable(finding: Finding, line: str) -> Fix | None:
        if "os.chmod" not in line:
            return None

        if "0o777" in line or "0777" in line:
            fixed = line.replace("0o777", "0o755").replace("0777", "0o755")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Restrict file permissions from 777 to 755",
                cwe="CWE-732", confidence="high",
            )
        if "0o666" in line or "0666" in line:
            fixed = line.replace("0o666", "0o644").replace("0666", "0o644")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Restrict file permissions from 666 to 644",
                cwe="CWE-732", confidence="high",
            )
        return None

    # ── XSS (CWE-79) ─────────────────────────────────────────────────

    @staticmethod
    def _fix_xss_innerhtml(finding: Finding, line: str) -> Fix | None:
        if ".innerHTML" not in line:
            return None

        fixed = line.replace(".innerHTML", ".textContent")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Replace innerHTML with textContent to prevent XSS",
            cwe="CWE-79", confidence="high",
        )

    @staticmethod
    def _fix_document_write(finding: Finding, line: str) -> Fix | None:
        if "document.write" not in line:
            return None

        indent = " " * (len(line) - len(line.lstrip()))
        fixed = f"{indent}// SECURITY: document.write() removed — use DOM manipulation instead"
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Remove document.write() — use safe DOM methods (createElement, textContent)",
            cwe="CWE-79", confidence="high",
        )

    # ── CORS (CWE-942) ───────────────────────────────────────────────

    @staticmethod
    def _fix_cors_wildcard(finding: Finding, line: str) -> Fix | None:
        if "Access-Control-Allow-Origin" not in line and "origin" not in line.lower():
            return None

        if "'*'" in line or '"*"' in line:
            fixed = line.replace("'*'", "'https://yourdomain.com'").replace('"*"', '"https://yourdomain.com"')
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Restrict CORS to specific trusted origin(s)",
                cwe="CWE-942", confidence="medium",
            )
        return None

    # ── Math.random (CWE-330) ─────────────────────────────────────────

    @staticmethod
    def _fix_math_random(finding: Finding, line: str) -> Fix | None:
        if "Math.random" not in line:
            return None

        fixed = line.replace("Math.random()", "crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295")
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Use crypto.getRandomValues() for security-sensitive random values",
            cwe="CWE-330", confidence="medium",
        )

    # ── JWT (CWE-347) ────────────────────────────────────────────────

    @staticmethod
    def _fix_weak_jwt(finding: Finding, line: str) -> Fix | None:
        if "'none'" in line or '"none"' in line:
            fixed = line.replace("'none'", "'HS256'").replace('"none"', '"HS256"')
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Require a signing algorithm for JWT tokens (never use 'none')",
                cwe="CWE-347", confidence="high",
            )
        return None

    # ── Assert for Security (CWE-617) ─────────────────────────────────

    @staticmethod
    def _fix_assert_security(finding: Finding, line: str) -> Fix | None:
        if not line.strip().startswith("assert"):
            return None

        indent = " " * (len(line) - len(line.lstrip()))
        condition = line.strip()[7:].split(",")[0].strip()
        fixed = f'{indent}if not ({condition}):\n{indent}    raise PermissionError("Access denied")'
        return Fix(
            finding=finding, original_line=line, fixed_line=fixed,
            explanation="Replace assert with explicit check — assert is removed by python -O",
            cwe="CWE-617", confidence="medium",
        )

    # ── Broad Except (CWE-396) ────────────────────────────────────────

    @staticmethod
    def _fix_broad_except(finding: Finding, line: str) -> Fix | None:
        if "except:" not in line and "except Exception:" not in line:
            return None

        if "except:" in line:
            fixed = line.replace("except:", "except Exception as e:  # TODO: narrow exception type")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Catch a specific exception type instead of bare except",
                cwe="CWE-396", confidence="low",
            )
        return None

    # ── XXE (CWE-611) ────────────────────────────────────────────────

    @staticmethod
    def _fix_xml_parse(finding: Finding, line: str) -> Fix | None:
        if "xml.etree.ElementTree.parse" in line:
            fixed = line.replace("xml.etree.ElementTree.parse", "defusedxml.ElementTree.parse")
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Use defusedxml to prevent XML External Entity (XXE) attacks",
                cwe="CWE-611", confidence="high",
                requires_import="import defusedxml.ElementTree",
            )
        if "lxml.etree.parse" in line:
            indent = " " * (len(line) - len(line.lstrip()))
            fixed = f"{indent}# SECURITY: use defusedxml.lxml instead of lxml.etree for XXE protection"
            return Fix(
                finding=finding, original_line=line, fixed_line=fixed,
                explanation="Use defusedxml to prevent XXE attacks",
                cwe="CWE-611", confidence="medium",
                requires_import="import defusedxml",
            )
        return None


class FixGenerator:
    """Generates auto-fix suggestions for scan findings."""

    def generate_fixes(self, findings: list[Finding]) -> FixResult:
        """Generate fixes for a list of findings."""
        result = FixResult()

        for finding in findings:
            fix = FixTemplates.fix_finding(finding)
            if fix and fix.has_fix:
                result.fixes.append(fix)
            else:
                result.unfixable.append(finding)

        log.info("fixes_generated", fixable=result.fix_count, unfixable=result.unfixable_count)
        return result

    def get_supported_cwes(self) -> list[str]:
        """Return list of CWEs that have fix templates."""
        return [
            "CWE-78",   # Command Injection
            "CWE-79",   # XSS
            "CWE-89",   # SQL Injection
            "CWE-95",   # Code Injection (eval/exec)
            "CWE-295",  # SSL Verification
            "CWE-327",  # Weak Cipher (ECB)
            "CWE-328",  # Weak Hash (MD5/SHA1)
            "CWE-330",  # Weak Random
            "CWE-347",  # JWT None Algorithm
            "CWE-352",  # CSRF
            "CWE-377",  # Insecure Tempfile
            "CWE-396",  # Broad Except
            "CWE-489",  # Debug Mode
            "CWE-502",  # Deserialization (Pickle/YAML)
            "CWE-611",  # XXE
            "CWE-732",  # World-Writable Permissions
            "CWE-798",  # Hardcoded Credentials
            "CWE-942",  # CORS Wildcard
        ]
