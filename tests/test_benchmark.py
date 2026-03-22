"""Precision/recall benchmarks against vulnerable fixtures.

Each fixture contains known vulnerabilities. We verify the scanner
detects them (recall) and doesn't produce excessive false positives (precision).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.engine import ScanEngine
from core.models import Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def engine():
    e = ScanEngine("rules")
    e.initialize()
    return e


# ── Expected findings per fixture ──────────────────────────────────────────
# Format: (file, min_expected_findings, expected_cwe_set)

EXPECTED = {
    "python_vulnerable.py": {
        "min_findings": 10,
        "expected_cwes": {"CWE-89", "CWE-78", "CWE-95", "CWE-502", "CWE-328", "CWE-798", "CWE-295"},
        "expected_rules": ["sql", "command", "eval", "pickle", "md5", "password", "verify"],
    },
    "javascript_vulnerable.js": {
        "min_findings": 8,
        "expected_cwes": {"CWE-89", "CWE-79", "CWE-95", "CWE-798", "CWE-295", "CWE-328"},
        "expected_rules": ["sql", "innerhtml", "eval", "password", "tls", "md5"],
    },
    "java_vulnerable.java": {
        "min_findings": 5,
        "expected_cwes": {"CWE-89", "CWE-78", "CWE-328", "CWE-502"},
        "expected_rules": ["sql", "runtime", "md5", "ObjectInputStream"],
    },
    "go_vulnerable.go": {
        "min_findings": 4,
        "expected_cwes": {"CWE-89", "CWE-78", "CWE-328", "CWE-295"},
        "expected_rules": ["sql", "bash", "md5", "InsecureSkipVerify"],
    },
    "php_vulnerable.php": {
        "min_findings": 6,
        "expected_cwes": {"CWE-89", "CWE-78", "CWE-95", "CWE-798", "CWE-328"},
        "expected_rules": ["sql", "system", "eval", "md5", "password"],
    },
    "terraform_vulnerable.tf": {
        "min_findings": 5,
        "expected_cwes": {"CWE-284", "CWE-250", "CWE-311"},
        "expected_rules": ["public", "cidr", "encrypted", "wildcard"],
    },
    "kubernetes_vulnerable.yaml": {
        "min_findings": 5,
        "expected_cwes": {"CWE-250"},
        "expected_rules": ["privileged", "hostNetwork", "SYS_ADMIN", "cluster-admin"],
    },
}


class TestRecall:
    """Verify the scanner detects expected vulnerabilities (recall)."""

    @pytest.mark.parametrize("fixture_name,expectations", EXPECTED.items())
    def test_minimum_findings(self, engine: ScanEngine, fixture_name: str, expectations: dict):
        path = str(FIXTURES_DIR / fixture_name)
        if not Path(path).exists():
            pytest.skip(f"Fixture not found: {fixture_name}")

        result = engine.scan_file(path)
        assert result.total_findings >= expectations["min_findings"], (
            f"{fixture_name}: expected >= {expectations['min_findings']} findings, "
            f"got {result.total_findings}"
        )

    @pytest.mark.parametrize("fixture_name,expectations", EXPECTED.items())
    def test_expected_cwes(self, engine: ScanEngine, fixture_name: str, expectations: dict):
        path = str(FIXTURES_DIR / fixture_name)
        if not Path(path).exists():
            pytest.skip(f"Fixture not found: {fixture_name}")

        result = engine.scan_file(path)
        found_cwes = {f.cwe for f in result.all_findings if f.cwe}

        for expected_cwe in expectations["expected_cwes"]:
            assert expected_cwe in found_cwes, (
                f"{fixture_name}: expected CWE {expected_cwe} not found. "
                f"Found: {found_cwes}"
            )

    @pytest.mark.parametrize("fixture_name,expectations", EXPECTED.items())
    def test_expected_rule_patterns(self, engine: ScanEngine, fixture_name: str, expectations: dict):
        path = str(FIXTURES_DIR / fixture_name)
        if not Path(path).exists():
            pytest.skip(f"Fixture not found: {fixture_name}")

        result = engine.scan_file(path)
        all_rules = " ".join(f.rule_id for f in result.all_findings)
        all_content = " ".join(f.line_content for f in result.all_findings)
        combined = (all_rules + " " + all_content).lower()

        for pattern in expectations["expected_rules"]:
            assert pattern.lower() in combined, (
                f"{fixture_name}: expected rule pattern '{pattern}' not matched"
            )


class TestPrecision:
    """Verify the scanner doesn't produce excessive false positives."""

    def test_clean_python(self, engine: ScanEngine, tmp_path):
        """Clean Python code should produce zero or near-zero findings."""
        code = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"

class Calculator:
    def multiply(self, x: float, y: float) -> float:
        return x * y
'''
        path = str(tmp_path / "clean.py")
        Path(path).write_text(code)
        result = engine.scan_file(path)
        assert result.total_findings <= 1, f"Clean code should have ≤1 findings, got {result.total_findings}"

    def test_clean_javascript(self, engine: ScanEngine, tmp_path):
        code = '''
function add(a, b) {
    return a + b;
}

const greet = (name) => `Hello, ${name}!`;

class Calculator {
    multiply(x, y) {
        return x * y;
    }
}
'''
        path = str(tmp_path / "clean.js")
        Path(path).write_text(code)
        result = engine.scan_file(path)
        assert result.total_findings <= 2, f"Clean JS should have ≤2 findings, got {result.total_findings}"

    def test_safe_parameterized_sql(self, engine: ScanEngine, tmp_path):
        """Parameterized queries should NOT be flagged."""
        code = '''
import sqlite3
conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("INSERT INTO logs (msg) VALUES (%s)", (message,))
'''
        path = str(tmp_path / "safe_sql.py")
        Path(path).write_text(code)
        result = engine.scan_file(path)
        sql_findings = [f for f in result.all_findings if "sql" in f.rule_id.lower() and f.severity == Severity.ERROR]
        assert len(sql_findings) == 0, "Parameterized SQL should not be flagged as injection"

    def test_comment_lines_not_flagged(self, engine: ScanEngine, tmp_path):
        code = '''
# password = "this is just a comment"
# eval(data) — this is documentation
# os.system("rm -rf /") — example of what NOT to do
'''
        path = str(tmp_path / "comments.py")
        Path(path).write_text(code)
        result = engine.scan_file(path)
        assert result.total_findings == 0, "Comment lines should not produce findings"


class TestProjectScan:
    """Test scanning the entire fixtures directory."""

    def test_scan_all_fixtures(self, engine: ScanEngine):
        result = engine.scan_project(str(FIXTURES_DIR))
        assert result.total_files >= 6
        assert result.total_findings >= 30, f"Expected 30+ findings across all fixtures, got {result.total_findings}"
        assert result.grade.value in ("D", "F"), f"Vulnerable fixtures should get D or F, got {result.grade.value}"

    def test_severity_distribution(self, engine: ScanEngine):
        result = engine.scan_project(str(FIXTURES_DIR))
        assert result.error_count >= 10, "Expected many critical findings"
        assert result.warning_count >= 5, "Expected several warning findings"


class TestDockerfileScan:
    def test_dockerfile_findings(self, engine: ScanEngine):
        path = str(FIXTURES_DIR / "Dockerfile.vulnerable")
        if not Path(path).exists():
            pytest.skip("Dockerfile fixture not found")
        result = engine.scan_file(path)
        assert result.total_findings >= 3
        rules = [f.rule_id for f in result.all_findings]
        assert any("latest" in r or "image" in r for r in rules) or \
               any("secret" in r or "env" in r.lower() for r in rules) or \
               any("curl" in r for r in rules), f"Expected Dockerfile rules, got: {rules}"
