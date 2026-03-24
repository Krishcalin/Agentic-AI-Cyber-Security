"""Tests for pattern matching engine."""

from core.models import Severity
from core.pattern_matcher import PatternMatcher


class TestPatternMatcher:
    def test_load_rules(self, matcher: PatternMatcher):
        assert len(matcher.rules) > 0

    def test_scan_python_fixture(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        assert result.language == "python"
        assert result.finding_count > 0
        assert result.lines_scanned > 0

    def test_detects_sql_injection(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        sql_findings = [f for f in result.findings if "sql" in f.rule_id.lower() or "CWE-89" in f.cwe]
        assert len(sql_findings) >= 1, "Should detect SQL injection"

    def test_detects_command_injection(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        cmd_findings = [f for f in result.findings if "command" in f.rule_id.lower() or "CWE-78" in f.cwe]
        assert len(cmd_findings) >= 1, "Should detect command injection"

    def test_detects_eval(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        eval_findings = [f for f in result.findings if "eval" in f.rule_id.lower()]
        assert len(eval_findings) >= 1, "Should detect eval usage"

    def test_detects_pickle(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        pickle_findings = [f for f in result.findings if "pickle" in f.rule_id.lower() or "deserialize" in f.rule_id.lower()]
        assert len(pickle_findings) >= 1, "Should detect pickle deserialization"

    def test_detects_weak_hash(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        hash_findings = [f for f in result.findings if "hash" in f.rule_id.lower() or "md5" in f.rule_id.lower()]
        assert len(hash_findings) >= 1, "Should detect weak hashing"

    def test_detects_hardcoded_password(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        cred_findings = [f for f in result.findings if "secret" in f.rule_id.lower() or "password" in f.rule_id.lower() or "CWE-798" in f.cwe]
        assert len(cred_findings) >= 1, "Should detect hardcoded credentials"

    def test_detects_ssl_disabled(self, matcher: PatternMatcher, python_fixture: str):
        result = matcher.scan_file(python_fixture)
        ssl_findings = [f for f in result.findings if "ssl" in f.rule_id.lower() or "verify" in f.rule_id.lower() or "CWE-295" in f.cwe]
        assert len(ssl_findings) >= 1, "Should detect SSL verification disabled"

    def test_scan_javascript_fixture(self, matcher: PatternMatcher, javascript_fixture: str):
        result = matcher.scan_file(javascript_fixture)
        assert result.language == "javascript"
        assert result.finding_count > 0

    def test_js_detects_xss(self, matcher: PatternMatcher, javascript_fixture: str):
        result = matcher.scan_file(javascript_fixture)
        xss_findings = [f for f in result.findings if "xss" in f.rule_id.lower() or "innerHTML" in f.rule_id.lower() or "CWE-79" in f.cwe]
        assert len(xss_findings) >= 1, "Should detect XSS"

    def test_js_detects_eval(self, matcher: PatternMatcher, javascript_fixture: str):
        result = matcher.scan_file(javascript_fixture)
        eval_findings = [f for f in result.findings if "eval" in f.rule_id.lower()]
        assert len(eval_findings) >= 1, "Should detect eval"

    def test_js_detects_command_injection(self, matcher: PatternMatcher, javascript_fixture: str):
        result = matcher.scan_file(javascript_fixture)
        cmd_findings = [f for f in result.findings if "command" in f.rule_id.lower() or "exec" in f.rule_id.lower()]
        assert len(cmd_findings) >= 1, "Should detect command injection"

    def test_skips_comment_lines(self, matcher: PatternMatcher):
        """Comments should not trigger rules."""
        import tempfile, os
        code = "# password = 'test123'\n# eval(data)\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            tmp = f.name
        try:
            result = matcher.scan_file(tmp)
            assert result.finding_count == 0, "Comments should not trigger findings"
        finally:
            os.unlink(tmp)

    def test_nonexistent_file(self, matcher: PatternMatcher):
        result = matcher.scan_file("/nonexistent/file.py")
        assert result.error != ""
        assert result.finding_count == 0


class TestScanDirectory:
    def test_scan_fixtures(self, matcher: PatternMatcher):
        import os
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        results = matcher.scan_directory(fixtures_dir)
        assert len(results) >= 2  # Python + JavaScript fixtures
        total_findings = sum(r.finding_count for r in results)
        assert total_findings > 10, "Should find many issues in vulnerable fixtures"
