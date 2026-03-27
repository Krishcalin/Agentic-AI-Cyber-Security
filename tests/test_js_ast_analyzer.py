"""Tests for JavaScript/TypeScript AST analyzer."""

from __future__ import annotations

import pytest

from core.js_ast_analyzer import JSASTAnalyzer


@pytest.fixture
def analyzer():
    return JSASTAnalyzer()


class TestDangerousCalls:
    def test_eval_with_variable(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source('const x = eval(userInput);')
        assert any("eval" in f.rule_id for f in findings)

    def test_eval_with_literal_not_flagged(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source('const x = eval("2+2");')
        assert not any("eval-dynamic" in f.rule_id for f in findings)

    def test_new_function_dynamic(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source('const fn = new Function(body);')
        assert any("new-function" in f.rule_id for f in findings)

    def test_exec_template_literal(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source('exec(`ls ${dir}`);')
        assert any("command" in f.rule_id for f in findings)

    def test_vm_context(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source('vm.runInNewContext(code, sandbox);')
        assert any("vm" in f.rule_id for f in findings)

    def test_settimeout_string(self, analyzer: JSASTAnalyzer):
        findings = analyzer.analyze_source("setTimeout('alert(1)', 1000);")
        assert any("settimeout" in f.rule_id for f in findings)


class TestSQLInjection:
    def test_template_literal_in_query(self, analyzer: JSASTAnalyzer):
        code = 'db.query(`SELECT * FROM users WHERE id = ${userId}`);'
        findings = analyzer.analyze_source(code)
        assert any("sql" in f.rule_id for f in findings)

    def test_safe_parameterized_not_flagged(self, analyzer: JSASTAnalyzer):
        code = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);'
        findings = analyzer.analyze_source(code)
        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) == 0

    def test_concat_in_query(self, analyzer: JSASTAnalyzer):
        code = 'db.query("SELECT * FROM users WHERE name = \'" + name);'
        findings = analyzer.analyze_source(code)
        assert any("sql" in f.rule_id for f in findings)


class TestXSS:
    def test_innerhtml_dynamic(self, analyzer: JSASTAnalyzer):
        code = 'element.innerHTML = userContent;'
        findings = analyzer.analyze_source(code)
        assert any("innerhtml" in f.rule_id for f in findings)

    def test_innerhtml_literal_not_flagged(self, analyzer: JSASTAnalyzer):
        code = 'element.innerHTML = "<p>Hello</p>";'
        findings = analyzer.analyze_source(code)
        assert not any("innerhtml-dynamic" in f.rule_id for f in findings)

    def test_document_write(self, analyzer: JSASTAnalyzer):
        code = 'document.write(content);'
        findings = analyzer.analyze_source(code)
        assert any("document-write" in f.rule_id for f in findings)

    def test_dangerously_set(self, analyzer: JSASTAnalyzer):
        code = '<div dangerouslySetInnerHTML={{ __html: data }} />'
        findings = analyzer.analyze_source(code)
        assert any("dangerously" in f.rule_id for f in findings)


class TestCredentials:
    def test_hardcoded_password(self, analyzer: JSASTAnalyzer):
        code = 'const password = "SuperSecret123!";'
        findings = analyzer.analyze_source(code)
        assert any("credential" in f.rule_id for f in findings)

    def test_hardcoded_api_key(self, analyzer: JSASTAnalyzer):
        code = 'const apiKey = "sk-1234567890abcdef";'
        findings = analyzer.analyze_source(code)
        assert any("credential" in f.rule_id for f in findings)

    def test_placeholder_not_flagged(self, analyzer: JSASTAnalyzer):
        code = 'const password = "change.me";'
        findings = analyzer.analyze_source(code)
        cred_findings = [f for f in findings if "credential" in f.rule_id]
        assert len(cred_findings) == 0


class TestCrypto:
    def test_md5_hash(self, analyzer: JSASTAnalyzer):
        code = "const hash = crypto.createHash('md5').update(data).digest('hex');"
        findings = analyzer.analyze_source(code)
        assert any("weak-hash" in f.rule_id for f in findings)

    def test_sha256_not_flagged(self, analyzer: JSASTAnalyzer):
        code = "const hash = crypto.createHash('sha256').update(data).digest('hex');"
        findings = analyzer.analyze_source(code)
        assert not any("weak-hash" in f.rule_id for f in findings)


class TestTLS:
    def test_reject_unauthorized_false(self, analyzer: JSASTAnalyzer):
        code = 'const agent = new https.Agent({ rejectUnauthorized: false });'
        findings = analyzer.analyze_source(code)
        assert any("tls" in f.rule_id for f in findings)

    def test_env_tls_disabled(self, analyzer: JSASTAnalyzer):
        code = 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'
        findings = analyzer.analyze_source(code)
        assert any("tls" in f.rule_id for f in findings)


class TestCommentStripping:
    def test_comments_not_flagged(self, analyzer: JSASTAnalyzer):
        code = '// eval(userInput);\n/* document.write(x); */\nconst a = 1;'
        findings = analyzer.analyze_source(code)
        assert not any("eval" in f.rule_id for f in findings)
        assert not any("document-write" in f.rule_id for f in findings)


class TestTypeScript:
    def test_ts_type_annotations_dont_break(self, analyzer: JSASTAnalyzer):
        code = """
interface User {
  name: string;
  password: string;
}
const getUser = (id: number): Promise<User> => {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
};
"""
        findings = analyzer.analyze_source(code, language="typescript")
        # Should not produce false positives from type annotations
        sql_findings = [f for f in findings if "sql" in f.rule_id]
        assert len(sql_findings) == 0

    def test_ts_file_detection(self, analyzer: JSASTAnalyzer, tmp_path):
        ts_file = tmp_path / "app.ts"
        ts_file.write_text('const x = eval(data);')
        result = analyzer.analyze_file(str(ts_file))
        assert result.language == "typescript"
        assert len(result.findings) >= 1
