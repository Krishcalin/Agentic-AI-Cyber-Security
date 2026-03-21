"""Tests for Python AST analyzer."""

from core.ast_analyzer import ASTAnalyzer
from core.models import Severity


def analyzer():
    return ASTAnalyzer()


class TestDangerousCalls:
    def test_detects_eval(self):
        code = 'result = eval(user_input)\n'
        result = analyzer().analyze_source(code)
        assert any("eval" in f.rule_id for f in result.findings)

    def test_detects_exec(self):
        code = 'exec(dynamic_code)\n'
        result = analyzer().analyze_source(code)
        assert any("exec" in f.rule_id for f in result.findings)

    def test_detects_os_system(self):
        code = 'import os\nos.system(command)\n'
        result = analyzer().analyze_source(code)
        assert any("os-system" in f.rule_id for f in result.findings)

    def test_detects_os_popen(self):
        code = 'import os\nos.popen(cmd)\n'
        result = analyzer().analyze_source(code)
        assert any("os-popen" in f.rule_id for f in result.findings)

    def test_detects_pickle_loads(self):
        code = 'import pickle\ndata = pickle.loads(raw)\n'
        result = analyzer().analyze_source(code)
        assert any("pickle" in f.rule_id for f in result.findings)

    def test_detects_pickle_load(self):
        code = 'import pickle\ndata = pickle.load(file_obj)\n'
        result = analyzer().analyze_source(code)
        assert any("pickle" in f.rule_id for f in result.findings)

    def test_detects_yaml_load_unsafe(self):
        code = 'import yaml\ndata = yaml.load(text)\n'
        result = analyzer().analyze_source(code)
        assert any("yaml" in f.rule_id for f in result.findings)

    def test_yaml_safe_loader_not_flagged(self):
        code = 'import yaml\ndata = yaml.load(text, Loader=yaml.SafeLoader)\n'
        result = analyzer().analyze_source(code)
        yaml_findings = [f for f in result.findings if "yaml" in f.rule_id]
        assert len(yaml_findings) == 0, "yaml.load with SafeLoader should not be flagged"

    def test_detects_md5(self):
        code = 'import hashlib\nh = hashlib.md5(data)\n'
        result = analyzer().analyze_source(code)
        assert any("md5" in f.rule_id for f in result.findings)

    def test_detects_sha1(self):
        code = 'import hashlib\nh = hashlib.sha1(data)\n'
        result = analyzer().analyze_source(code)
        assert any("sha1" in f.rule_id for f in result.findings)

    def test_detects_mktemp(self):
        code = 'import tempfile\ntmp = tempfile.mktemp()\n'
        result = analyzer().analyze_source(code)
        assert any("mktemp" in f.rule_id for f in result.findings)


class TestSubprocessShell:
    def test_subprocess_shell_true(self):
        code = 'import subprocess\nsubprocess.call(cmd, shell=True)\n'
        result = analyzer().analyze_source(code)
        assert any("subprocess-shell" in f.rule_id for f in result.findings)

    def test_subprocess_shell_false_ok(self):
        code = 'import subprocess\nsubprocess.call(["ls", "-la"], shell=False)\n'
        result = analyzer().analyze_source(code)
        shell_findings = [f for f in result.findings if "subprocess-shell" in f.rule_id]
        assert len(shell_findings) == 0

    def test_subprocess_shell_dynamic_cmd_is_error(self):
        code = 'import subprocess\nsubprocess.run(user_cmd, shell=True)\n'
        result = analyzer().analyze_source(code)
        shell_findings = [f for f in result.findings if "subprocess-shell" in f.rule_id]
        assert len(shell_findings) >= 1
        assert shell_findings[0].severity == Severity.ERROR


class TestSQLFormatting:
    def test_fstring_sql(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        result = analyzer().analyze_source(code)
        sql_findings = [f for f in result.findings if "sql" in f.rule_id.lower()]
        assert len(sql_findings) >= 1

    def test_format_sql(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n'
        result = analyzer().analyze_source(code)
        sql_findings = [f for f in result.findings if "sql" in f.rule_id.lower()]
        assert len(sql_findings) >= 1

    def test_percent_sql(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
        result = analyzer().analyze_source(code)
        sql_findings = [f for f in result.findings if "sql" in f.rule_id.lower()]
        assert len(sql_findings) >= 1

    def test_parameterized_not_flagged(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        result = analyzer().analyze_source(code)
        sql_findings = [f for f in result.findings if "sql-fstring" in f.rule_id or "sql-format" in f.rule_id or "sql-percent" in f.rule_id]
        assert len(sql_findings) == 0, "Parameterized queries should not be flagged"


class TestHardcodedCredentials:
    def test_hardcoded_password(self):
        code = 'password = "SuperSecret123"\n'
        result = analyzer().analyze_source(code)
        cred_findings = [f for f in result.findings if "hardcoded" in f.rule_id]
        assert len(cred_findings) >= 1

    def test_hardcoded_api_key(self):
        code = 'api_key = "sk-1234567890abcdefghijklmn"\n'
        result = analyzer().analyze_source(code)
        cred_findings = [f for f in result.findings if "hardcoded" in f.rule_id]
        assert len(cred_findings) >= 1

    def test_env_var_not_flagged(self):
        code = 'import os\npassword = os.getenv("PASSWORD")\n'
        result = analyzer().analyze_source(code)
        cred_findings = [f for f in result.findings if "hardcoded-credential" in f.rule_id]
        assert len(cred_findings) == 0


class TestSSLVerify:
    def test_verify_false(self):
        code = 'requests.get("https://example.com", verify=False)\n'
        result = analyzer().analyze_source(code)
        ssl_findings = [f for f in result.findings if "ssl" in f.rule_id]
        assert len(ssl_findings) >= 1

    def test_verify_true_ok(self):
        code = 'requests.get("https://example.com", verify=True)\n'
        result = analyzer().analyze_source(code)
        ssl_findings = [f for f in result.findings if "ssl-verify" in f.rule_id]
        assert len(ssl_findings) == 0


class TestFileAnalysis:
    def test_analyze_fixture(self, python_fixture: str):
        result = analyzer().analyze_file(python_fixture)
        assert result.finding_count > 0
        assert result.language == "python"

    def test_syntax_error_handled(self):
        code = 'def broken(\n'
        result = analyzer().analyze_source(code)
        assert "SyntaxError" in result.error

    def test_nonexistent_file(self):
        result = analyzer().analyze_file("/nonexistent.py")
        assert result.error != ""
