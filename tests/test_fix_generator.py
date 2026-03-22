"""Tests for auto-fix generator."""

from __future__ import annotations

from core.fix_generator import Fix, FixGenerator, FixResult, FixTemplates
from core.models import Confidence, Finding, Severity


def make_finding(rule_id: str = "test", cwe: str = "", line: str = "",
                 line_num: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id, message="test", severity=Severity.ERROR,
        file_path="test.py", line_number=line_num, line_content=line, cwe=cwe,
    )


class TestSQLInjectionFix:
    def test_fstring_to_parameterized(self):
        line = '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        finding = make_finding(rule_id="python.injection.sql", cwe="CWE-89", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert fix.has_fix
        assert "%s" in fix.fixed_line
        assert "user_id" in fix.fixed_line
        assert "f\"" not in fix.fixed_line

    def test_percent_to_parameterized(self):
        line = '    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        finding = make_finding(rule_id="python.injection.sql", cwe="CWE-89", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert fix.has_fix


class TestCommandInjectionFix:
    def test_os_system_to_subprocess(self):
        line = '    os.system(command)'
        finding = make_finding(rule_id="python.ast.os-system", cwe="CWE-78", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "subprocess.run" in fix.fixed_line
        assert "shell=False" in fix.fixed_line

    def test_os_popen_to_subprocess(self):
        line = '    result = os.popen(cmd)'
        finding = make_finding(rule_id="python.ast.os-popen", cwe="CWE-78", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "subprocess.run" in fix.fixed_line

    def test_subprocess_shell_true(self):
        line = '    subprocess.call(cmd, shell=True)'
        finding = make_finding(rule_id="python.ast.subprocess-shell", cwe="CWE-78", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "shell=False" in fix.fixed_line


class TestCodeInjectionFix:
    def test_eval_removed(self):
        line = '    result = eval(user_input)'
        finding = make_finding(rule_id="python.ast.eval", cwe="CWE-95", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "SECURITY" in fix.fixed_line
        assert "ast.literal_eval" in fix.explanation

    def test_exec_removed(self):
        line = '    exec(dynamic_code)'
        finding = make_finding(rule_id="python.ast.exec", cwe="CWE-95", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "SECURITY" in fix.fixed_line


class TestDeserializationFix:
    def test_pickle_to_json(self):
        line = '    data = pickle.loads(raw_bytes)'
        finding = make_finding(rule_id="python.ast.pickle-loads", cwe="CWE-502", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "json.loads" in fix.fixed_line

    def test_yaml_to_safe_load(self):
        line = '    data = yaml.load(text)'
        finding = make_finding(rule_id="python.ast.yaml-load", cwe="CWE-502", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "safe_load" in fix.fixed_line

    def test_yaml_safe_already(self):
        line = '    data = yaml.safe_load(text)'
        finding = make_finding(rule_id="python.ast.yaml-load", cwe="CWE-502", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is None  # Already safe


class TestCryptoFix:
    def test_md5_to_sha256(self):
        line = '    h = hashlib.md5(data)'
        finding = make_finding(rule_id="python.crypto.weak-hash-md5", cwe="CWE-328", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "sha256" in fix.fixed_line

    def test_sha1_to_sha256(self):
        line = '    h = hashlib.sha1(data)'
        finding = make_finding(rule_id="python.crypto.weak-hash-sha1", cwe="CWE-328", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "sha256" in fix.fixed_line

    def test_js_md5_to_sha256(self):
        line = "    const hash = crypto.createHash('md5')"
        finding = make_finding(rule_id="javascript.crypto.weak-hash", cwe="CWE-328", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "'sha256'" in fix.fixed_line

    def test_ecb_to_gcm(self):
        line = '    cipher = AES.new(key, AES.MODE_ECB)'
        finding = make_finding(rule_id="python.crypto.ecb-mode", cwe="CWE-327", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "MODE_GCM" in fix.fixed_line


class TestSSLFix:
    def test_verify_false_to_true(self):
        line = '    r = requests.get(url, verify=False)'
        finding = make_finding(rule_id="python.network.ssl-verify", cwe="CWE-295", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "verify=True" in fix.fixed_line

    def test_node_tls_reject(self):
        line = '    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"'
        finding = make_finding(rule_id="javascript.network.tls-reject", cwe="CWE-295", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert '"1"' in fix.fixed_line


class TestHardcodedSecretFix:
    def test_python_secret_to_env(self):
        line = '    password = "SuperSecret123"'
        finding = make_finding(rule_id="python.secrets.hardcoded-password", cwe="CWE-798", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "os.environ" in fix.fixed_line
        assert "PASSWORD" in fix.fixed_line

    def test_js_secret_to_env(self):
        line = '    const apiKey = "sk-1234567890abcdef"'
        finding = make_finding(rule_id="javascript.secrets.hardcoded", cwe="CWE-798", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "process.env" in fix.fixed_line


class TestXSSFix:
    def test_innerhtml_to_textcontent(self):
        line = '    element.innerHTML = userInput;'
        finding = make_finding(rule_id="javascript.xss.innerhtml", cwe="CWE-79", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "textContent" in fix.fixed_line

    def test_document_write_removed(self):
        line = '    document.write(data);'
        finding = make_finding(rule_id="javascript.xss.document-write", cwe="CWE-79", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "SECURITY" in fix.fixed_line


class TestMiscFixes:
    def test_debug_mode(self):
        line = '    DEBUG = True'
        finding = make_finding(rule_id="python.django.debug", cwe="CWE-489", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "False" in fix.fixed_line

    def test_tempfile_mktemp(self):
        line = '    tmp = tempfile.mktemp()'
        finding = make_finding(rule_id="python.path.tempfile", cwe="CWE-377", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "mkstemp" in fix.fixed_line

    def test_chmod_777(self):
        line = '    os.chmod(path, 0o777)'
        finding = make_finding(rule_id="python.path.chmod", cwe="CWE-732", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "0o755" in fix.fixed_line

    def test_cors_wildcard(self):
        line = '''    res.setHeader('Access-Control-Allow-Origin', '*')'''
        finding = make_finding(rule_id="javascript.network.cors", cwe="CWE-942", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "yourdomain" in fix.fixed_line

    def test_assert_to_raise(self):
        line = '    assert user.is_admin, "Unauthorized"'
        finding = make_finding(rule_id="python.ast.security-assert", cwe="CWE-617", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert "if not" in fix.fixed_line
        assert "raise" in fix.fixed_line


class TestFixGenerator:
    def test_generate_fixes(self):
        findings = [
            make_finding(rule_id="python.crypto.weak-hash-md5", cwe="CWE-328",
                        line='    h = hashlib.md5(data)'),
            make_finding(rule_id="python.network.ssl-verify", cwe="CWE-295",
                        line='    r = requests.get(url, verify=False)'),
        ]
        gen = FixGenerator()
        result = gen.generate_fixes(findings)
        assert result.fix_count >= 2

    def test_unfixable_tracked(self):
        findings = [
            make_finding(rule_id="unknown.rule", cwe="", line="something obscure"),
        ]
        gen = FixGenerator()
        result = gen.generate_fixes(findings)
        assert result.unfixable_count == 1

    def test_supported_cwes(self):
        gen = FixGenerator()
        cwes = gen.get_supported_cwes()
        assert "CWE-89" in cwes
        assert "CWE-78" in cwes
        assert "CWE-79" in cwes
        assert len(cwes) >= 15

    def test_generate_diff(self):
        findings = [
            make_finding(rule_id="python.crypto.weak-hash-md5", cwe="CWE-328",
                        line='    h = hashlib.md5(data)', line_num=10),
        ]
        gen = FixGenerator()
        result = gen.generate_fixes(findings)
        diff = result.generate_diff("test.py")
        assert "---" in diff
        assert "+++" in diff
        assert "sha256" in diff


class TestFixProperties:
    def test_fix_to_dict(self):
        line = '    h = hashlib.md5(data)'
        finding = make_finding(rule_id="test", cwe="CWE-328", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        d = fix.to_dict()
        assert "original" in d
        assert "fixed" in d
        assert "explanation" in d

    def test_requires_import(self):
        line = '    os.system(command)'
        finding = make_finding(rule_id="python.ast.os-system", cwe="CWE-78", line=line)
        fix = FixTemplates.fix_finding(finding)
        assert fix is not None
        assert fix.requires_import == "import subprocess"
