"""Tests for taint tracking engine."""

from core.taint_tracker import TaintTracker
from core.models import Severity


def tracker():
    return TaintTracker()


class TestTaintSources:
    def test_flask_request_args(self):
        code = '''
from flask import request
user_input = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
'''
        findings = tracker().analyze_source(code)
        assert len(findings) >= 1
        assert any("sql_injection" in f.rule_id for f in findings)

    def test_flask_request_form(self):
        code = '''
from flask import request
name = request.form["name"]
os.system(f"echo {name}")
'''
        findings = tracker().analyze_source(code)
        assert any("command_injection" in f.rule_id for f in findings)

    def test_input_builtin(self):
        code = '''
user_data = input("Enter command: ")
eval(user_data)
'''
        findings = tracker().analyze_source(code)
        assert any("code_injection" in f.rule_id for f in findings)

    def test_sys_argv(self):
        code = '''
import sys
filename = sys.argv[1]
open(filename)
'''
        findings = tracker().analyze_source(code)
        assert any("path_traversal" in f.rule_id for f in findings)

    def test_os_environ(self):
        code = '''
import os
cmd = os.environ["USER_CMD"]
os.system(cmd)
'''
        findings = tracker().analyze_source(code)
        assert any("command_injection" in f.rule_id for f in findings)


class TestTaintPropagation:
    def test_taint_through_assignment(self):
        code = '''
from flask import request
raw = request.args.get("q")
cleaned = raw.strip()
cursor.execute(f"SELECT * FROM items WHERE name = {cleaned}")
'''
        findings = tracker().analyze_source(code)
        assert any("sql_injection" in f.rule_id for f in findings)

    def test_taint_through_string_concat(self):
        code = '''
from flask import request
user_input = request.args.get("id")
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)
'''
        findings = tracker().analyze_source(code)
        assert any("sql_injection" in f.rule_id for f in findings)

    def test_taint_through_fstring(self):
        code = '''
from flask import request
name = request.form.get("name")
cmd = f"echo {name}"
os.system(cmd)
'''
        findings = tracker().analyze_source(code)
        assert any("command_injection" in f.rule_id for f in findings)


class TestCleanDataNotFlagged:
    def test_literal_string_not_tainted(self):
        code = '''
query = "SELECT * FROM users WHERE active = true"
cursor.execute(query)
'''
        findings = tracker().analyze_source(code)
        taint_findings = [f for f in findings if "taint" in f.rule_id]
        assert len(taint_findings) == 0

    def test_constant_not_tainted(self):
        code = '''
filename = "/etc/config.yaml"
open(filename)
'''
        findings = tracker().analyze_source(code)
        taint_findings = [f for f in findings if "taint" in f.rule_id]
        assert len(taint_findings) == 0


class TestSinkDetection:
    def test_sql_sink(self):
        code = '''
user_input = input("SQL: ")
cursor.execute(user_input)
'''
        findings = tracker().analyze_source(code)
        assert any("sql_injection" in f.rule_id for f in findings)

    def test_command_sink(self):
        code = '''
cmd = input("cmd: ")
os.system(cmd)
'''
        findings = tracker().analyze_source(code)
        assert any("command_injection" in f.rule_id for f in findings)

    def test_eval_sink(self):
        code = '''
expr = input("expression: ")
eval(expr)
'''
        findings = tracker().analyze_source(code)
        assert any("code_injection" in f.rule_id for f in findings)

    def test_open_sink(self):
        code = '''
filename = input("file: ")
open(filename)
'''
        findings = tracker().analyze_source(code)
        assert any("path_traversal" in f.rule_id for f in findings)


class TestFindingMetadata:
    def test_finding_has_source_info(self):
        code = '''
from flask import request
user_id = request.args.get("id")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = tracker().analyze_source(code)
        taint_findings = [f for f in findings if "taint" in f.rule_id]
        assert len(taint_findings) >= 1
        f = taint_findings[0]
        assert f.cwe != ""
        assert f.category == "taint"
        assert "source" in f.metadata

    def test_finding_severity_is_error(self):
        code = '''
data = input()
eval(data)
'''
        findings = tracker().analyze_source(code)
        taint_findings = [f for f in findings if "taint" in f.rule_id]
        for f in taint_findings:
            assert f.severity == Severity.ERROR


class TestFileAnalysis:
    def test_analyze_fixture(self, python_fixture: str):
        result = tracker().analyze_file(python_fixture)
        # Fixture may not have Flask imports, so taint findings depend on sources present
        assert result.language == "python"
        assert result.lines_scanned > 0

    def test_syntax_error(self):
        findings = tracker().analyze_source("def broken(\n")
        assert findings == []

    def test_nonexistent_file(self):
        result = tracker().analyze_file("/nonexistent.py")
        assert result.error != ""
