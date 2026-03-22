"""Tests for LLM-powered semantic code reviewer."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from core.semantic_reviewer import (
    ClaudeProvider,
    MockProvider,
    OpenAIProvider,
    ReviewResult,
    SemanticReviewer,
    detect_project_type,
)


# ── Project Type Detection ─────────────────────────────────────────────────


class TestProjectTypeDetection:
    def test_web_api_flask(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/users')
def get_users():
    return jsonify(users)
"""
        assert detect_project_type(code) == "web-api"

    def test_web_api_django(self):
        code = """
from django.http import HttpResponse
from django.views import View

class UserView(View):
    def get(self, request):
        return HttpResponse("OK")
"""
        assert detect_project_type(code) == "web-api"

    def test_cli_tool(self):
        code = """
import argparse
import subprocess
parser = argparse.ArgumentParser()
parser.add_argument('--input', required=True)
args = parser.parse_args()
subprocess.run(['grep', args.input, '/var/log/syslog'])
"""
        assert detect_project_type(code) == "cli-tool"

    def test_data_pipeline(self):
        code = """
import pandas as pd
import numpy as np
df = pd.read_csv('data.csv')
df = df.transform(lambda x: x.fillna(0))
df.to_parquet('output.parquet')
"""
        assert detect_project_type(code) == "data-pipeline"

    def test_ml_model(self):
        code = """
import torch
from torch import nn
model = nn.Sequential(nn.Linear(10, 5))
optimizer = torch.optim.Adam(model.parameters())
for epoch in range(100):
    loss = criterion(model(x), y)
"""
        assert detect_project_type(code) == "ml-model"

    def test_security_tool(self):
        code = """
def scan_for_vulnerabilities(target):
    cve_list = check_cve_database(target)
    exploits = find_exploits(cve_list)
    return exploits
"""
        assert detect_project_type(code) == "security-tool"

    def test_general_fallback(self):
        code = "x = 1 + 2\nprint(x)\n"
        assert detect_project_type(code) == "general"


# ── Mock Provider ──────────────────────────────────────────────────────────


class TestMockProvider:
    def test_default_response(self):
        provider = MockProvider()
        text, tokens = provider.complete("system", "user")
        data = json.loads(text)
        assert "summary" in data
        assert "findings" in data
        assert tokens > 0

    def test_custom_response(self):
        custom = json.dumps({
            "summary": "Code is secure",
            "intent_analysis": "A helper function",
            "findings": [
                {
                    "title": "Weak hash",
                    "description": "MD5 used",
                    "severity": "medium",
                    "line_start": 5,
                    "cwe": "CWE-328",
                    "fix_suggestion": "Use SHA-256",
                    "confidence": "high",
                    "category": "crypto",
                }
            ],
        })
        provider = MockProvider(response=custom)
        text, tokens = provider.complete("system", "user")
        data = json.loads(text)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cwe"] == "CWE-328"


# ── Semantic Reviewer (with MockProvider) ──────────────────────────────────


class TestSemanticReviewer:
    def test_mock_review_code(self):
        reviewer = SemanticReviewer(provider="mock")
        result = reviewer.review_code("x = eval(input())", "python")
        assert isinstance(result, ReviewResult)
        assert result.provider == "mock"
        assert result.review_time_ms >= 0

    def test_mock_review_file(self):
        code = 'password = "secret123"\nos.system(cmd)\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            reviewer = SemanticReviewer(provider="mock")
            result = reviewer.review_file(path)
            assert result.project_type != ""
            assert result.error == ""
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        reviewer = SemanticReviewer(provider="mock")
        result = reviewer.review_file("/nonexistent.py")
        assert result.error != ""

    def test_project_type_detected(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route('/api')
def api():
    user_input = request.args.get('q')
    return eval(user_input)
"""
        reviewer = SemanticReviewer(provider="mock")
        result = reviewer.review_code(code, "python")
        assert result.project_type == "web-api"

    def test_with_findings_from_mock(self):
        response = json.dumps({
            "summary": "Critical SQL injection found",
            "intent_analysis": "Database query handler",
            "findings": [
                {
                    "title": "SQL Injection via f-string",
                    "description": "User input flows directly into SQL query",
                    "severity": "critical",
                    "line_start": 5,
                    "line_end": 5,
                    "cwe": "CWE-89",
                    "fix_suggestion": "Use parameterized queries",
                    "confidence": "high",
                    "category": "injection",
                },
                {
                    "title": "Hardcoded database password",
                    "description": "Password visible in source code",
                    "severity": "high",
                    "line_start": 2,
                    "cwe": "CWE-798",
                    "fix_suggestion": "Use environment variables",
                    "confidence": "high",
                    "category": "secrets",
                },
            ],
        })

        reviewer = SemanticReviewer(provider="mock")
        reviewer._provider = MockProvider(response=response)

        result = reviewer.review_code("db_pass = 'secret'\ncursor.execute(f'SELECT * FROM {table}')", "python")
        assert result.finding_count == 2
        assert result.summary == "Critical SQL injection found"
        assert any(f.cwe == "CWE-89" for f in result.findings)
        assert any(f.severity == "critical" for f in result.findings)

    def test_finding_to_finding_conversion(self):
        response = json.dumps({
            "summary": "Issue found",
            "intent_analysis": "",
            "findings": [
                {
                    "title": "Eval usage",
                    "description": "Dangerous",
                    "severity": "high",
                    "line_start": 1,
                    "cwe": "CWE-95",
                    "fix_suggestion": "",
                    "confidence": "high",
                    "category": "injection",
                },
            ],
        })
        reviewer = SemanticReviewer(provider="mock")
        reviewer._provider = MockProvider(response=response)

        result = reviewer.review_code("eval(x)", "python")
        assert result.finding_count == 1

        finding = result.findings[0].to_finding("test.py", ["eval(x)"])
        assert finding.rule_id.startswith("semantic.")
        assert finding.category == "semantic"
        assert finding.cwe == "CWE-95"

    def test_code_truncation(self):
        long_code = "\n".join([f"line_{i} = {i}" for i in range(1000)])
        reviewer = SemanticReviewer(provider="mock", max_lines=100)
        result = reviewer.review_code(long_code, "python")
        # Should not error even with truncation
        assert result.error == ""

    def test_response_parsing_with_markdown_fences(self):
        response = '```json\n{"summary": "test", "intent_analysis": "", "findings": []}\n```'
        reviewer = SemanticReviewer(provider="mock")
        reviewer._provider = MockProvider(response=response)
        result = reviewer.review_code("x = 1", "python")
        assert result.summary == "test"
        assert result.error == ""


# ── Provider Initialization ────────────────────────────────────────────────


class TestProviderInit:
    def test_mock_always_works(self):
        reviewer = SemanticReviewer(provider="mock")
        assert reviewer.provider_name == "mock"

    def test_claude_falls_back_to_mock(self):
        """Without ANTHROPIC_API_KEY, Claude should fall back to mock."""
        # Temporarily clear the env var
        original = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            reviewer = SemanticReviewer(provider="claude")
            # Should fall back to mock without crashing
            result = reviewer.review_code("x = 1", "python")
            assert result.error == "" or "mock" in result.summary.lower() or result.finding_count == 0
        finally:
            if original:
                os.environ["ANTHROPIC_API_KEY"] = original

    def test_openai_falls_back_to_mock(self):
        original = os.environ.pop("OPENAI_API_KEY", None)
        try:
            reviewer = SemanticReviewer(provider="openai")
            result = reviewer.review_code("x = 1", "python")
            assert result.error == "" or result.finding_count == 0
        finally:
            if original:
                os.environ["OPENAI_API_KEY"] = original

    def test_unknown_provider_uses_mock(self):
        reviewer = SemanticReviewer(provider="nonexistent")
        result = reviewer.review_code("x = 1", "python")
        assert result.error == "" or result.finding_count == 0


# ── ReviewResult Properties ────────────────────────────────────────────────


class TestReviewResult:
    def test_empty_result(self):
        r = ReviewResult()
        assert r.finding_count == 0
        assert r.error == ""

    def test_with_findings(self):
        from core.semantic_reviewer import ReviewFinding
        r = ReviewResult(findings=[
            ReviewFinding(title="test", description="desc", severity="high"),
            ReviewFinding(title="test2", description="desc2", severity="medium"),
        ])
        assert r.finding_count == 2
