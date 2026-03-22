"""Validation tests for all security rule YAML files."""

from __future__ import annotations

import re

import pytest

from core.models import Severity
from core.rule_loader import RuleLoader


@pytest.fixture
def all_rules():
    loader = RuleLoader("rules")
    return loader.load_all()


class TestRuleCounts:
    def test_total_rules(self, all_rules):
        assert len(all_rules) >= 200, f"Expected 200+ total rules, got {len(all_rules)}"

    def test_python_rules(self, all_rules):
        count = sum(1 for r in all_rules if "python" in r.languages)
        assert count >= 40, f"Expected 40+ Python rules, got {count}"

    def test_javascript_rules(self, all_rules):
        count = sum(1 for r in all_rules if "javascript" in r.languages)
        assert count >= 30, f"Expected 30+ JS rules, got {count}"

    def test_java_rules(self, all_rules):
        count = sum(1 for r in all_rules if "java" in r.languages)
        assert count >= 20, f"Expected 20+ Java rules, got {count}"

    def test_go_rules(self, all_rules):
        count = sum(1 for r in all_rules if "go" in r.languages)
        assert count >= 15, f"Expected 15+ Go rules, got {count}"

    def test_php_rules(self, all_rules):
        count = sum(1 for r in all_rules if "php" in r.languages)
        assert count >= 15, f"Expected 15+ PHP rules, got {count}"

    def test_ruby_rules(self, all_rules):
        count = sum(1 for r in all_rules if "ruby" in r.languages)
        assert count >= 10, f"Expected 10+ Ruby rules, got {count}"

    def test_c_cpp_rules(self, all_rules):
        count = sum(1 for r in all_rules if "c" in r.languages or "cpp" in r.languages)
        assert count >= 15, f"Expected 15+ C/C++ rules, got {count}"

    def test_dockerfile_rules(self, all_rules):
        count = sum(1 for r in all_rules if "dockerfile" in r.languages)
        assert count >= 10, f"Expected 10+ Dockerfile rules, got {count}"

    def test_terraform_rules(self, all_rules):
        count = sum(1 for r in all_rules if "terraform" in r.languages)
        assert count >= 15, f"Expected 15+ Terraform rules, got {count}"

    def test_kubernetes_rules(self, all_rules):
        count = sum(1 for r in all_rules if "yaml" in r.languages or "kubernetes" in r.languages)
        assert count >= 15, f"Expected 15+ K8s rules, got {count}"

    def test_common_rules(self, all_rules):
        count = sum(1 for r in all_rules if "any" in r.languages)
        assert count >= 5, f"Expected 5+ common rules, got {count}"


class TestRuleValidity:
    def test_all_have_ids(self, all_rules):
        for r in all_rules:
            assert r.id, "Rule missing ID"
            assert "." in r.id, f"Rule ID should be dotted: {r.id}"

    def test_all_have_patterns(self, all_rules):
        for r in all_rules:
            assert len(r.patterns) > 0, f"Rule {r.id} has no patterns"

    def test_all_have_messages(self, all_rules):
        for r in all_rules:
            assert r.message, f"Rule {r.id} has empty message"

    def test_all_have_valid_severity(self, all_rules):
        for r in all_rules:
            assert r.severity in Severity, f"Rule {r.id} invalid severity: {r.severity}"

    def test_all_have_languages(self, all_rules):
        for r in all_rules:
            assert len(r.languages) > 0, f"Rule {r.id} has no languages"

    def test_patterns_compile(self, all_rules):
        """All regex patterns should compile without errors."""
        for r in all_rules:
            for pattern in r.patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"Rule {r.id} pattern fails to compile: {pattern} — {e}")

    def test_no_duplicate_ids(self, all_rules):
        ids = [r.id for r in all_rules]
        duplicates = [id for id in ids if ids.count(id) > 1]
        assert len(set(duplicates)) == 0, f"Duplicate rule IDs: {set(duplicates)}"

    def test_cwe_format(self, all_rules):
        for r in all_rules:
            if r.cwe:
                assert r.cwe.startswith("CWE-"), f"Rule {r.id}: CWE should start with CWE-: {r.cwe}"


class TestRuleCoverage:
    """Verify key vulnerability categories are covered."""

    EXPECTED_CATEGORIES = [
        "injection", "crypto", "secrets", "xss", "deserialize",
        "network", "path",
    ]

    def test_categories_covered(self, all_rules):
        categories = set()
        for r in all_rules:
            parts = r.id.split(".")
            if len(parts) >= 2:
                categories.add(parts[1])

        for cat in self.EXPECTED_CATEGORIES:
            assert cat in categories, f"Category '{cat}' not found in rules"

    def test_owasp_top10_covered(self, all_rules):
        """Key OWASP Top 10 CWEs should be present."""
        cwes = {r.cwe for r in all_rules if r.cwe}
        critical_cwes = ["CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-798", "CWE-295"]
        for cwe in critical_cwes:
            assert cwe in cwes, f"OWASP-critical {cwe} not covered by any rule"
