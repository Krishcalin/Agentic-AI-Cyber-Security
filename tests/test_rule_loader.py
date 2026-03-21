"""Tests for YAML rule loader."""

from core.models import Severity
from core.rule_loader import RuleLoader


class TestRuleLoader:
    def test_load_all_rules(self, loader: RuleLoader):
        rules = loader.load_all()
        assert len(rules) > 0

    def test_python_rules_exist(self, loader: RuleLoader):
        rules = loader.load_all()
        python_rules = [r for r in rules if "python" in r.languages]
        assert len(python_rules) >= 40, f"Expected 40+ Python rules, got {len(python_rules)}"

    def test_javascript_rules_exist(self, loader: RuleLoader):
        rules = loader.load_all()
        js_rules = [r for r in rules if "javascript" in r.languages]
        assert len(js_rules) >= 30, f"Expected 30+ JS rules, got {len(js_rules)}"

    def test_common_rules_exist(self, loader: RuleLoader):
        rules = loader.load_all()
        common_rules = [r for r in rules if "any" in r.languages]
        assert len(common_rules) >= 5

    def test_rules_have_ids(self, loader: RuleLoader):
        rules = loader.load_all()
        for rule in rules:
            assert rule.id, f"Rule missing id"
            assert "." in rule.id, f"Rule ID should be dotted: {rule.id}"

    def test_rules_have_patterns(self, loader: RuleLoader):
        rules = loader.load_all()
        for rule in rules:
            assert len(rule.patterns) > 0, f"Rule {rule.id} has no patterns"

    def test_rules_have_valid_severity(self, loader: RuleLoader):
        rules = loader.load_all()
        for rule in rules:
            assert rule.severity in Severity, f"Rule {rule.id} has invalid severity: {rule.severity}"

    def test_rules_have_messages(self, loader: RuleLoader):
        rules = loader.load_all()
        for rule in rules:
            assert rule.message, f"Rule {rule.id} has empty message"

    def test_load_for_language(self, loader: RuleLoader):
        loader.load_all()
        python_rules = loader.load_for_language("python")
        assert len(python_rules) > 0
        for rule in python_rules:
            assert "python" in rule.languages or "any" in rule.languages

    def test_cwe_format(self, loader: RuleLoader):
        rules = loader.load_all()
        for rule in rules:
            if rule.cwe:
                assert rule.cwe.startswith("CWE-"), f"Rule {rule.id} CWE should start with CWE-: {rule.cwe}"
