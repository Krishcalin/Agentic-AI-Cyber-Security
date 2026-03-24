"""Tests for P1, P2, P3 features: OWASP LLM mapper, HTML reports, policy profiles,
sandbox evaluator, secrets scanner, SBOM generator, new rules."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


class TestOWASPLLMMapper:
    def test_map_prompt_injection(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        mappings = mapper.map_finding({"category": "jailbreak"})
        assert any(m.entry_id == "LLM01" for m in mappings)

    def test_map_supply_chain(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        mappings = mapper.map_finding({"category": "malicious_package"})
        assert any(m.entry_id == "LLM03" for m in mappings)

    def test_map_excessive_agency(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        mappings = mapper.map_finding({"category": "tool_abuse"})
        assert any(m.entry_id == "LLM06" for m in mappings)

    def test_map_cost_harvesting(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        mappings = mapper.map_finding({"category": "cost_harvesting"})
        assert any(m.entry_id == "LLM10" for m in mappings)

    def test_batch_mapping(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        result = mapper.map_findings([
            {"category": "jailbreak"},
            {"category": "secrets"},
            {"category": "cost_harvesting"},
        ])
        assert result.mapped_findings == 3
        assert len(result.entries_covered) >= 2

    def test_compliance_report(self):
        from core.owasp_llm_mapper import OWASPLLMMapper
        mapper = OWASPLLMMapper()
        report = mapper.generate_compliance_report([
            {"category": "jailbreak"},
            {"category": "malicious_package"},
        ])
        assert len(report["entries"]) == 10
        assert "summary" in report
        assert report["summary"]["failing"] >= 2

    def test_all_10_entries_exist(self):
        from core.owasp_llm_mapper import OWASP_LLM_TOP10
        assert len(OWASP_LLM_TOP10) == 10
        for i in range(1, 11):
            assert f"LLM{i:02d}" in OWASP_LLM_TOP10


class TestSandboxEvaluator:
    def test_safe_sandbox(self):
        from core.sandbox_evaluator import SandboxEvaluator, SandboxConfig
        evaluator = SandboxEvaluator()
        config = SandboxConfig(
            network_enabled=False,
            shell_access=False,
            subprocess_allowed=False,
            memory_limit_mb=512,
            timeout_seconds=300,
            max_processes=10,
        )
        result = evaluator.evaluate(config)
        assert result.score >= 80
        assert result.grade in ("A", "B")

    def test_dangerous_sandbox(self):
        from core.sandbox_evaluator import SandboxEvaluator, SandboxConfig
        evaluator = SandboxEvaluator()
        config = SandboxConfig(
            root_filesystem_access=True,
            shell_access=True,
            runs_as_root=True,
            network_enabled=True,
            env_vars=["AWS_SECRET_ACCESS_KEY", "DATABASE_URL"],
        )
        result = evaluator.evaluate(config)
        assert result.score < 30
        assert result.grade == "F"
        assert result.critical_count >= 3

    def test_evaluate_from_dict(self):
        from core.sandbox_evaluator import SandboxEvaluator
        evaluator = SandboxEvaluator()
        result = evaluator.evaluate_from_dict({
            "shell_access": True,
            "runs_as_root": True,
        })
        assert result.finding_count > 0

    def test_credential_detection(self):
        from core.sandbox_evaluator import SandboxEvaluator, SandboxConfig
        evaluator = SandboxEvaluator()
        config = SandboxConfig(
            env_vars=["OPENAI_API_KEY", "STRIPE_SECRET", "HOME", "PATH"],
        )
        result = evaluator.evaluate(config)
        cred_findings = [f for f in result.findings if f.category == "credentials"]
        assert len(cred_findings) == 2  # OPENAI + STRIPE, not HOME/PATH


class TestSecretsScanner:
    def test_detect_aws_key(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        result = scanner.scan_content('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        assert not result.is_clean

    def test_detect_github_token(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        result = scanner.scan_content('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456"')
        assert any(s.secret_type == "github_token" for s in result.secrets_found)

    def test_detect_database_url(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        result = scanner.scan_content('DB = "postgres://user:secretpassword@host:5432/mydb"')
        assert not result.is_clean

    def test_detect_private_key(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        result = scanner.scan_content("-----BEGIN RSA PRIVATE KEY-----\nMIIEo...")
        assert any(s.secret_type == "ssh_private_key" for s in result.secrets_found)

    def test_skip_false_positive(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        result = scanner.scan_content('api_key = "your_api_key_here"')
        assert result.is_clean  # "your_api_key_here" is a placeholder

    def test_high_entropy_detection(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        # High-entropy random string
        result = scanner.scan_content('secret = "k8sJ2m4nP9qR3vX7bZ1cD5fG8hL0wY6"')
        assert not result.is_clean

    def test_redaction(self):
        from core.secrets_scanner import SecretsScanner
        result = SecretsScanner._redact("AKIAIOSFODNN7EXAMPLE")
        assert "AKIA" in result
        assert "OSFODNN7" not in result

    def test_pattern_count(self):
        from core.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        assert scanner.pattern_count >= 25


class TestSBOMGenerator:
    def test_generate_from_requirements(self):
        from core.sbom_generator import SBOMGenerator
        gen = SBOMGenerator()
        tmp_dir = tempfile.mkdtemp()
        req_file = Path(tmp_dir) / "requirements.txt"
        req_file.write_text("flask==2.3.0\nrequests==2.31.0\n")
        sbom = gen.generate_file(str(req_file))
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 2

    def test_purl_format(self):
        from core.sbom_generator import SBOMGenerator
        gen = SBOMGenerator()
        tmp_dir = tempfile.mkdtemp()
        req_file = Path(tmp_dir) / "requirements.txt"
        req_file.write_text("flask==2.3.0\n")
        sbom = gen.generate_file(str(req_file))
        assert sbom["components"][0]["purl"] == "pkg:pypi/flask@2.3.0"

    def test_generate_project(self):
        from core.sbom_generator import SBOMGenerator
        gen = SBOMGenerator()
        tmp_dir = tempfile.mkdtemp()
        Path(tmp_dir, "requirements.txt").write_text("flask==2.3.0\n")
        Path(tmp_dir, "package.json").write_text('{"dependencies":{"express":"^4.18.0"}}')
        sbom = gen.generate_project(tmp_dir)
        assert len(sbom["components"]) == 2

    def test_metadata_present(self):
        from core.sbom_generator import SBOMGenerator
        gen = SBOMGenerator()
        tmp_dir = tempfile.mkdtemp()
        Path(tmp_dir, "requirements.txt").write_text("flask==2.3.0\n")
        sbom = gen.generate_project(tmp_dir)
        assert "metadata" in sbom
        assert "serialNumber" in sbom


class TestNewRuleFiles:
    @pytest.fixture
    def rules_dir(self):
        return Path(__file__).parent.parent / "rules"

    def test_csharp_rules(self, rules_dir):
        import yaml
        data = yaml.safe_load((rules_dir / "csharp.yaml").read_text())
        assert len(data["rules"]) >= 28

    def test_yaml_security_rules(self, rules_dir):
        import yaml
        data = yaml.safe_load((rules_dir / "yaml_security.yaml").read_text())
        assert len(data["rules"]) >= 18

    def test_total_rules_over_440(self, rules_dir):
        import yaml
        total = 0
        for path in rules_dir.glob("*.yaml"):
            if path.parent.name == "rules":
                data = yaml.safe_load(path.read_text())
                if data and "rules" in data:
                    total += len(data["rules"])
        assert total >= 440, f"Expected 440+ rules, got {total}"


class TestPolicyProfiles:
    @pytest.fixture
    def policies_dir(self):
        return Path(__file__).parent.parent / "rules" / "policies"

    def test_strict_profile_loads(self, policies_dir):
        import yaml
        data = yaml.safe_load((policies_dir / "strict.yaml").read_text())
        assert data["name"] == "strict"
        assert data["default_decision"] == "deny"
        assert len(data["rules"]) >= 4

    def test_permissive_profile_loads(self, policies_dir):
        import yaml
        data = yaml.safe_load((policies_dir / "permissive.yaml").read_text())
        assert data["name"] == "permissive"
        assert data["default_decision"] == "allow"

    def test_enterprise_profile_loads(self, policies_dir):
        import yaml
        data = yaml.safe_load((policies_dir / "enterprise.yaml").read_text())
        assert data["name"] == "enterprise"
        assert data["default_decision"] == "audit"
        assert len(data["rules"]) >= 10

    def test_policy_engine_loads_strict(self, policies_dir):
        from core.policy_engine import PolicyEngine
        engine = PolicyEngine()
        engine.load_policy_file(str(policies_dir / "strict.yaml"))
        assert engine.rule_count > 0


class TestHTMLReport:
    def test_template_exists(self):
        path = Path(__file__).parent.parent / "templates" / "report.html"
        assert path.exists()

    def test_template_renders(self):
        from jinja2 import Environment, FileSystemLoader
        templates_dir = Path(__file__).parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(str(templates_dir)))
        template = env.get_template("report.html")
        html = template.render(
            title="Test Report",
            timestamp="2026-03-22",
            grade="A", score=95,
            errors=0, warnings=1, infos=3,
            total_files=10, duration="1.2",
            findings=[],
            owasp_entries=[],
            atlas_techniques=[],
        )
        assert "Test Report" in html
        assert "grade-A" in html


class TestConfigProfiles:
    @pytest.fixture
    def config_dir(self):
        return Path(__file__).parent.parent / "config"

    def test_settings_yaml_exists(self, config_dir):
        import yaml
        path = config_dir / "settings.yaml"
        assert path.exists()
        data = yaml.safe_load(path.read_text())
        assert "scanner" in data
        assert "grading" in data

    def test_quick_profile(self, config_dir):
        import yaml
        data = yaml.safe_load((config_dir / "profiles" / "quick.yaml").read_text())
        assert data["name"] == "quick"
        assert data["engines"]["ast_analyzer"] is False

    def test_full_profile(self, config_dir):
        import yaml
        data = yaml.safe_load((config_dir / "profiles" / "full.yaml").read_text())
        assert data["name"] == "full"
        assert data["engines"]["ast_analyzer"] is True

    def test_ci_profile(self, config_dir):
        import yaml
        data = yaml.safe_load((config_dir / "profiles" / "ci.yaml").read_text())
        assert data["name"] == "ci"
        assert data["output"]["format"] == "sarif"


class TestDockerfile:
    def test_dockerfile_exists(self):
        path = Path(__file__).parent.parent / "Dockerfile"
        assert path.exists()
        content = path.read_text()
        assert "FROM python" in content
        assert "USER scanner" in content  # Non-root
        assert "HEALTHCHECK" in content


class TestP1P2MCPTools:
    @pytest.fixture
    def handlers(self):
        from mcp_server.tools import ToolHandlers
        return ToolHandlers(rules_dir="rules")

    def test_map_owasp_llm(self, handlers):
        result = handlers.handle("map_owasp_llm", {
            "findings": [{"category": "jailbreak"}],
        })
        assert result["mapped"] > 0

    def test_owasp_compliance(self, handlers):
        result = handlers.handle("map_owasp_llm", {
            "findings": [{"category": "jailbreak"}],
            "compliance": True,
        })
        assert len(result["entries"]) == 10

    def test_evaluate_sandbox(self, handlers):
        result = handlers.handle("evaluate_sandbox", {
            "config": {"shell_access": True, "runs_as_root": True},
        })
        assert result["score"] < 80

    def test_scan_secrets(self, handlers):
        result = handlers.handle("scan_secrets", {
            "content": 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456"',
        })
        assert result["secrets_count"] > 0

    def test_generate_sbom(self, handlers):
        tmp_dir = tempfile.mkdtemp()
        Path(tmp_dir, "requirements.txt").write_text("flask==2.3.0\n")
        result = handlers.handle("generate_sbom", {"directory": tmp_dir})
        assert result["bomFormat"] == "CycloneDX"
