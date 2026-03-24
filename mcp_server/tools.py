"""MCP tool handlers — implements all 30 scanner tools."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import structlog

from core.atlas_mapper import ATLASMapper
from core.chain_detector import ChainDetector
from core.clickbait_detector import ClickbaitDetector
from core.dependency_analyzer import DependencyAnalyzer
from core.engine import ScanEngine
from core.fix_generator import FixGenerator
from core.grader import calculate_grade, calculate_score, grade_label
from core.inference_monitor import InferenceMonitor
from core.llm_worm_detector import LLMWormDetector
from core.mcp_auditor import MCPAuditor
from core.model_scanner import ModelScanner
from core.package_checker import PackageChecker
from core.policy_engine import PolicyEngine
from core.prompt_scanner import PromptScanner
from core.rag_scanner import RAGScanner
from core.redteam_generator import RedTeamGenerator
from core.runtime_monitor import RuntimeMonitor
from core.semantic_reviewer import SemanticReviewer
from core.owasp_llm_mapper import OWASPLLMMapper
from core.sandbox_evaluator import SandboxEvaluator
from core.sbom_generator import SBOMGenerator
from core.secrets_scanner import SecretsScanner
from core.tool_response_analyzer import ToolResponseAnalyzer

log = structlog.get_logger("mcp_tools")


class ToolHandlers:
    """Implements all MCP tool call handlers."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.engine = ScanEngine(rules_dir)
        self.engine.initialize()
        self.fix_gen = FixGenerator()
        self.pkg_checker = PackageChecker()
        self.prompt_scanner = PromptScanner(rules_path="rules/prompt_injection.yaml")
        self.mcp_auditor = MCPAuditor()
        self.rag_scanner = RAGScanner()
        self.response_analyzer = ToolResponseAnalyzer()
        self.chain_detector = ChainDetector()
        self.policy_engine = PolicyEngine()
        self.policy_engine.load_builtin_policies()
        self.redteam_gen = RedTeamGenerator()
        self.dep_analyzer = DependencyAnalyzer()
        self.runtime_monitor = RuntimeMonitor()
        self.atlas_mapper = ATLASMapper()
        self.model_scanner = ModelScanner()
        self.worm_detector = LLMWormDetector()
        self.inference_monitor = InferenceMonitor()
        self.clickbait_detector = ClickbaitDetector()
        self.owasp_mapper = OWASPLLMMapper()
        self.sandbox_evaluator = SandboxEvaluator()
        self.secrets_scanner = SecretsScanner()
        self.sbom_generator = SBOMGenerator()
        self.semantic_reviewer: SemanticReviewer | None = None  # Lazy init (needs API key)

    def _get_reviewer(self, provider: str = "claude") -> SemanticReviewer:
        if self.semantic_reviewer is None or self.semantic_reviewer.provider_name != provider:
            self.semantic_reviewer = SemanticReviewer(provider=provider)
        return self.semantic_reviewer

    def handle(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Route a tool call to the appropriate handler."""
        handlers = {
            "scan_security": self._scan_security,
            "fix_security": self._fix_security,
            "check_package": self._check_package,
            "scan_packages": self._scan_packages,
            "scan_agent_prompt": self._scan_agent_prompt,
            "scan_agent_action": self._scan_agent_action,
            "scan_project": self._scan_project,
            "scan_git_diff": self._scan_git_diff,
            "scan_dockerfile": self._scan_dockerfile,
            "scan_iac": self._scan_iac,
            "scanner_health": self._scanner_health,
            "semantic_review": self._semantic_review,
            "audit_mcp_server": self._audit_mcp_server,
            "scan_rag_document": self._scan_rag_document,
            "analyze_tool_response": self._analyze_tool_response,
            "detect_exploit_chains": self._detect_exploit_chains,
            "evaluate_policy": self._evaluate_policy,
            "generate_redteam": self._generate_redteam,
            "analyze_dependencies": self._analyze_dependencies,
            "monitor_session": self._monitor_session,
            "map_atlas": self._map_atlas,
            "scan_model": self._scan_model,
            "detect_llm_worm": self._detect_llm_worm,
            "monitor_inference": self._monitor_inference,
            "detect_clickbait": self._detect_clickbait,
            "map_owasp_llm": self._map_owasp_llm,
            "evaluate_sandbox": self._evaluate_sandbox,
            "scan_secrets": self._scan_secrets,
            "generate_sbom": self._generate_sbom,
        }

        handler = handlers.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            return handler(arguments)
        except Exception as e:
            log.error("tool_error", tool=tool_name, error=str(e))
            return {"error": str(e)}

    # ── scan_security ──────────────────────────────────────────────────

    def _scan_security(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        code = args.get("code")
        language = args.get("language", "python")
        verbosity = args.get("verbosity", "compact")

        if file_path:
            result = self.engine.scan_file(file_path)
        elif code:
            result = self.engine.scan_content(code, language)
        else:
            return {"error": "Provide either file_path or code"}

        findings = result.all_findings
        if verbosity == "minimal":
            return {
                "grade": result.grade.value,
                "total": result.total_findings,
                "errors": result.error_count,
                "warnings": result.warning_count,
            }

        finding_list = []
        for f in findings:
            entry: dict[str, Any] = {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "line": f.line_number,
                "cwe": f.cwe,
            }
            if verbosity == "full":
                entry["line_content"] = f.line_content
                entry["confidence"] = f.confidence.value
                entry["fix_suggestion"] = f.fix_suggestion
                entry["category"] = f.category
            finding_list.append(entry)

        return {
            "grade": result.grade.value,
            "score": calculate_score(result),
            "total_findings": result.total_findings,
            "findings": finding_list,
        }

    # ── fix_security ───────────────────────────────────────────────────

    def _fix_security(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args["file_path"]
        finding_id = args.get("finding_id")

        if not Path(file_path).exists():
            return {"error": f"File not found: {file_path}"}

        result = self.engine.scan_file(file_path)
        findings = result.all_findings

        if finding_id:
            findings = [f for f in findings if f.rule_id == finding_id]

        fix_result = self.fix_gen.generate_fixes(findings)

        fixes = []
        for fix in fix_result.fixes:
            fixes.append({
                "line": fix.finding.line_number,
                "cwe": fix.cwe,
                "original": fix.original_line.strip(),
                "fixed": fix.fixed_line.strip(),
                "explanation": fix.explanation,
                "requires_import": fix.requires_import,
            })

        return {
            "file": file_path,
            "fixes_available": fix_result.fix_count,
            "unfixable": fix_result.unfixable_count,
            "fixes": fixes,
            "diff": fix_result.generate_diff(file_path),
        }

    # ── check_package ──────────────────────────────────────────────────

    def _check_package(self, args: dict[str, Any]) -> dict[str, Any]:
        name = args["name"]
        registry = args.get("registry", "pypi")

        result = self.pkg_checker.check_package(name, registry)
        return {
            "package": name,
            "registry": registry,
            "exists": result.exists,
            "is_typosquat": result.is_typosquat,
            "is_malicious": result.is_malicious,
            "similar_to": result.similar_to,
            "risk_level": result.risk_level,
            "reason": result.reason,
        }

    # ── scan_packages ──────────────────────────────────────────────────

    def _scan_packages(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args["file_path"]
        if not Path(file_path).exists():
            return {"error": f"File not found: {file_path}"}

        results = self.pkg_checker.check_file_imports(file_path)
        packages = []
        for r in results:
            packages.append({
                "name": r.package_name,
                "registry": r.registry,
                "exists": r.exists,
                "is_typosquat": r.is_typosquat,
                "is_malicious": r.is_malicious,
                "risk_level": r.risk_level,
                "reason": r.reason,
            })

        critical = sum(1 for r in results if r.risk_level in ("high", "critical"))
        return {
            "file": file_path,
            "total_packages": len(results),
            "critical_issues": critical,
            "packages": packages,
        }

    # ── scan_agent_prompt ──────────────────────────────────────────────

    def _scan_agent_prompt(self, args: dict[str, Any]) -> dict[str, Any]:
        text = args["prompt_text"]
        result = self.prompt_scanner.scan_text(text)

        findings = []
        for f in result.findings:
            findings.append({
                "pattern": f.pattern_id,
                "category": f.category,
                "risk": f.risk,
                "description": f.description,
                "matched": f.matched_text[:100],
            })

        return {
            "is_safe": result.is_safe,
            "risk_level": result.risk_level,
            "findings_count": result.finding_count,
            "findings": findings,
            "scan_time_ms": round(result.scan_time_ms, 1),
        }

    # ── scan_agent_action ──────────────────────────────────────────────

    def _scan_agent_action(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args["action"]
        target = args["target"]

        match action:
            case "execute_command":
                return self._check_command_safety(target)
            case "write_file":
                return self._check_file_write_safety(target)
            case "fetch_url":
                return self._check_url_safety(target)
            case "install_package":
                registry = args.get("args", {}).get("registry", "pypi")
                pkg_result = self.pkg_checker.check_package(target, registry)
                safe = not pkg_result.is_malicious and not pkg_result.is_typosquat
                return {
                    "safe": safe,
                    "action": action,
                    "target": target,
                    "risk": pkg_result.risk_level,
                    "reason": pkg_result.reason or "Package appears legitimate",
                }
            case _:
                return {"safe": True, "action": action, "target": target, "reason": "Unknown action type — allowing by default"}

    def _check_command_safety(self, command: str) -> dict[str, Any]:
        dangerous = ["rm -rf /", "rm -rf /*", "mkfs", "dd if=", "> /dev/sd",
                     "chmod 777", "curl|sh", "curl|bash", "wget|sh", "wget|bash",
                     ":(){:|:&};:", "fork bomb"]
        for d in dangerous:
            if d in command:
                return {"safe": False, "action": "execute_command", "target": command,
                        "risk": "critical", "reason": f"Dangerous command pattern: {d}"}

        # Check for reverse shell patterns
        revshell = ["nc -e", "ncat -e", "bash -i >& /dev/tcp", "/bin/sh -i",
                    "python -c 'import socket", "perl -e 'use Socket"]
        for r in revshell:
            if r in command:
                return {"safe": False, "action": "execute_command", "target": command,
                        "risk": "critical", "reason": "Reverse shell pattern detected"}

        return {"safe": True, "action": "execute_command", "target": command,
                "risk": "low", "reason": "No dangerous patterns detected"}

    def _check_file_write_safety(self, path: str) -> dict[str, Any]:
        sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     ".ssh/authorized_keys", ".bashrc", ".profile",
                     "/etc/cron", ".env", "/etc/hosts"]
        for s in sensitive:
            if s in path:
                return {"safe": False, "action": "write_file", "target": path,
                        "risk": "critical", "reason": f"Writing to sensitive path: {s}"}

        return {"safe": True, "action": "write_file", "target": path,
                "risk": "low", "reason": "Path appears safe"}

    def _check_url_safety(self, url: str) -> dict[str, Any]:
        suspicious = ["ngrok", "requestbin", "hookbin", "burpcollaborator",
                      "interact.sh", "pipedream", "canarytokens"]
        for s in suspicious:
            if s in url.lower():
                return {"safe": False, "action": "fetch_url", "target": url,
                        "risk": "high", "reason": f"Suspicious URL — {s} is an exfiltration service"}

        if not url.startswith("https://"):
            return {"safe": False, "action": "fetch_url", "target": url,
                    "risk": "medium", "reason": "Non-HTTPS URL — data transmitted in cleartext"}

        return {"safe": True, "action": "fetch_url", "target": url,
                "risk": "low", "reason": "URL appears safe"}

    # ── scan_project ───────────────────────────────────────────────────

    def _scan_project(self, args: dict[str, Any]) -> dict[str, Any]:
        directory = args["directory"]
        exclude_tests = args.get("exclude_tests", False)

        if not Path(directory).is_dir():
            return {"error": f"Directory not found: {directory}"}

        result = self.engine.scan_project(directory, exclude_tests=exclude_tests)

        return {
            "directory": directory,
            "grade": result.grade.value,
            "score": calculate_score(result),
            "grade_label": grade_label(result.grade),
            "total_files": result.total_files,
            "total_lines": result.total_lines,
            "total_findings": result.total_findings,
            "errors": result.error_count,
            "warnings": result.warning_count,
            "infos": result.info_count,
            "duration_seconds": round(result.duration_seconds, 2),
        }

    # ── scan_git_diff ──────────────────────────────────────────────────

    def _scan_git_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        directory = args.get("directory", ".")
        base_ref = args.get("base_ref", "HEAD")

        try:
            diff_output = subprocess.run(
                ["git", "diff", "--name-only", base_ref],
                capture_output=True, text=True, cwd=directory, timeout=30,
            )
            if diff_output.returncode != 0:
                return {"error": f"git diff failed: {diff_output.stderr.strip()}"}

            changed_files = [f.strip() for f in diff_output.stdout.strip().splitlines() if f.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"error": f"git not available: {str(e)}"}

        if not changed_files:
            return {"changed_files": 0, "findings": [], "message": "No changed files"}

        all_findings = []
        for file in changed_files:
            full_path = str(Path(directory) / file)
            if Path(full_path).exists():
                result = self.engine.scan_file(full_path)
                for f in result.all_findings:
                    all_findings.append({
                        "file": file,
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "message": f.message,
                        "line": f.line_number,
                        "cwe": f.cwe,
                    })

        return {
            "changed_files": len(changed_files),
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

    # ── scan_dockerfile / scan_iac ─────────────────────────────────────

    def _scan_dockerfile(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._scan_security({"file_path": args["file_path"], "verbosity": "compact"})

    def _scan_iac(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._scan_security({"file_path": args["file_path"], "verbosity": "compact"})

    # ── scanner_health ─────────────────────────────────────────────────

    def _scanner_health(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "version": "0.1.0",
            "status": "healthy",
            "rules_loaded": self.engine.rules_loaded,
            "prompt_patterns": self.prompt_scanner.pattern_count,
            "engines": [
                "pattern_matcher", "ast_analyzer", "taint_tracker", "package_checker",
                "prompt_scanner", "fix_generator", "semantic_reviewer",
                "mcp_auditor", "rag_scanner", "tool_response_analyzer",
                "chain_detector", "policy_engine", "runtime_monitor",
                "redteam_generator", "dependency_analyzer",
                "atlas_mapper", "model_scanner", "llm_worm_detector",
                "inference_monitor", "clickbait_detector",
            ],
            "supported_languages": [
                "python", "javascript", "typescript", "java", "go", "php",
                "ruby", "c", "cpp", "rust", "swift", "kotlin",
                "shell", "dockerfile", "terraform", "kubernetes",
            ],
        }

    # ── semantic_review ────────────────────────────────────────────────

    def _semantic_review(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        code = args.get("code")
        language = args.get("language", "python")
        provider = args.get("provider", "claude")

        try:
            reviewer = self._get_reviewer(provider)
        except Exception as e:
            return {"error": f"Failed to initialize reviewer: {e}"}

        if file_path:
            if not Path(file_path).exists():
                return {"error": f"File not found: {file_path}"}
            result = reviewer.review_file(file_path)
        elif code:
            result = reviewer.review_code(code, language)
        else:
            return {"error": "Provide either file_path or code"}

        if result.error:
            return {"error": result.error}

        return {
            "summary": result.summary,
            "intent_analysis": result.intent_analysis,
            "project_type": result.project_type,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "line_start": f.line_start,
                    "cwe": f.cwe,
                    "fix_suggestion": f.fix_suggestion,
                    "confidence": f.confidence,
                    "category": f.category,
                }
                for f in result.findings
            ],
            "tokens_used": result.tokens_used,
            "review_time_ms": round(result.review_time_ms, 1),
            "provider": result.provider,
        }

    # ── audit_mcp_server ───────────────────────────────────────────────

    def _audit_mcp_server(self, args: dict[str, Any]) -> dict[str, Any]:
        tools = args.get("tools", [])
        server_name = args.get("server_name", "unknown")

        if not tools:
            return {"error": "Provide 'tools' array (MCP tools/list response)"}

        result = self.mcp_auditor.audit_tools(tools, server_name=server_name)
        return {
            "server": server_name,
            "grade": result.grade,
            "score": result.score,
            "total_tools": result.total_tools,
            "findings_count": result.finding_count,
            "critical": result.critical_count,
            "high": result.high_count,
            "tool_risks": result.tool_risks,
            "findings": [
                {"tool": f.tool_name, "risk": f.risk, "category": f.category,
                 "title": f.title, "remediation": f.remediation}
                for f in result.findings
            ],
        }

    # ── scan_rag_document ──────────────────────────────────────────────

    def _scan_rag_document(self, args: dict[str, Any]) -> dict[str, Any]:
        content = args.get("content")
        file_path = args.get("file_path")

        if file_path:
            if not Path(file_path).exists():
                return {"error": f"File not found: {file_path}"}
            findings = self.rag_scanner.scan_file(file_path)
            source = file_path
        elif content:
            findings = self.rag_scanner.scan_document(content, source_file="<input>")
            source = "<input>"
        else:
            return {"error": "Provide 'content' or 'file_path'"}

        return {
            "source": source,
            "is_safe": len(findings) == 0,
            "findings_count": len(findings),
            "findings": [
                {"category": f.category, "risk": f.risk, "title": f.title,
                 "line": f.line_number, "matched": f.matched_text[:100]}
                for f in findings
            ],
        }

    # ── analyze_tool_response ──────────────────────────────────────────

    def _analyze_tool_response(self, args: dict[str, Any]) -> dict[str, Any]:
        tool_name = args.get("tool_name", "unknown")
        response = args.get("response", "")

        if not response:
            return {"error": "Provide 'response' text to analyze"}

        result = self.response_analyzer.analyze(tool_name, response)
        return {
            "tool": tool_name,
            "is_safe": result.is_safe,
            "risk_level": result.risk_level,
            "findings_count": result.finding_count,
            "findings": [
                {"category": f.category, "risk": f.risk, "title": f.title,
                 "matched": f.matched_text[:100]}
                for f in result.findings
            ],
            "sanitized_output": result.sanitized_output[:1000] if not result.is_safe else "",
        }

    # ── detect_exploit_chains ─────────────────────────────────────────

    def _detect_exploit_chains(self, args: dict[str, Any]) -> dict[str, Any]:
        actions = args.get("actions", [])
        session_id = args.get("session_id", "mcp")

        if not actions:
            return {"error": "Provide 'actions' array"}

        detector = ChainDetector()  # Fresh detector per request
        for action in actions:
            detector.record_action(
                session_id=session_id,
                tool_name=action.get("tool", "unknown"),
                target=action.get("target", ""),
            )

        result = detector.check()
        return result.to_dict()

    # ── evaluate_policy ───────────────────────────────────────────────

    def _evaluate_policy(self, args: dict[str, Any]) -> dict[str, Any]:
        scope = args.get("scope", "command")
        target = args.get("target", "")

        if not target:
            return {"error": "Provide 'target' to evaluate"}

        result = self.policy_engine.evaluate(scope, target)
        return result.to_dict()

    # ── generate_redteam ──────────────────────────────────────────────

    def _generate_redteam(self, args: dict[str, Any]) -> dict[str, Any]:
        category = args.get("category")
        difficulty = args.get("difficulty")
        run_benchmark = args.get("benchmark", False)

        if category:
            suite = self.redteam_gen.generate_by_category(category)
        elif difficulty:
            suite = self.redteam_gen.generate_by_difficulty(difficulty)
        else:
            suite = self.redteam_gen.generate_full_suite()

        output = {
            "name": suite.name,
            "total_tests": suite.total,
            "by_category": suite.by_category,
            "by_difficulty": suite.by_difficulty,
        }

        if run_benchmark:
            output["benchmark"] = self.redteam_gen.benchmark(
                suite,
                prompt_scanner=self.prompt_scanner,
                chain_detector=self.chain_detector,
            )

        # Include test summaries (not full payloads to keep response manageable)
        output["tests"] = [
            {"test_id": t.test_id, "name": t.name, "category": t.category.value,
             "difficulty": t.difficulty.value, "expected_detection": t.expected_detection}
            for t in suite.tests
        ]

        return output

    # ── analyze_dependencies ──────────────────────────────────────────

    def _analyze_dependencies(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        directory = args.get("directory")

        if file_path:
            result = self.dep_analyzer.analyze_file(file_path)
            return result.to_dict()
        elif directory:
            results = self.dep_analyzer.analyze_project(directory)
            return {
                "directory": directory,
                "files_analyzed": len(results),
                "results": [r.to_dict() for r in results],
            }
        else:
            return {"error": "Provide 'file_path' or 'directory'"}

    # ── monitor_session ───────────────────────────────────────────────

    def _monitor_session(self, args: dict[str, Any]) -> dict[str, Any]:
        session_id = args.get("session_id", "default")
        action_type = args.get("action_type", "unknown")
        target = args.get("target", "")
        tool_name = args.get("tool_name", action_type)

        alert = self.runtime_monitor.record(
            session_id=session_id,
            action_type=action_type,
            target=target,
            tool_name=tool_name,
        )

        profile = self.runtime_monitor.get_session_profile(session_id)
        result: dict[str, Any] = {
            "session_id": session_id,
            "action_recorded": True,
            "alert": None,
        }

        if profile:
            result["risk_score"] = round(profile.risk_score, 2)
            result["total_actions"] = profile.total_actions

        if alert:
            result["alert"] = alert.to_dict()

        return result

    # ── map_atlas ─────────────────────────────────────────────────────

    def _map_atlas(self, args: dict[str, Any]) -> dict[str, Any]:
        findings = args.get("findings", [])
        generate_layer = args.get("generate_layer", False)

        if not findings:
            return {"error": "Provide 'findings' array"}

        result = self.atlas_mapper.map_findings(findings)
        output = result.to_dict()

        if generate_layer:
            output["navigator_layer"] = self.atlas_mapper.generate_navigator_layer(findings)

        return output

    # ── scan_model ────────────────────────────────────────────────────

    def _scan_model(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        code = args.get("code")

        if file_path:
            result = self.model_scanner.scan_file(file_path)
            return result.to_dict()
        elif code:
            findings = self.model_scanner.scan_code_for_unsafe_loading(code)
            return {
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            }
        else:
            return {"error": "Provide 'file_path' or 'code'"}

    # ── detect_llm_worm ──────────────────────────────────────────────

    def _detect_llm_worm(self, args: dict[str, Any]) -> dict[str, Any]:
        text = args.get("text", "")
        original_prompt = args.get("original_prompt")
        llm_output = args.get("llm_output")

        if original_prompt and llm_output:
            result = self.worm_detector.check_output_for_replication(original_prompt, llm_output)
        elif text:
            result = self.worm_detector.scan_text(text)
        else:
            return {"error": "Provide 'text' or both 'original_prompt' and 'llm_output'"}

        return result.to_dict()

    # ── monitor_inference ─────────────────────────────────────────────

    def _monitor_inference(self, args: dict[str, Any]) -> dict[str, Any]:
        request_id = args.get("request_id", "unknown")
        source_ip = args.get("source_ip", "0.0.0.0")
        model_id = args.get("model_id", "unknown")
        input_tokens = args.get("input_tokens", 0)
        output_tokens = args.get("output_tokens", 0)

        alert = self.inference_monitor.record_request(
            request_id=request_id, source_ip=source_ip, model_id=model_id,
            input_tokens=input_tokens, output_tokens=output_tokens,
        )

        profile = self.inference_monitor.get_profile(source_ip)
        result: dict[str, Any] = {
            "recorded": True,
            "alert": alert.to_dict() if alert else None,
        }
        if profile:
            result["profile"] = profile.to_dict()

        return result

    # ── detect_clickbait ──────────────────────────────────────────────

    def _detect_clickbait(self, args: dict[str, Any]) -> dict[str, Any]:
        content = args.get("content", "")
        content_type = args.get("content_type", "auto")

        if not content:
            return {"error": "Provide 'content' to scan"}

        result = self.clickbait_detector.scan_content(content, content_type)
        return result.to_dict()

    # ── map_owasp_llm ─────────────────────────────────────────────────

    def _map_owasp_llm(self, args: dict[str, Any]) -> dict[str, Any]:
        findings = args.get("findings", [])
        compliance = args.get("compliance", False)

        if not findings:
            return {"error": "Provide 'findings' array"}

        if compliance:
            return self.owasp_mapper.generate_compliance_report(findings)
        return self.owasp_mapper.map_findings(findings).to_dict()

    # ── evaluate_sandbox ──────────────────────────────────────────────

    def _evaluate_sandbox(self, args: dict[str, Any]) -> dict[str, Any]:
        config = args.get("config", args)
        return self.sandbox_evaluator.evaluate_from_dict(config).to_dict()

    # ── scan_secrets ──────────────────────────────────────────────────

    def _scan_secrets(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        content = args.get("content")
        directory = args.get("directory")

        if file_path:
            return self.secrets_scanner.scan_file(file_path).to_dict()
        elif content:
            return self.secrets_scanner.scan_content(content).to_dict()
        elif directory:
            results = self.secrets_scanner.scan_directory(directory)
            return {
                "directory": directory,
                "files_with_secrets": len(results),
                "total_secrets": sum(r.count for r in results),
                "results": [r.to_dict() for r in results],
            }
        return {"error": "Provide 'file_path', 'content', or 'directory'"}

    # ── generate_sbom ─────────────────────────────────────────────────

    def _generate_sbom(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path = args.get("file_path")
        directory = args.get("directory")

        if directory:
            return self.sbom_generator.generate_project(directory)
        elif file_path:
            return self.sbom_generator.generate_file(file_path)
        return {"error": "Provide 'file_path' or 'directory'"}
