"""MCP tool schemas — input/output definitions for all 20 scanner tools."""

from __future__ import annotations

from typing import Any


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return MCP tool definitions with JSON schemas."""
    return [
        {
            "name": "scan_security",
            "description": "Scan a file or code snippet for security vulnerabilities using AST analysis, taint tracking, and pattern matching. Returns findings with severity, CWE, and fix suggestions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to scan"},
                    "code": {"type": "string", "description": "Code snippet to scan (alternative to file_path)"},
                    "language": {"type": "string", "description": "Language of the code snippet (python, javascript, etc.)"},
                    "verbosity": {"type": "string", "enum": ["minimal", "compact", "full"], "default": "compact"},
                },
                "oneOf": [
                    {"required": ["file_path"]},
                    {"required": ["code", "language"]},
                ],
            },
        },
        {
            "name": "fix_security",
            "description": "Auto-fix detected security vulnerabilities in a file. Returns patched code with explanations for each fix applied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to fix"},
                    "finding_id": {"type": "string", "description": "Specific rule ID to fix (optional — fixes all if omitted)"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "check_package",
            "description": "Verify if a package name exists on a registry (PyPI, npm, crates.io). Detects hallucinated, typosquatted, and known malicious packages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Package name to check"},
                    "registry": {"type": "string", "enum": ["pypi", "npm", "crates"], "default": "pypi"},
                },
                "required": ["name"],
            },
        },
        {
            "name": "scan_packages",
            "description": "Scan all imports in a file for hallucinated, typosquatted, or malicious packages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to scan imports from"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "scan_agent_prompt",
            "description": "Scan text for prompt injection attacks including jailbreaks, DAN mode, data exfiltration, hidden instructions, and tool abuse patterns. Returns risk level and matched patterns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt_text": {"type": "string", "description": "The text to scan for prompt injection"},
                },
                "required": ["prompt_text"],
            },
        },
        {
            "name": "scan_agent_action",
            "description": "Pre-execution safety check for an action an AI agent is about to take. Evaluates command safety, file path safety, and URL safety.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Action type (execute_command, write_file, fetch_url, install_package)"},
                    "target": {"type": "string", "description": "The target of the action (command, file path, URL, or package name)"},
                    "args": {"type": "object", "description": "Additional arguments for the action"},
                },
                "required": ["action", "target"],
            },
        },
        {
            "name": "scan_project",
            "description": "Full security audit of a project directory. Returns A-F security grade, finding summary, and per-file results.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Path to the project directory"},
                    "exclude_tests": {"type": "boolean", "default": False, "description": "Exclude test files from scanning"},
                },
                "required": ["directory"],
            },
        },
        {
            "name": "scan_git_diff",
            "description": "Scan only files changed in the current git diff for security issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Project directory (defaults to current)"},
                    "base_ref": {"type": "string", "default": "HEAD", "description": "Base git ref to diff against"},
                },
            },
        },
        {
            "name": "scan_dockerfile",
            "description": "Security audit of a Dockerfile for hardening issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the Dockerfile"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "scan_iac",
            "description": "Scan Infrastructure-as-Code files (Terraform, Kubernetes manifests) for misconfigurations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the IaC file"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "scanner_health",
            "description": "Plugin diagnostics — returns version, loaded rules, engine status, and pattern counts.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
        {
            "name": "semantic_review",
            "description": "AI-powered semantic code review using Claude or OpenAI. Provides context-aware security analysis where the same code pattern gets different verdicts based on project type (web app vs CLI tool vs library).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file to review"},
                    "code": {"type": "string", "description": "Code snippet to review (alternative to file_path)"},
                    "language": {"type": "string", "description": "Language of the code snippet", "default": "python"},
                    "provider": {"type": "string", "enum": ["claude", "openai"], "default": "claude"},
                },
                "oneOf": [
                    {"required": ["file_path"]},
                    {"required": ["code", "language"]},
                ],
            },
        },
        # ── Tier 1 Tools ─────────────────────────────────────────────────
        {
            "name": "audit_mcp_server",
            "description": "Audit an MCP server's tool definitions for dangerous capabilities, schema injection, missing safety controls, and exfiltration chains.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tools": {"type": "array", "description": "MCP tools/list response array"},
                    "server_name": {"type": "string", "description": "Name of the MCP server", "default": "unknown"},
                },
                "required": ["tools"],
            },
        },
        {
            "name": "scan_rag_document",
            "description": "Scan a document for RAG pipeline injection attacks including hidden instructions, sensitive data exposure, and exfiltration attempts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Document text to scan"},
                    "file_path": {"type": "string", "description": "Path to document file"},
                },
            },
        },
        {
            "name": "analyze_tool_response",
            "description": "Analyze an MCP tool response for injection attacks, exfiltration URLs, and escalation patterns before passing to LLM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "description": "Name of the tool that produced the response"},
                    "response": {"type": "string", "description": "Tool response text to analyze"},
                },
                "required": ["response"],
            },
        },
        # ── Tier 2 Tools ─────────────────────────────────────────────────
        {
            "name": "detect_exploit_chains",
            "description": "Detect multi-step exploit chains (exfiltration, persistence, privilege escalation) in a sequence of agent actions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actions": {"type": "array", "description": "Sequence of {tool, target} objects"},
                    "session_id": {"type": "string", "default": "mcp"},
                },
                "required": ["actions"],
            },
        },
        {
            "name": "evaluate_policy",
            "description": "Evaluate an agent action against security policies. Returns allow/deny/warn decision.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["command", "file_read", "file_write", "network", "package"]},
                    "target": {"type": "string", "description": "Action target"},
                },
                "required": ["scope", "target"],
            },
        },
        {
            "name": "generate_redteam",
            "description": "Generate adversarial red team test suite for benchmarking agent security defenses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": ["prompt_injection", "tool_abuse", "evasion", "supply_chain", "mcp_poisoning", "rag_injection"]},
                    "difficulty": {"type": "string", "enum": ["easy", "medium", "hard", "expert"]},
                    "benchmark": {"type": "boolean", "default": False},
                },
            },
        },
        {
            "name": "analyze_dependencies",
            "description": "Analyze dependency files for supply chain risks including typosquatting, malicious packages, and dependency confusion.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Dependency file path"},
                    "directory": {"type": "string", "description": "Project directory"},
                },
            },
        },
        {
            "name": "monitor_session",
            "description": "Record agent action and check for real-time anomalies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "action_type": {"type": "string"},
                    "target": {"type": "string"},
                    "tool_name": {"type": "string"},
                },
                "required": ["session_id", "action_type", "target"],
            },
        },
    ]
