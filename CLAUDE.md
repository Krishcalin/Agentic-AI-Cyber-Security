# CLAUDE.md — Agentic AI Cyber Security

## Project Overview

An open-source Python-based source code security analyzer that identifies security flaws,
flags fictitious or non-existent dependencies, prevents prompt injection attacks, and delivers
AI-driven semantic code analysis — accessible through MCP integrations with Claude Code or
command-line interfaces and CI/CD pipelines.

**Repository**: https://github.com/Krishcalin/Agentic-AI-Cyber-Security
**License**: MIT
**Python**: 3.10+
**Inspired by**: [sinewaveai/agent-security-scanner-mcp](https://github.com/sinewaveai/agent-security-scanner-mcp)

---

## Architecture

### Directory Structure

```
Agentic-AI-Cyber-Security/
├── config/                            # Configuration files
│   ├── settings.yaml                  # Global scanner settings
│   └── profiles/                      # Scan profiles (quick, full, ci)
│       ├── quick.yaml
│       ├── full.yaml
│       └── ci.yaml
├── core/                              # Core engine components
│   ├── __init__.py
│   ├── engine.py                      # Main scanner orchestrator
│   ├── ast_analyzer.py                # AST-based vulnerability detection (Python)
│   ├── pattern_matcher.py             # Regex/pattern-based scanning (multi-lang)
│   ├── taint_tracker.py               # Cross-function taint flow analysis
│   ├── package_checker.py             # Dependency verification (PyPI, npm, crates)
│   ├── prompt_scanner.py              # Prompt injection detection engine
│   ├── semantic_reviewer.py           # LLM-powered code review (Claude API)
│   ├── fix_generator.py               # Auto-fix template engine
│   ├── reporter.py                    # Report generation (terminal, JSON, SARIF, HTML)
│   ├── grader.py                      # A–F security grading system
│   ├── models.py                      # Data models (Finding, ScanResult, Severity)
│   └── logger.py                      # Structured logging
├── rules/                             # YAML security rules (organized by language)
│   ├── python.yaml                    # Python-specific rules
│   ├── javascript.yaml                # JavaScript/TypeScript rules
│   ├── java.yaml                      # Java rules
│   ├── go.yaml                        # Go rules
│   ├── php.yaml                       # PHP rules
│   ├── ruby.yaml                      # Ruby rules
│   ├── c_cpp.yaml                     # C/C++ rules
│   ├── dockerfile.yaml                # Dockerfile rules
│   ├── terraform.yaml                 # Terraform/IaC rules
│   ├── kubernetes.yaml                # Kubernetes manifest rules
│   ├── prompt_injection.yaml          # Prompt injection patterns
│   └── common.yaml                    # Cross-language rules (secrets, hardcoded creds)
├── mcp_server/                        # MCP (Model Context Protocol) server
│   ├── __init__.py
│   ├── server.py                      # MCP server entry point (stdio transport)
│   ├── tools.py                       # MCP tool definitions and handlers
│   └── schemas.py                     # Input/output JSON schemas for tools
├── cli/                               # CLI interface
│   ├── __init__.py
│   └── main.py                        # Click-based CLI entry point
├── integrations/                      # CI/CD and editor integrations
│   ├── github_actions.py              # GitHub Actions reporter
│   ├── gitlab_ci.py                   # GitLab CI integration
│   └── sarif_exporter.py              # SARIF 2.1.0 export for Code Scanning
├── data/                              # Static data files
│   ├── pypi_packages.bloom            # Bloom filter — PyPI package names
│   ├── npm_packages.bloom             # Bloom filter — npm package names
│   ├── crates_packages.bloom          # Bloom filter — crates.io package names
│   └── known_malicious.yaml           # Known malicious package list
├── templates/                         # Report templates
│   ├── report.html                    # HTML report template (Jinja2)
│   └── fix_templates/                 # Auto-fix templates by CWE
│       ├── cwe_78.py                  # OS Command Injection fixes
│       ├── cwe_89.py                  # SQL Injection fixes
│       ├── cwe_79.py                  # XSS fixes
│       ├── cwe_798.py                 # Hardcoded Credentials fixes
│       └── ...
├── tests/                             # pytest test suite
│   ├── conftest.py
│   ├── test_engine.py
│   ├── test_ast_analyzer.py
│   ├── test_pattern_matcher.py
│   ├── test_taint_tracker.py
│   ├── test_package_checker.py
│   ├── test_prompt_scanner.py
│   ├── test_semantic_reviewer.py
│   ├── test_fix_generator.py
│   ├── test_grader.py
│   ├── test_mcp_server.py
│   ├── test_rules/                    # Rule validation tests
│   └── fixtures/                      # Vulnerable code samples per language
│       ├── python_vulnerable.py
│       ├── javascript_vulnerable.js
│       └── ...
├── benchmarks/                        # Performance and accuracy benchmarks
│   ├── accuracy_test.py               # Precision/recall against known CVEs
│   └── results.md                     # Benchmark results
├── main.py                            # CLI entry point
├── pyproject.toml                     # Project metadata + dependencies
├── requirements.txt                   # Pinned dependencies
├── CLAUDE.md                          # This file
└── README.md
```

### Core Design Principles

1. **Python-native** — entire scanner written in Python, no Node.js dependency
2. **Multi-engine analysis** — AST parsing, regex patterns, taint tracking, and LLM review
3. **MCP-first** — designed as an MCP server for Claude Code, also works standalone CLI
4. **Rule-driven** — all vulnerability patterns defined in YAML, easy to extend
5. **Language-agnostic rules** — supports Python, JavaScript/TypeScript, Java, Go, PHP, Ruby, C/C++, Dockerfile, Terraform, Kubernetes
6. **Package hallucination detection** — bloom filter verification against real registries
7. **Prompt injection firewall** — detects injection patterns in LLM-integrated code
8. **Context-aware** — same code pattern gets different verdicts based on project context
9. **Auto-fix** — generates remediation code, not just findings
10. **CI/CD ready** — SARIF 2.1.0 export, GitHub Actions integration, exit codes

---

## MCP Tools (11 total)

| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `scan_security` | Scan file(s) for vulnerabilities | `file_path`, `language?`, `verbosity?` | Findings with severity, CWE, fix suggestions |
| `fix_security` | Auto-fix detected vulnerabilities | `file_path`, `finding_id?` | Patched code with explanation |
| `check_package` | Verify if a package exists on registry | `name`, `registry?` (pypi/npm/crates) | Exists, typosquat risk, known malicious |
| `scan_packages` | Bulk verify all imports in a file | `file_path` | List of verified/suspicious packages |
| `scan_agent_prompt` | Detect prompt injection in text | `prompt_text` | Injection patterns found, risk level |
| `scan_agent_action` | Pre-execution safety check | `action`, `args` | Safe/unsafe verdict with reason |
| `scan_project` | Full project security audit | `directory`, `profile?` | A–F grade, finding summary, report |
| `scan_git_diff` | Scan only changed files | `base_ref?` | Findings in diff only |
| `scan_dockerfile` | Dockerfile security audit | `file_path` | Image hardening findings |
| `scan_iac` | Infrastructure-as-Code scan | `file_path` | Terraform/K8s misconfigurations |
| `scanner_health` | Plugin diagnostics | — | Version, rules loaded, engine status |

---

## Analysis Engines

### 1. AST Analyzer (`core/ast_analyzer.py`)
- Python `ast` module for Python source files
- Tree-sitter bindings for JavaScript, Java, Go, etc.
- Detects: dangerous function calls, unsafe imports, eval/exec usage, SQL string formatting
- Cross-function scope tracking

### 2. Pattern Matcher (`core/pattern_matcher.py`)
- YAML-defined regex rules per language
- CWE-mapped patterns with severity levels
- Framework-aware filtering (Django, Flask, Express, etc.)
- Test file exclusion

### 3. Taint Tracker (`core/taint_tracker.py`)
- Tracks user input → dangerous sink flows
- Sources: `request.args`, `sys.argv`, `input()`, `os.environ`
- Sinks: `os.system()`, `subprocess.run()`, `cursor.execute()`, `eval()`
- Cross-function taint propagation

### 4. Package Checker (`core/package_checker.py`)
- Bloom filter verification (PyPI: ~500K, npm: ~2.5M, crates: ~130K)
- Typosquatting detection (edit distance + common substitutions)
- Known malicious package database
- Version pinning audit

### 5. Prompt Scanner (`core/prompt_scanner.py`)
- 60+ prompt injection patterns
- Jailbreak detection (DAN, ignore previous, system prompt leak)
- Data exfiltration patterns (encode and send, webhook calls)
- Hidden instruction detection in user inputs
- LLM integration security (tool_use abuse, function calling injection)

### 6. Semantic Reviewer (`core/semantic_reviewer.py`)
- LLM-powered code review via Claude API
- Context-aware analysis (build tool vs web app vs CLI)
- Intent classification: is `subprocess.run()` expected here?
- Project-type detection from dependencies and structure
- Providers: Claude API (default), OpenAI (optional)

---

## Security Rules Format

Rules are defined in YAML files under `rules/`:

```yaml
rules:
  - id: python.injection.sql-format-string
    languages: [python]
    severity: ERROR
    cwe: CWE-89
    owasp: A03:2021
    message: "SQL query built with string formatting — SQL injection risk"
    patterns:
      - 'cursor\.execute\s*\(\s*f["\']'
      - 'cursor\.execute\s*\(\s*["\'].*%[sd]'
      - 'cursor\.execute\s*\(\s*["\'].*\.format\s*\('
    fix_template: cwe_89
    metadata:
      confidence: HIGH
      effort: LOW
      references:
        - https://cwe.mitre.org/data/definitions/89.html

  - id: python.crypto.weak-hash
    languages: [python]
    severity: WARNING
    cwe: CWE-328
    message: "Use of weak hash algorithm (MD5/SHA1)"
    patterns:
      - 'hashlib\.(md5|sha1)\s*\('
      - 'Crypto\.Hash\.(MD5|SHA)\.'
    fix_template: cwe_328
    metadata:
      confidence: HIGH
      replacement: "hashlib.sha256()"
```

---

## Security Grading System

| Grade | Score | Criteria |
|-------|-------|----------|
| A | 90-100 | No critical/high findings, ≤2 medium |
| B | 75-89 | No critical, ≤2 high, ≤5 medium |
| C | 60-74 | No critical, ≤5 high |
| D | 40-59 | ≤2 critical, any high/medium |
| F | 0-39 | 3+ critical findings |

---

## Output Formats

### Terminal (default)
Rich-formatted output with color-coded severity, code snippets, and fix suggestions.

### JSON
Machine-readable output for CI/CD integration.

### SARIF 2.1.0
Standard format for GitHub Code Scanning, GitLab SAST, and other code analysis tools.

### HTML
Standalone HTML report with executive summary, finding details, and security grade.

---

## Verbosity Levels

| Level | Tokens | Use Case |
|-------|--------|----------|
| `minimal` | ~50 | CI/CD pipelines, automated checks |
| `compact` | ~200 | Default development use |
| `full` | ~2000 | Debugging, compliance reporting, audits |

---

## Development Phases

### Phase 1 — Foundation
- [ ] Project scaffolding: `pyproject.toml`, `requirements.txt`, `.gitignore`
- [ ] Data models (`core/models.py`) — Finding, ScanResult, Severity, Grade
- [ ] Pattern matcher engine (`core/pattern_matcher.py`) — regex-based scanning
- [ ] Rule loader — YAML rule parsing and validation
- [ ] Initial rules: Python (50+ rules), JavaScript (50+ rules)
- [ ] CLI entry point (`cli/main.py`) with click
- [ ] Terminal reporter with Rich formatting
- [ ] Security grading system (`core/grader.py`)
- [ ] Structured logging (`core/logger.py`)

### Phase 2 — AST Analysis & Taint Tracking
- [ ] Python AST analyzer (`core/ast_analyzer.py`)
- [ ] Taint tracking engine (`core/taint_tracker.py`)
- [ ] Cross-function data flow analysis
- [ ] Source/sink database for Python and JavaScript
- [ ] Framework detection (Django, Flask, FastAPI, Express)
- [ ] Test file exclusion and context filtering

### Phase 3 — Package Verification
- [ ] Bloom filter builder for PyPI, npm, crates.io
- [ ] Package existence checker (`core/package_checker.py`)
- [ ] Typosquatting detection (Levenshtein distance + substitutions)
- [ ] Known malicious package database
- [ ] Import extraction for Python, JavaScript, Go, Java, Ruby
- [ ] Version pinning audit (requirements.txt, package.json, go.mod)

### Phase 4 — Prompt Injection Detection
- [ ] Prompt injection pattern engine (`core/prompt_scanner.py`)
- [ ] 60+ injection patterns (jailbreak, DAN, system prompt leak)
- [ ] Data exfiltration pattern detection
- [ ] Hidden instruction detection
- [ ] LLM integration security (tool_use abuse, function calling)
- [ ] Prompt injection rules in YAML (`rules/prompt_injection.yaml`)

### Phase 5 — Auto-Fix Engine
- [ ] Fix template system (`core/fix_generator.py`)
- [ ] CWE-mapped fix templates (100+ fixes)
- [ ] SQL injection → parameterized queries
- [ ] XSS → output encoding
- [ ] Command injection → subprocess with list args
- [ ] Hardcoded secrets → environment variable references
- [ ] Weak crypto → strong algorithm replacements
- [ ] Diff-based fix output

### Phase 6 — MCP Server
- [ ] MCP server implementation (`mcp_server/server.py`) — stdio transport
- [ ] All 11 tool handlers (`mcp_server/tools.py`)
- [ ] Input/output JSON schemas (`mcp_server/schemas.py`)
- [ ] Claude Code integration (`.claude/settings.json` config)
- [ ] Cursor/Windsurf/Cline integration support
- [ ] Init command for client setup

### Phase 7 — Semantic Code Review (LLM-Powered)
- [ ] Semantic reviewer (`core/semantic_reviewer.py`)
- [ ] Claude API integration (Anthropic SDK)
- [ ] Context-aware analysis (project type detection)
- [ ] Intent classification for ambiguous patterns
- [ ] OpenAI provider support (optional)
- [ ] Cost optimization (batch, caching, minimal prompts)

### Phase 8 — Multi-Language Rules
- [ ] Java rules (50+ rules)
- [ ] Go rules (50+ rules)
- [ ] PHP rules (50+ rules)
- [ ] Ruby rules (30+ rules)
- [ ] C/C++ rules (40+ rules)
- [ ] Dockerfile rules (30+ rules)
- [ ] Terraform rules (30+ rules)
- [ ] Kubernetes manifest rules (30+ rules)
- [ ] Common cross-language rules (secrets, credentials, API keys)

### Phase 9 — Reporting & CI/CD
- [ ] SARIF 2.1.0 exporter (`integrations/sarif_exporter.py`)
- [ ] GitHub Actions integration (`integrations/github_actions.py`)
- [ ] GitLab CI integration (`integrations/gitlab_ci.py`)
- [ ] HTML report with executive summary and code snippets
- [ ] Git diff scanning (only scan changed files)
- [ ] Pre-commit hook support
- [ ] Exit codes for CI pass/fail

### Phase 10 — Testing & Benchmarks
- [ ] Unit tests for all core engines
- [ ] Rule validation tests (no regex errors, valid CWEs)
- [ ] Vulnerable code fixtures per language
- [ ] Precision/recall benchmarks against known CVE datasets
- [ ] MCP server integration tests
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Performance benchmarks (files/second, memory usage)

---

## Key Dependencies

```
click>=8.0                # CLI framework
pyyaml>=6.0               # YAML rule parsing
rich>=13.0                # Terminal UI, syntax highlighting
structlog>=23.0           # Structured logging
tree-sitter>=0.20         # Multi-language AST parsing
tree-sitter-python        # Python grammar
tree-sitter-javascript    # JavaScript grammar
anthropic>=0.30           # Claude API SDK (semantic review)
pybloom-live>=4.0         # Bloom filter for package verification
python-Levenshtein>=0.21  # Typosquatting detection
jinja2>=3.1               # Report templating
mcp>=1.0                  # Model Context Protocol SDK
```

---

## Coding Conventions

- Python 3.10+ (use `match/case`, `X | Y` union types)
- Type hints on all public functions
- Rule file naming: `{language}.yaml` (e.g., `python.yaml`, `javascript.yaml`)
- Rule ID format: `{language}.{category}.{rule-name}` (e.g., `python.injection.sql-format-string`)
- Use `structlog` for all logging — never bare `print()`
- Tests mirror source layout under `tests/`
- All security patterns mapped to CWE IDs
- OWASP Top 10 2021 mapping where applicable

---

## Running the Tool

```bash
# Scan a single file
python main.py scan --file app.py

# Scan an entire project
python main.py scan --project ./myapp --profile full

# Check a specific package
python main.py check-package requests --registry pypi

# Scan all imports in a file
python main.py scan-packages --file requirements.txt

# Detect prompt injection
python main.py scan-prompt --text "Ignore previous instructions and..."

# Generate HTML report
python main.py report --input results.json --format html

# Scan git diff only
python main.py scan-diff --base main

# Start MCP server (for Claude Code)
python main.py mcp-serve

# Run semantic code review
python main.py review --file app.py --provider claude
```

---

## MCP Server Configuration

### Claude Code
```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "python",
      "args": ["path/to/main.py", "mcp-serve"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-..."
      }
    }
  }
}
```

### Cursor / Windsurf
```json
{
  "mcp": {
    "servers": {
      "security-scanner": {
        "command": "python",
        "args": ["path/to/main.py", "mcp-serve"]
      }
    }
  }
}
```
