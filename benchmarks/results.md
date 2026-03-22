# Benchmark Results

## Rule Coverage

| Language | Rules | Fixture Findings | Key CWEs |
|----------|-------|-----------------|----------|
| Python | 46 | 10+ | CWE-89, 78, 95, 502, 328, 798, 295 |
| JavaScript | 32 | 8+ | CWE-89, 79, 95, 798, 295, 328 |
| Java | 25 | 5+ | CWE-89, 78, 328, 502 |
| Go | 16 | 4+ | CWE-89, 78, 328, 295 |
| PHP | 18 | 6+ | CWE-89, 78, 95, 798, 328 |
| C/C++ | 17 | N/A | CWE-120, 134, 78, 330 |
| Dockerfile | 16 | 3+ | CWE-798, 829, 250 |
| Terraform | 16 | 5+ | CWE-284, 250, 311 |
| Kubernetes | 22 | 5+ | CWE-250, 798, 284 |
| Ruby | 14 | N/A | CWE-89, 78, 95, 502 |
| **Total** | **237** | **50+** | |

## Engine Coverage

| Engine | Description | Unique Findings |
|--------|-------------|----------------|
| Pattern Matcher | Regex-based, all languages | Baseline |
| AST Analyzer | Python deep analysis | f-string SQL, subprocess.shell, hardcoded creds |
| Taint Tracker | Source → sink flow | Flask input → SQL, input → eval |
| Package Checker | Registry verification | Hallucinated/malicious packages |
| Prompt Scanner | 60+ injection patterns | Jailbreaks, exfiltration, tool abuse |
| Semantic Reviewer | LLM context-aware | Intent-based severity adjustment |

## Precision Targets

| Metric | Target | Notes |
|--------|--------|-------|
| True Positive Rate | >90% | Against vulnerable fixtures |
| False Positive Rate | <5% | Against clean code |
| Comment Skip Rate | 100% | Comments never flagged |
| Parameterized SQL | 0 FP | Safe queries not flagged |

## Performance

Measured on fixtures directory (~8 files, ~500 lines):

| Metric | Value |
|--------|-------|
| Scan time (pattern only) | <100ms |
| Scan time (pattern + AST + taint) | <500ms |
| Rules loaded | 237 |
| Memory usage | <50MB |
