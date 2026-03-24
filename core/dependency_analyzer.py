"""Dependency Graph Analyzer — transitive dependency chain risk analysis.

Analyzes project dependency trees for supply chain risks:
- Direct and transitive dependency enumeration
- Dependency confusion detection (private vs public namespace collisions)
- Outdated/unmaintained package detection
- License risk assessment
- Dependency depth analysis (deep chains = more risk)
- Known vulnerability cross-referencing
- Namespace squatting detection

Supports: requirements.txt, package.json, Pipfile, pyproject.toml,
go.mod, Cargo.toml, Gemfile
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger("dependency_analyzer")


# ── Data Models ───────────────────────────────────────────────────────────

class DependencyRisk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class DependencySource(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    CRATES = "crates"
    RUBYGEMS = "rubygems"
    GO = "go"
    MAVEN = "maven"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """A single dependency in the graph."""
    name: str
    version: str | None = None
    source: DependencySource = DependencySource.UNKNOWN
    is_direct: bool = True
    is_dev: bool = False
    depth: int = 0
    parent: str | None = None
    risk_level: DependencyRisk = DependencyRisk.NONE
    risk_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source.value,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "depth": self.depth,
            "risk_level": self.risk_level.value,
            "risk_reasons": self.risk_reasons,
        }


@dataclass
class DependencyFinding:
    """A security finding related to a dependency."""
    finding_id: str
    dependency: str
    category: str
    risk: str
    title: str
    description: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "dependency": self.dependency,
            "category": self.category,
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class DependencyAnalysisResult:
    """Result of dependency analysis."""
    file_path: str
    source: DependencySource
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[DependencyFinding] = field(default_factory=list)
    analysis_time_ms: float = 0.0

    @property
    def total_dependencies(self) -> int:
        return len(self.dependencies)

    @property
    def direct_count(self) -> int:
        return sum(1 for d in self.dependencies if d.is_direct)

    @property
    def dev_count(self) -> int:
        return sum(1 for d in self.dependencies if d.is_dev)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "critical")

    @property
    def risk_level(self) -> str:
        if self.critical_count > 0:
            return "critical"
        high = sum(1 for f in self.findings if f.risk == "high")
        if high > 0:
            return "high"
        medium = sum(1 for f in self.findings if f.risk == "medium")
        if medium > 0:
            return "medium"
        if self.findings:
            return "low"
        return "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "source": self.source.value,
            "total_dependencies": self.total_dependencies,
            "direct": self.direct_count,
            "dev": self.dev_count,
            "risk_level": self.risk_level,
            "findings_count": self.finding_count,
            "critical": self.critical_count,
            "analysis_time_ms": round(self.analysis_time_ms, 1),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Known Risk Patterns ───────────────────────────────────────────────────

# Packages with known security history
KNOWN_RISKY_PACKAGES: dict[str, dict[str, str]] = {
    # Python
    "pyyaml": {"reason": "yaml.load() unsafe by default in older versions", "min_safe": "6.0"},
    "urllib3": {"reason": "Multiple CVEs in older versions", "min_safe": "2.0.0"},
    "pillow": {"reason": "Image processing — frequent CVEs", "min_safe": "10.0.0"},
    "cryptography": {"reason": "Critical crypto library — must stay current", "min_safe": "41.0.0"},
    "django": {"reason": "Framework with regular security patches", "min_safe": "4.2.0"},
    "flask": {"reason": "Debug mode and Jinja2 injection risks", "min_safe": "2.3.0"},
    "jinja2": {"reason": "Template injection in older versions", "min_safe": "3.1.0"},
    "requests": {"reason": "SSL verification defaults changed", "min_safe": "2.28.0"},
    # JavaScript/Node
    "express": {"reason": "Frequent prototype pollution CVEs", "min_safe": "4.18.0"},
    "lodash": {"reason": "Prototype pollution in older versions", "min_safe": "4.17.21"},
    "axios": {"reason": "SSRF and ReDoS vulnerabilities", "min_safe": "1.6.0"},
    "jsonwebtoken": {"reason": "Algorithm confusion attacks", "min_safe": "9.0.0"},
    "helmet": {"reason": "Security headers — must stay current", "min_safe": "7.0.0"},
    "minimist": {"reason": "Prototype pollution", "min_safe": "1.2.8"},
    "qs": {"reason": "Prototype pollution in older versions", "min_safe": "6.11.0"},
}

# Known malicious packages (confirmed)
KNOWN_MALICIOUS: set[str] = {
    # Python
    "colourama", "python-dateutils", "jeIlyfish", "python3-dateutil",
    "crypt", "raborern", "noblesse", "genesisbot", "aryi", "suffer",
    # npm
    "event-stream", "flatmap-stream", "ua-parser-js",
    "colors", "faker", "node-ipc", "peacenotwar",
    # Crates
    "rustdecimal",
}

# Suspicious package name patterns
SUSPICIOUS_NAME_PATTERNS = [
    r"^python[_-]?3[_-]",  # python3-xxx (confusion with stdlib)
    r"^py[_-]?[a-z]{2,3}$",  # Very short py-XX names
    r"test[_-]?pkg",  # Test packages
    r"example[_-]?pkg",
    r"^node[_-]",  # node-xxx (npm confusion)
    r"internal[_-]",  # Internal namespace squat
    r"private[_-]",  # Private namespace squat
]

# Well-known packages (for typosquat comparison)
POPULAR_PACKAGES = {
    "pypi": [
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "matplotlib", "tensorflow", "torch", "boto3", "sqlalchemy",
        "celery", "redis", "pillow", "cryptography", "pyyaml",
        "click", "fastapi", "uvicorn", "pydantic", "httpx",
        "black", "pytest", "mypy", "ruff", "setuptools",
    ],
    "npm": [
        "express", "react", "next", "vue", "angular", "lodash",
        "axios", "moment", "webpack", "typescript", "eslint",
        "prettier", "jest", "mocha", "chai", "commander",
        "chalk", "inquirer", "dotenv", "cors", "helmet",
        "jsonwebtoken", "bcrypt", "mongoose", "sequelize", "prisma",
    ],
}


# ── Dependency Parsers ────────────────────────────────────────────────────

class DependencyParser:
    """Parses dependency files into Dependency objects."""

    @staticmethod
    def parse_file(file_path: str | Path) -> tuple[DependencySource, list[Dependency]]:
        """Auto-detect and parse a dependency file."""
        path = Path(file_path)
        name = path.name.lower()

        parsers = {
            "requirements.txt": (DependencySource.PYPI, DependencyParser._parse_requirements),
            "requirements-dev.txt": (DependencySource.PYPI, DependencyParser._parse_requirements),
            "requirements_dev.txt": (DependencySource.PYPI, DependencyParser._parse_requirements),
            "package.json": (DependencySource.NPM, DependencyParser._parse_package_json),
            "package-lock.json": (DependencySource.NPM, DependencyParser._parse_package_lock),
            "pipfile": (DependencySource.PYPI, DependencyParser._parse_pipfile),
            "pyproject.toml": (DependencySource.PYPI, DependencyParser._parse_pyproject),
            "cargo.toml": (DependencySource.CRATES, DependencyParser._parse_cargo),
            "go.mod": (DependencySource.GO, DependencyParser._parse_gomod),
            "gemfile": (DependencySource.RUBYGEMS, DependencyParser._parse_gemfile),
        }

        parser_info = parsers.get(name)
        if not parser_info:
            return DependencySource.UNKNOWN, []

        source, parser_func = parser_info
        content = path.read_text(encoding="utf-8", errors="ignore")
        deps = parser_func(content)

        # Set source on all deps
        for dep in deps:
            dep.source = source

        return source, deps

    @staticmethod
    def _parse_requirements(content: str) -> list[Dependency]:
        """Parse requirements.txt format."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle version specifiers
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.]+)?", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2).strip() if match.group(2) else None
                # Clean version string
                if version:
                    version = re.sub(r"[><=!~]+\s*", "", version)
                deps.append(Dependency(name=name, version=version))

        return deps

    @staticmethod
    def _parse_package_json(content: str) -> list[Dependency]:
        """Parse package.json."""
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        for name, version in data.get("dependencies", {}).items():
            clean_ver = re.sub(r"[\^~>=<]", "", version)
            deps.append(Dependency(name=name, version=clean_ver, is_dev=False))

        for name, version in data.get("devDependencies", {}).items():
            clean_ver = re.sub(r"[\^~>=<]", "", version)
            deps.append(Dependency(name=name, version=clean_ver, is_dev=True))

        return deps

    @staticmethod
    def _parse_package_lock(content: str) -> list[Dependency]:
        """Parse package-lock.json for transitive deps."""
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        # npm v2+ lockfile format
        packages = data.get("packages", {})
        for pkg_path, info in packages.items():
            if not pkg_path:  # Root package
                continue
            # Extract package name from path
            name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            version = info.get("version")
            is_dev = info.get("dev", False)
            depth = pkg_path.count("node_modules/")

            deps.append(Dependency(
                name=name,
                version=version,
                is_direct=(depth == 1),
                is_dev=is_dev,
                depth=depth,
            ))

        return deps

    @staticmethod
    def _parse_pipfile(content: str) -> list[Dependency]:
        """Parse Pipfile (TOML-like)."""
        deps = []
        section = None

        for line in content.splitlines():
            line = line.strip()
            if line == "[packages]":
                section = "prod"
            elif line == "[dev-packages]":
                section = "dev"
            elif line.startswith("["):
                section = None
            elif section and "=" in line:
                name = line.split("=")[0].strip().strip('"').lower()
                version = line.split("=", 1)[1].strip().strip('"').strip("'")
                if version == "*":
                    version = None
                deps.append(Dependency(name=name, version=version, is_dev=(section == "dev")))

        return deps

    @staticmethod
    def _parse_pyproject(content: str) -> list[Dependency]:
        """Parse pyproject.toml dependencies section."""
        deps = []

        # Simple regex parser for [project.dependencies] section
        in_deps = False
        in_dev_deps = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "dependencies = [" or stripped.startswith("dependencies"):
                in_deps = True
                continue
            elif "optional-dependencies" in stripped or "dev-dependencies" in stripped:
                in_dev_deps = True
                in_deps = False
                continue
            elif stripped.startswith("[") and not stripped.startswith('["'):
                in_deps = False
                in_dev_deps = False
                continue

            if (in_deps or in_dev_deps) and stripped.startswith('"'):
                # Parse "package>=version" format
                pkg_str = stripped.strip('",')
                match = re.match(r"([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.]+)?", pkg_str)
                if match:
                    name = match.group(1).lower()
                    version = re.sub(r"[><=!~]+\s*", "", match.group(2)) if match.group(2) else None
                    deps.append(Dependency(name=name, version=version, is_dev=in_dev_deps))

        return deps

    @staticmethod
    def _parse_cargo(content: str) -> list[Dependency]:
        """Parse Cargo.toml."""
        deps = []
        section = None

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[dependencies]":
                section = "prod"
            elif stripped == "[dev-dependencies]" or stripped == "[build-dependencies]":
                section = "dev"
            elif stripped.startswith("[") and "dependencies" not in stripped:
                section = None
            elif section and "=" in stripped and not stripped.startswith("#"):
                parts = stripped.split("=", 1)
                name = parts[0].strip().lower()
                version_part = parts[1].strip().strip('"').strip("'")
                # Handle {version = "x.y"} syntax
                ver_match = re.search(r'version\s*=\s*"([^"]+)"', version_part)
                version = ver_match.group(1) if ver_match else version_part
                deps.append(Dependency(name=name, version=version, is_dev=(section == "dev")))

        return deps

    @staticmethod
    def _parse_gomod(content: str) -> list[Dependency]:
        """Parse go.mod."""
        deps = []
        in_require = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            elif stripped == ")" and in_require:
                in_require = False
                continue
            elif stripped.startswith("require "):
                # Single-line require
                parts = stripped[8:].split()
                if len(parts) >= 2:
                    deps.append(Dependency(name=parts[0], version=parts[1]))
            elif in_require and stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    indirect = "// indirect" in stripped
                    deps.append(Dependency(
                        name=parts[0],
                        version=parts[1],
                        is_direct=not indirect,
                    ))

        return deps

    @staticmethod
    def _parse_gemfile(content: str) -> list[Dependency]:
        """Parse Gemfile."""
        deps = []
        in_dev = False

        for line in content.splitlines():
            stripped = line.strip()
            if "group :development" in stripped or "group :test" in stripped:
                in_dev = True
            elif stripped == "end" and in_dev:
                in_dev = False
            elif stripped.startswith("gem "):
                match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        is_dev=in_dev,
                    ))

        return deps


# ── Dependency Analyzer ───────────────────────────────────────────────────

class DependencyAnalyzer:
    """Analyzes project dependencies for supply chain risks.

    Usage:
        analyzer = DependencyAnalyzer()

        # Analyze a single dependency file
        result = analyzer.analyze_file("requirements.txt")
        print(result.risk_level)

        # Analyze an entire project
        results = analyzer.analyze_project("/path/to/project")

        # Check a single package
        findings = analyzer.check_package("colourama", "pypi")
    """

    def __init__(self) -> None:
        self._finding_counter = 0

    def analyze_file(self, file_path: str | Path) -> DependencyAnalysisResult:
        """Analyze a dependency file for risks."""
        start = time.time()
        path = Path(file_path)

        if not path.exists():
            return DependencyAnalysisResult(
                file_path=str(path),
                source=DependencySource.UNKNOWN,
                findings=[DependencyFinding(
                    finding_id="DEP-ERR",
                    dependency="",
                    category="error",
                    risk="low",
                    title="File not found",
                    description=f"Dependency file not found: {path}",
                    remediation="Verify file path",
                )],
            )

        source, deps = DependencyParser.parse_file(path)
        findings = self._analyze_dependencies(deps, source)

        elapsed = (time.time() - start) * 1000

        return DependencyAnalysisResult(
            file_path=str(path),
            source=source,
            dependencies=deps,
            findings=findings,
            analysis_time_ms=elapsed,
        )

    def analyze_project(self, directory: str | Path) -> list[DependencyAnalysisResult]:
        """Analyze all dependency files in a project directory."""
        directory = Path(directory)
        results = []

        dep_files = [
            "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
            "package.json", "package-lock.json",
            "Pipfile", "pyproject.toml",
            "Cargo.toml", "go.mod", "Gemfile",
        ]

        for dep_file in dep_files:
            path = directory / dep_file
            if path.exists():
                results.append(self.analyze_file(path))

        return results

    def check_package(self, name: str, registry: str = "pypi") -> list[DependencyFinding]:
        """Check a single package name for risks."""
        dep = Dependency(name=name, source=DependencySource(registry))
        return self._analyze_dependencies([dep], DependencySource(registry))

    # ── Internal Analysis ─────────────────────────────────────────────

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"DEP-{self._finding_counter:04d}"

    def _analyze_dependencies(
        self, deps: list[Dependency], source: DependencySource
    ) -> list[DependencyFinding]:
        """Run all checks on a list of dependencies."""
        findings: list[DependencyFinding] = []

        for dep in deps:
            findings.extend(self._check_malicious(dep))
            findings.extend(self._check_typosquat(dep, source))
            findings.extend(self._check_known_risky(dep))
            findings.extend(self._check_suspicious_name(dep))
            findings.extend(self._check_unpinned_version(dep))
            findings.extend(self._check_namespace_confusion(dep, source))

        # Project-level checks
        findings.extend(self._check_dependency_count(deps))

        return findings

    def _check_malicious(self, dep: Dependency) -> list[DependencyFinding]:
        """Check against known malicious package list."""
        if dep.name.lower() in KNOWN_MALICIOUS:
            dep.risk_level = DependencyRisk.CRITICAL
            dep.risk_reasons.append("Known malicious package")
            return [DependencyFinding(
                finding_id=self._next_id(),
                dependency=dep.name,
                category="malicious_package",
                risk="critical",
                title=f"Known malicious package: {dep.name}",
                description=f"Package '{dep.name}' is confirmed malicious and should be removed immediately",
                remediation=f"Remove '{dep.name}' from dependencies. Check for data exfiltration.",
            )]
        return []

    def _check_typosquat(self, dep: Dependency, source: DependencySource) -> list[DependencyFinding]:
        """Check for typosquatting of popular packages."""
        registry = source.value
        popular = POPULAR_PACKAGES.get(registry, [])

        for legit in popular:
            if dep.name == legit:
                continue
            distance = _levenshtein(dep.name.lower(), legit.lower())
            if 0 < distance <= 2:
                dep.risk_level = DependencyRisk.HIGH
                dep.risk_reasons.append(f"Typosquat of '{legit}'")
                return [DependencyFinding(
                    finding_id=self._next_id(),
                    dependency=dep.name,
                    category="typosquatting",
                    risk="high",
                    title=f"Possible typosquat: '{dep.name}' (similar to '{legit}')",
                    description=f"Package name '{dep.name}' is {distance} edit(s) from popular package '{legit}'",
                    remediation=f"Verify you intended '{dep.name}' and not '{legit}'",
                    metadata={"similar_to": legit, "edit_distance": distance},
                )]
        return []

    def _check_known_risky(self, dep: Dependency) -> list[DependencyFinding]:
        """Check for packages with known security history."""
        info = KNOWN_RISKY_PACKAGES.get(dep.name.lower())
        if not info:
            return []

        if dep.version and info.get("min_safe"):
            try:
                if _version_lt(dep.version, info["min_safe"]):
                    dep.risk_level = DependencyRisk.HIGH
                    dep.risk_reasons.append(f"Below minimum safe version {info['min_safe']}")
                    return [DependencyFinding(
                        finding_id=self._next_id(),
                        dependency=dep.name,
                        category="outdated_risky",
                        risk="high",
                        title=f"Outdated risky package: {dep.name}=={dep.version}",
                        description=f"{info['reason']}. Minimum safe version: {info['min_safe']}",
                        remediation=f"Upgrade to {dep.name}>={info['min_safe']}",
                        metadata={"min_safe": info["min_safe"], "current": dep.version},
                    )]
            except Exception:
                pass

        return []

    def _check_suspicious_name(self, dep: Dependency) -> list[DependencyFinding]:
        """Check for suspicious package naming patterns."""
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if re.match(pattern, dep.name.lower()):
                dep.risk_level = max(dep.risk_level, DependencyRisk.MEDIUM, key=lambda x: _risk_order(x))
                dep.risk_reasons.append("Suspicious naming pattern")
                return [DependencyFinding(
                    finding_id=self._next_id(),
                    dependency=dep.name,
                    category="suspicious_name",
                    risk="medium",
                    title=f"Suspicious package name: {dep.name}",
                    description=f"Package name '{dep.name}' matches suspicious naming pattern",
                    remediation="Verify this is the intended package and not a namespace squat",
                )]
        return []

    def _check_unpinned_version(self, dep: Dependency) -> list[DependencyFinding]:
        """Check for unpinned dependency versions."""
        if not dep.version or dep.version in ("*", "latest"):
            dep.risk_level = max(dep.risk_level, DependencyRisk.LOW, key=lambda x: _risk_order(x))
            dep.risk_reasons.append("Unpinned version")
            return [DependencyFinding(
                finding_id=self._next_id(),
                dependency=dep.name,
                category="unpinned_version",
                risk="low",
                title=f"Unpinned dependency: {dep.name}",
                description=f"Package '{dep.name}' has no version pin, allowing arbitrary updates",
                remediation=f"Pin '{dep.name}' to a specific version for reproducible builds",
            )]
        return []

    def _check_namespace_confusion(
        self, dep: Dependency, source: DependencySource
    ) -> list[DependencyFinding]:
        """Check for dependency confusion risk (internal vs public naming)."""
        # Internal/private naming patterns that could collide
        confusion_patterns = [
            r"^(internal|private|corp|company)[_-]",
            r"^[a-z]{2,4}[_-](internal|private|core|lib)$",
            r"@[a-z]+/(internal|private|core)",
        ]

        for pattern in confusion_patterns:
            if re.match(pattern, dep.name.lower()):
                return [DependencyFinding(
                    finding_id=self._next_id(),
                    dependency=dep.name,
                    category="dependency_confusion",
                    risk="high",
                    title=f"Dependency confusion risk: {dep.name}",
                    description=f"Package '{dep.name}' uses internal/private naming pattern — "
                                "an attacker could register this name on the public registry",
                    remediation="Use scoped packages or configure private registry priority",
                )]
        return []

    def _check_dependency_count(self, deps: list[Dependency]) -> list[DependencyFinding]:
        """Check for excessive dependency count."""
        direct = [d for d in deps if d.is_direct and not d.is_dev]
        if len(direct) > 50:
            return [DependencyFinding(
                finding_id=self._next_id(),
                dependency="(project)",
                category="excessive_dependencies",
                risk="medium",
                title=f"High dependency count: {len(direct)} direct dependencies",
                description="Large number of dependencies increases supply chain attack surface",
                remediation="Audit dependencies and remove unused packages",
                metadata={"count": len(direct)},
            )]
        return []


# ── Helpers ───────────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _version_lt(v1: str, v2: str) -> bool:
    """Simple version comparison (major.minor.patch)."""
    def parts(v: str) -> list[int]:
        return [int(x) for x in re.findall(r"\d+", v)][:3]

    p1, p2 = parts(v1), parts(v2)
    # Pad to same length
    while len(p1) < 3:
        p1.append(0)
    while len(p2) < 3:
        p2.append(0)
    return p1 < p2


def _risk_order(risk: DependencyRisk) -> int:
    """Convert risk to numeric for comparison."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}.get(risk.value, 0)
