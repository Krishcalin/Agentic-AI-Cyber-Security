"""Package hallucination detection engine.

Verifies that imported packages actually exist on their registries,
detects typosquatting attempts, and flags known malicious packages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.bloom_filter import BloomFilter
from core.import_extractor import ExtractedImport, ImportExtractor
from core.models import Confidence, FileResult, Finding, Severity

log = structlog.get_logger("package_checker")


# ──────────────────────────────────────────────────────────────────────────
# Common typosquatting substitutions
# ──────────────────────────────────────────────────────────────────────────

TYPOSQUAT_SUBSTITUTIONS: list[tuple[str, str]] = [
    ("-", "_"), ("_", "-"), (".", "-"), ("-", ""),
    ("py", ""), ("", "py"),
    ("python-", ""), ("", "python-"),
    ("js", ""), ("", "js"),
    ("node-", ""), ("", "node-"),
]

# Popular packages — if a package is very close to one of these, flag it
POPULAR_PYPI: set[str] = {
    "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
    "tensorflow", "torch", "sklearn", "scikit-learn", "pillow", "boto3",
    "sqlalchemy", "celery", "redis", "pymongo", "psycopg2", "cryptography",
    "paramiko", "fabric", "scrapy", "beautifulsoup4", "lxml", "pyyaml",
    "jinja2", "click", "fastapi", "uvicorn", "gunicorn", "pytest",
    "setuptools", "pip", "wheel", "twine", "black", "ruff", "mypy",
    "httpx", "aiohttp", "pydantic", "rich", "typer", "structlog",
    "anthropic", "openai", "langchain", "transformers", "huggingface-hub",
    "aws-cdk-lib", "boto3", "botocore", "google-cloud-storage",
    "azure-storage-blob", "stripe", "sentry-sdk",
}

POPULAR_NPM: set[str] = {
    "express", "react", "react-dom", "next", "vue", "angular", "axios",
    "lodash", "moment", "dayjs", "webpack", "babel", "typescript",
    "eslint", "prettier", "jest", "mocha", "chai", "passport", "jsonwebtoken",
    "mongoose", "sequelize", "prisma", "socket.io", "cors", "helmet",
    "dotenv", "nodemon", "pm2", "commander", "yargs", "chalk",
    "uuid", "bcrypt", "crypto-js", "node-fetch", "cheerio", "puppeteer",
    "sharp", "multer", "body-parser", "cookie-parser", "winston",
    "openai", "langchain", "@anthropic-ai/sdk",
}


@dataclass
class PackageCheckResult:
    """Result of checking a single package."""
    package_name: str
    registry: str
    exists: bool = True
    is_typosquat: bool = False
    is_malicious: bool = False
    similar_to: str = ""
    distance: int = 0
    risk_level: str = "safe"   # safe, low, medium, high, critical
    reason: str = ""


class PackageChecker:
    """Verifies package legitimacy and detects hallucinations."""

    def __init__(self, data_dir: str = "data", known_malicious_path: str = "data/known_malicious.yaml") -> None:
        self.data_dir = Path(data_dir)
        self._bloom_filters: dict[str, BloomFilter] = {}
        self._known_malicious: dict[str, set[str]] = {}
        self._extractor = ImportExtractor()
        self._load_malicious_db(known_malicious_path)

    def _load_malicious_db(self, path: str) -> None:
        """Load known malicious package database."""
        p = Path(path)
        if p.exists():
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
                if data and "packages" in data:
                    for entry in data["packages"]:
                        registry = entry.get("registry", "pypi")
                        name = entry.get("name", "")
                        if name:
                            self._known_malicious.setdefault(registry, set()).add(name.lower())
                log.info("malicious_db_loaded", entries=sum(len(v) for v in self._known_malicious.values()))
            except Exception as e:
                log.warning("malicious_db_load_failed", error=str(e))

    def load_bloom_filter(self, registry: str, path: str) -> None:
        """Load a pre-built bloom filter for a registry."""
        try:
            self._bloom_filters[registry] = BloomFilter.load(path)
            log.info("bloom_filter_loaded", registry=registry, items=len(self._bloom_filters[registry]))
        except Exception as e:
            log.warning("bloom_filter_load_failed", registry=registry, error=str(e))

    def build_bloom_filter(self, registry: str, packages: list[str], save_path: str | None = None) -> BloomFilter:
        """Build a bloom filter from a list of package names."""
        bf = BloomFilter(expected_items=max(len(packages), 1000))
        bf.add_many([p.lower() for p in packages])
        self._bloom_filters[registry] = bf

        if save_path:
            bf.save(save_path)
            log.info("bloom_filter_built", registry=registry, packages=len(packages), path=save_path)

        return bf

    def check_package(self, package_name: str, registry: str = "pypi") -> PackageCheckResult:
        """Check a single package for existence, typosquatting, and malicious status."""
        name_lower = package_name.lower()
        result = PackageCheckResult(package_name=package_name, registry=registry)

        # Check malicious database first
        if name_lower in self._known_malicious.get(registry, set()):
            result.is_malicious = True
            result.exists = True
            result.risk_level = "critical"
            result.reason = "Package is in known malicious package database"
            return result

        # Check bloom filter if available
        bf = self._bloom_filters.get(registry)
        if bf is not None:
            if name_lower not in bf:
                result.exists = False
                result.risk_level = "high"
                result.reason = "Package not found in registry"

                # Check for typosquatting
                typosquat = self._check_typosquat(name_lower, registry)
                if typosquat:
                    result.is_typosquat = True
                    result.similar_to = typosquat[0]
                    result.distance = typosquat[1]
                    result.risk_level = "critical"
                    result.reason = f"Possible typosquat of '{typosquat[0]}' (distance: {typosquat[1]})"

                return result

        # No bloom filter — check against popular packages for typosquatting
        popular = POPULAR_PYPI if registry == "pypi" else POPULAR_NPM if registry == "npm" else set()
        if popular:
            typosquat = self._find_similar(name_lower, popular)
            if typosquat and name_lower not in popular:
                result.is_typosquat = True
                result.similar_to = typosquat[0]
                result.distance = typosquat[1]
                result.risk_level = "medium"
                result.reason = f"Similar to popular package '{typosquat[0]}' (distance: {typosquat[1]})"

        return result

    def check_file_imports(self, file_path: str) -> list[PackageCheckResult]:
        """Extract and check all imports from a file."""
        imports = self._extractor.extract_from_file(file_path)
        results: list[PackageCheckResult] = []
        for imp in imports:
            result = self.check_package(imp.package_name, imp.registry)
            results.append(result)
        return results

    def scan_file(self, file_path: str) -> FileResult:
        """Scan a file for package hallucinations and return findings."""
        imports = self._extractor.extract_from_file(file_path)
        file_result = FileResult(file_path=file_path, language="")

        for imp in imports:
            check = self.check_package(imp.package_name, imp.registry)

            if check.is_malicious:
                file_result.findings.append(Finding(
                    rule_id=f"package.malicious.{imp.registry}",
                    message=f"MALICIOUS PACKAGE: '{imp.package_name}' is in the known malicious package database",
                    severity=Severity.ERROR,
                    file_path=file_path,
                    line_number=imp.line_number,
                    line_content=imp.full_import,
                    cwe="CWE-829",
                    owasp="A06:2021",
                    confidence=Confidence.HIGH,
                    category="package",
                    metadata={"registry": imp.registry, "risk": "critical"},
                ))
            elif check.is_typosquat:
                file_result.findings.append(Finding(
                    rule_id=f"package.typosquat.{imp.registry}",
                    message=f"Possible typosquat: '{imp.package_name}' is similar to '{check.similar_to}' (distance: {check.distance})",
                    severity=Severity.ERROR,
                    file_path=file_path,
                    line_number=imp.line_number,
                    line_content=imp.full_import,
                    cwe="CWE-829",
                    confidence=Confidence.MEDIUM,
                    category="package",
                    metadata={"registry": imp.registry, "similar_to": check.similar_to, "distance": check.distance},
                ))
            elif not check.exists:
                file_result.findings.append(Finding(
                    rule_id=f"package.not-found.{imp.registry}",
                    message=f"Package '{imp.package_name}' not found on {imp.registry} — possible hallucination",
                    severity=Severity.WARNING,
                    file_path=file_path,
                    line_number=imp.line_number,
                    line_content=imp.full_import,
                    cwe="CWE-829",
                    confidence=Confidence.MEDIUM,
                    category="package",
                    metadata={"registry": imp.registry},
                ))

        return file_result

    # ── Typosquatting detection ─────────────────────────────────────────────

    def _check_typosquat(self, name: str, registry: str) -> tuple[str, int] | None:
        """Check against popular packages and bloom filter for typosquats."""
        popular = POPULAR_PYPI if registry == "pypi" else POPULAR_NPM if registry == "npm" else set()
        return self._find_similar(name, popular)

    def _find_similar(self, name: str, corpus: set[str], max_distance: int = 2) -> tuple[str, int] | None:
        """Find the closest package in a corpus using edit distance."""
        best: tuple[str, int] | None = None

        for candidate in corpus:
            if candidate == name:
                continue
            dist = self._levenshtein(name, candidate)
            if dist <= max_distance:
                if best is None or dist < best[1]:
                    best = (candidate, dist)

        # Also check substitution patterns
        for old, new in TYPOSQUAT_SUBSTITUTIONS:
            if old in name:
                variant = name.replace(old, new, 1)
                if variant in corpus and variant != name:
                    return (variant, 1)

        return best

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return PackageChecker._levenshtein(s2, s1)
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
