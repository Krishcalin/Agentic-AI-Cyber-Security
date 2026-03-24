"""SBOM Generator — generates Software Bill of Materials in CycloneDX format.

Produces CycloneDX 1.5 JSON SBOM from project dependency files:
- requirements.txt, Pipfile, pyproject.toml (Python)
- package.json, package-lock.json (Node.js)
- go.mod (Go), Cargo.toml (Rust), Gemfile (Ruby)

Covers ATLAS technique AML.T0010 — ML Supply Chain Compromise.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from core.dependency_analyzer import DependencyAnalyzer, DependencyParser, DependencySource

log = structlog.get_logger("sbom_generator")


@dataclass
class SBOMComponent:
    """A component in the SBOM."""
    name: str
    version: str | None
    purl: str  # Package URL
    component_type: str = "library"
    scope: str = "required"  # required, optional, excluded
    source: str = ""
    license_id: str | None = None

    def to_cyclonedx(self) -> dict[str, Any]:
        component: dict[str, Any] = {
            "type": self.component_type,
            "name": self.name,
            "purl": self.purl,
        }
        if self.version:
            component["version"] = self.version
        if self.scope != "required":
            component["scope"] = self.scope
        if self.license_id:
            component["licenses"] = [{"license": {"id": self.license_id}}]
        # BOM reference
        component["bom-ref"] = self.purl
        return component


@dataclass
class SBOMResult:
    """Generated SBOM result."""
    format_type: str = "CycloneDX"
    spec_version: str = "1.5"
    components: list[SBOMComponent] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    generation_time_ms: float = 0.0

    @property
    def component_count(self) -> int:
        return len(self.components)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format_type,
            "spec_version": self.spec_version,
            "components": self.component_count,
            "source_files": self.source_files,
            "generation_time_ms": round(self.generation_time_ms, 1),
        }


# ── PURL Builders ─────────────────────────────────────────────────────────

def _build_purl(name: str, version: str | None, source: DependencySource) -> str:
    """Build a Package URL (PURL) for a component."""
    purl_types = {
        DependencySource.PYPI: "pypi",
        DependencySource.NPM: "npm",
        DependencySource.CRATES: "cargo",
        DependencySource.GO: "golang",
        DependencySource.RUBYGEMS: "gem",
        DependencySource.MAVEN: "maven",
    }
    purl_type = purl_types.get(source, "generic")
    purl = f"pkg:{purl_type}/{name}"
    if version:
        purl += f"@{version}"
    return purl


# ── SBOM Generator ────────────────────────────────────────────────────────

class SBOMGenerator:
    """Generates CycloneDX SBOM from project dependencies.

    Usage:
        gen = SBOMGenerator()

        # Generate SBOM for a project
        sbom_json = gen.generate_project("./myapp")

        # Generate for a single file
        sbom_json = gen.generate_file("requirements.txt")

        # Save to file
        gen.save(sbom_json, "sbom.json")
    """

    def __init__(self) -> None:
        self._analyzer = DependencyAnalyzer()

    def generate_project(self, directory: str | Path) -> dict[str, Any]:
        """Generate a CycloneDX SBOM for an entire project."""
        start = time.time()
        directory = Path(directory)
        components: list[SBOMComponent] = []
        source_files: list[str] = []
        seen_purls: set[str] = set()

        dep_files = [
            "requirements.txt", "requirements-dev.txt",
            "package.json", "package-lock.json",
            "Pipfile", "pyproject.toml",
            "Cargo.toml", "go.mod", "Gemfile",
        ]

        for dep_file in dep_files:
            path = directory / dep_file
            if path.exists():
                source, deps = DependencyParser.parse_file(path)
                source_files.append(str(path))

                for dep in deps:
                    purl = _build_purl(dep.name, dep.version, source)
                    if purl not in seen_purls:
                        seen_purls.add(purl)
                        components.append(SBOMComponent(
                            name=dep.name,
                            version=dep.version,
                            purl=purl,
                            scope="optional" if dep.is_dev else "required",
                            source=source.value,
                        ))

        elapsed = (time.time() - start) * 1000

        result = SBOMResult(
            components=components, source_files=source_files,
            generation_time_ms=elapsed,
        )

        return self._build_cyclonedx(result, str(directory))

    def generate_file(self, file_path: str | Path) -> dict[str, Any]:
        """Generate SBOM from a single dependency file."""
        start = time.time()
        path = Path(file_path)

        if not path.exists():
            return {"error": f"File not found: {path}"}

        source, deps = DependencyParser.parse_file(path)
        components = [
            SBOMComponent(
                name=dep.name,
                version=dep.version,
                purl=_build_purl(dep.name, dep.version, source),
                scope="optional" if dep.is_dev else "required",
                source=source.value,
            )
            for dep in deps
        ]

        elapsed = (time.time() - start) * 1000
        result = SBOMResult(
            components=components, source_files=[str(path)],
            generation_time_ms=elapsed,
        )
        return self._build_cyclonedx(result, str(path))

    def save(self, sbom: dict[str, Any], output_path: str | Path) -> None:
        """Save SBOM to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        log.info("sbom_saved", path=str(path), components=len(sbom.get("components", [])))

    def _build_cyclonedx(self, result: SBOMResult, source_name: str) -> dict[str, Any]:
        """Build CycloneDX 1.5 JSON document."""
        serial = hashlib.sha256(
            f"{source_name}:{time.time()}".encode()
        ).hexdigest()[:36]

        sbom: dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [{
                        "type": "application",
                        "name": "agentic-ai-security",
                        "version": "0.1.0",
                        "description": "AI-powered source code security analyzer",
                    }],
                },
                "component": {
                    "type": "application",
                    "name": Path(source_name).name,
                    "bom-ref": f"project:{Path(source_name).name}",
                },
            },
            "components": [c.to_cyclonedx() for c in result.components],
            "dependencies": [],
        }

        # Add root dependency listing
        root_ref = f"project:{Path(source_name).name}"
        sbom["dependencies"].append({
            "ref": root_ref,
            "dependsOn": [c.purl for c in result.components if c.scope == "required"],
        })

        return sbom
