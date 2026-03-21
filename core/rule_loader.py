"""YAML rule loader and validator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml

from core.models import Confidence, Rule, Severity

log = structlog.get_logger("rule_loader")


class RuleLoader:
    """Loads and validates security rules from YAML files."""

    def __init__(self, rules_dir: str = "rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []

    def load_all(self) -> list[Rule]:
        """Load all rules from the rules directory."""
        self.rules = []
        if not self.rules_dir.exists():
            log.warning("rules_dir_not_found", path=str(self.rules_dir))
            return self.rules

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                rules = self._load_file(yaml_file)
                self.rules.extend(rules)
                log.debug("rules_loaded", file=yaml_file.name, count=len(rules))
            except Exception as e:
                log.error("rule_load_failed", file=yaml_file.name, error=str(e))

        log.info("all_rules_loaded", total=len(self.rules))
        return self.rules

    def load_for_language(self, language: str) -> list[Rule]:
        """Load rules applicable to a specific language."""
        if not self.rules:
            self.load_all()
        return [r for r in self.rules if language in r.languages or "any" in r.languages]

    def _load_file(self, path: Path) -> list[Rule]:
        """Parse a single YAML rule file."""
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not content or "rules" not in content:
            return []

        rules: list[Rule] = []
        for entry in content["rules"]:
            rule = self._parse_rule(entry)
            if rule:
                rules.append(rule)
        return rules

    def _parse_rule(self, entry: dict[str, Any]) -> Rule | None:
        """Parse a single rule entry from YAML."""
        required = ["id", "languages", "severity", "message", "patterns"]
        for key in required:
            if key not in entry:
                log.warning("rule_missing_field", rule=entry.get("id", "?"), field=key)
                return None

        try:
            severity = Severity(entry["severity"].lower())
        except ValueError:
            severity = Severity.INFO

        try:
            confidence = Confidence(entry.get("confidence", "high").lower())
        except ValueError:
            confidence = Confidence.MEDIUM

        # Extract category from rule ID (e.g., "python.injection.sql" → "injection")
        parts = entry["id"].split(".")
        category = parts[1] if len(parts) >= 2 else "general"

        metadata = entry.get("metadata", {})

        return Rule(
            id=entry["id"],
            languages=entry["languages"],
            severity=severity,
            message=entry["message"],
            patterns=entry["patterns"],
            cwe=entry.get("cwe", metadata.get("cwe", "")),
            owasp=entry.get("owasp", metadata.get("owasp", "")),
            confidence=confidence,
            fix_template=entry.get("fix_template", ""),
            category=category,
            metadata=metadata,
        )
