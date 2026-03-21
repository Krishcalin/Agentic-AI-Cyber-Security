"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.engine import ScanEngine
from core.pattern_matcher import PatternMatcher
from core.rule_loader import RuleLoader

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent / "rules"


@pytest.fixture
def rules_dir() -> str:
    return str(RULES_DIR)


@pytest.fixture
def loader(rules_dir: str) -> RuleLoader:
    return RuleLoader(rules_dir)


@pytest.fixture
def matcher(rules_dir: str) -> PatternMatcher:
    m = PatternMatcher(rules_dir)
    m.load_rules()
    return m


@pytest.fixture
def engine(rules_dir: str) -> ScanEngine:
    e = ScanEngine(rules_dir)
    e.initialize()
    return e


@pytest.fixture
def python_fixture() -> str:
    return str(FIXTURES_DIR / "python_vulnerable.py")


@pytest.fixture
def javascript_fixture() -> str:
    return str(FIXTURES_DIR / "javascript_vulnerable.js")
