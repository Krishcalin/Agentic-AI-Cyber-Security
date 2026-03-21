"""Tests for package hallucination detection."""

from __future__ import annotations

import os
import tempfile

import pytest

from core.bloom_filter import BloomFilter
from core.import_extractor import ImportExtractor
from core.package_checker import PackageChecker


# ── Bloom Filter ───────────────────────────────────────────────────────────


class TestBloomFilter:
    def test_add_and_check(self):
        bf = BloomFilter(expected_items=100)
        bf.add("requests")
        bf.add("flask")
        assert "requests" in bf
        assert "flask" in bf

    def test_not_in_filter(self):
        bf = BloomFilter(expected_items=100)
        bf.add("requests")
        assert "nonexistent-pkg-xyz" not in bf

    def test_add_many(self):
        bf = BloomFilter(expected_items=1000)
        packages = [f"pkg-{i}" for i in range(500)]
        bf.add_many(packages)
        assert len(bf) == 500
        assert "pkg-0" in bf
        assert "pkg-499" in bf
        assert "pkg-500" not in bf

    def test_save_and_load(self, tmp_path):
        bf = BloomFilter(expected_items=100)
        bf.add("requests")
        bf.add("flask")
        bf.add("django")

        path = str(tmp_path / "test.bloom")
        bf.save(path)

        loaded = BloomFilter.load(path)
        assert "requests" in loaded
        assert "flask" in loaded
        assert "django" in loaded
        assert "nonexistent" not in loaded
        assert len(loaded) == 3

    def test_false_positive_rate(self):
        """False positive rate should be low."""
        bf = BloomFilter(expected_items=10000, false_positive_rate=0.01)
        for i in range(10000):
            bf.add(f"real-package-{i}")

        false_positives = 0
        tests = 10000
        for i in range(tests):
            if f"fake-package-{i}" in bf:
                false_positives += 1

        rate = false_positives / tests
        assert rate < 0.05, f"False positive rate too high: {rate:.3f}"


# ── Import Extractor ───────────────────────────────────────────────────────


class TestImportExtractor:
    def test_python_imports(self):
        code = '''
import requests
from flask import Flask
import os
import numpy as np
from collections import defaultdict
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name

        try:
            extractor = ImportExtractor()
            imports = extractor.extract_from_file(path)
            names = {i.package_name for i in imports}
            assert "requests" in names
            assert "flask" in names
            assert "numpy" in names
            # stdlib should be excluded
            assert "os" not in names
            assert "collections" not in names
        finally:
            os.unlink(path)

    def test_python_imports_registry(self):
        code = 'import requests\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            extractor = ImportExtractor()
            imports = extractor.extract_from_file(path)
            assert imports[0].registry == "pypi"
        finally:
            os.unlink(path)

    def test_javascript_require(self):
        code = '''
const express = require('express');
const fs = require('fs');
const axios = require('axios');
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            extractor = ImportExtractor()
            imports = extractor.extract_from_file(path)
            names = {i.package_name for i in imports}
            assert "express" in names
            assert "axios" in names
            assert "fs" not in names  # Node.js builtin
        finally:
            os.unlink(path)

    def test_javascript_import(self):
        code = '''
import React from 'react';
import { useState } from 'react';
import axios from 'axios';
import './local-file';
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            extractor = ImportExtractor()
            imports = extractor.extract_from_file(path)
            names = {i.package_name for i in imports}
            assert "react" in names
            assert "axios" in names
        finally:
            os.unlink(path)

    def test_requirements_txt(self):
        content = '''
requests>=2.28
flask==2.3.0
numpy
# comment
-r other.txt
pyyaml>=6.0
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False,
                                         prefix="requirements") as f:
            # Can't use prefix to set exact name, so test the method directly
            pass

        path = os.path.join(tempfile.gettempdir(), "requirements.txt")
        with open(path, "w") as f:
            f.write(content)
        try:
            extractor = ImportExtractor()
            imports = extractor._extract_requirements_txt(path)
            names = {i.package_name for i in imports}
            assert "requests" in names
            assert "flask" in names
            assert "numpy" in names
            assert "pyyaml" in names
        finally:
            os.unlink(path)

    def test_scoped_npm_packages(self):
        code = '''const sdk = require('@anthropic-ai/sdk');\n'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            extractor = ImportExtractor()
            imports = extractor.extract_from_file(path)
            assert any("@anthropic-ai/sdk" in i.package_name for i in imports)
        finally:
            os.unlink(path)


# ── Package Checker ────────────────────────────────────────────────────────


class TestPackageChecker:
    def test_known_malicious(self):
        checker = PackageChecker()
        result = checker.check_package("requesrs", "pypi")
        assert result.is_malicious is True
        assert result.risk_level == "critical"

    def test_typosquat_detection(self):
        checker = PackageChecker()
        # "requsets" is 1 edit distance from "requests"
        result = checker.check_package("requsets", "pypi")
        assert result.is_typosquat is True
        assert result.similar_to == "requests"

    def test_legit_popular_package(self):
        checker = PackageChecker()
        result = checker.check_package("requests", "pypi")
        assert result.is_malicious is False
        assert result.is_typosquat is False

    def test_npm_typosquat(self):
        checker = PackageChecker()
        result = checker.check_package("exprss", "npm")
        assert result.is_typosquat is True
        assert result.similar_to == "express"

    def test_bloom_filter_integration(self, tmp_path):
        checker = PackageChecker()

        # Build a small bloom filter
        packages = ["requests", "flask", "django", "numpy", "pandas"]
        bf = checker.build_bloom_filter("pypi", packages, str(tmp_path / "pypi.bloom"))

        # Known package passes
        result = checker.check_package("requests", "pypi")
        assert result.exists is True

        # Unknown package fails
        result = checker.check_package("totally-fake-package-xyz123", "pypi")
        assert result.exists is False

    def test_levenshtein(self):
        dist = PackageChecker._levenshtein("requests", "requesrs")
        assert dist == 1

        dist = PackageChecker._levenshtein("flask", "flask")
        assert dist == 0

        dist = PackageChecker._levenshtein("numpy", "numpyy")
        assert dist == 1

        dist = PackageChecker._levenshtein("abc", "xyz")
        assert dist == 3

    def test_check_file_imports(self):
        code = 'import requests\nimport requesrs\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            checker = PackageChecker()
            results = checker.check_file_imports(path)
            assert len(results) >= 2
            malicious = [r for r in results if r.is_malicious]
            assert len(malicious) >= 1  # requesrs is in malicious DB
        finally:
            os.unlink(path)

    def test_scan_file_findings(self):
        code = 'import requesrs\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            checker = PackageChecker()
            result = checker.scan_file(path)
            assert result.finding_count >= 1
            assert any("malicious" in f.rule_id.lower() or "MALICIOUS" in f.message for f in result.findings)
        finally:
            os.unlink(path)


class TestSubstitutionPatterns:
    def test_dash_underscore_swap(self):
        checker = PackageChecker()
        # python-dateutil vs python_dateutil
        result = checker.check_package("python_dateutil", "pypi")
        # Should not crash, may or may not detect depending on corpus

    def test_py_prefix(self):
        checker = PackageChecker()
        result = checker.check_package("pyrequests", "pypi")
        # Should detect similarity to "requests"
        # (depends on substitution patterns)
