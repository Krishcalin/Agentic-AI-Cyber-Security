#!/usr/bin/env python3
"""Build bloom filter data files for package verification.

Generates .bloom files for PyPI, npm, and crates.io registries containing
popular/legitimate package names. These are used by the PackageChecker
to detect hallucinated or non-existent packages.

Usage:
    python scripts/build_bloom_filters.py

Outputs:
    data/pypi_packages.bloom
    data/npm_packages.bloom
    data/crates_packages.bloom
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.bloom_filter import BloomFilter


# ── Popular PyPI Packages (top 500+) ──────────────────────────────────────

PYPI_PACKAGES = [
    # Web frameworks
    "flask", "django", "fastapi", "tornado", "bottle", "pyramid", "sanic",
    "starlette", "uvicorn", "gunicorn", "waitress", "hypercorn", "daphne",
    "aiohttp", "quart", "falcon", "hug", "responder", "masonite",
    # HTTP & networking
    "requests", "httpx", "urllib3", "httplib2", "aiohttp", "grpcio",
    "websockets", "paramiko", "fabric", "twisted", "treq",
    # Data science & ML
    "numpy", "pandas", "scipy", "scikit-learn", "matplotlib", "seaborn",
    "tensorflow", "torch", "keras", "xgboost", "lightgbm", "catboost",
    "statsmodels", "sympy", "networkx", "dask", "vaex", "polars",
    "transformers", "datasets", "tokenizers", "accelerate", "safetensors",
    "diffusers", "peft", "trl", "bitsandbytes", "sentencepiece",
    "langchain", "llama-index", "openai", "anthropic", "cohere",
    "huggingface-hub", "timm", "torchvision", "torchaudio",
    # Database
    "sqlalchemy", "psycopg2", "psycopg2-binary", "pymysql", "mysqlclient",
    "pymongo", "redis", "celery", "kombu", "elasticsearch",
    "motor", "tortoise-orm", "peewee", "pony", "databases",
    "asyncpg", "aiomysql", "aioredis", "sqlmodel",
    # Testing
    "pytest", "pytest-cov", "pytest-asyncio", "pytest-mock", "pytest-xdist",
    "unittest2", "nose", "nose2", "tox", "nox", "coverage",
    "hypothesis", "faker", "factory-boy", "mimesis", "responses",
    "vcrpy", "moto", "freezegun", "time-machine",
    # CLI & config
    "click", "typer", "argparse", "fire", "docopt",
    "pyyaml", "toml", "tomli", "tomli-w", "python-dotenv", "configparser",
    "pydantic", "pydantic-settings", "attrs", "cattrs", "marshmallow",
    # Utilities
    "rich", "tqdm", "colorama", "termcolor", "tabulate", "texttable",
    "structlog", "loguru", "logging-config",
    "arrow", "pendulum", "python-dateutil", "pytz", "babel",
    "pillow", "wand", "imageio", "scikit-image",
    "jinja2", "mako", "chameleon",
    "more-itertools", "toolz", "cytoolz", "boltons", "funcy",
    "tenacity", "retry", "backoff",
    "cachetools", "diskcache", "lru-dict",
    # Crypto & security
    "cryptography", "pycryptodome", "pynacl", "bcrypt", "passlib",
    "certifi", "pyopenssl", "cffi", "pyjwt", "python-jose",
    "itsdangerous", "fernet",
    # Cloud & DevOps
    "boto3", "botocore", "s3transfer",
    "google-cloud-storage", "google-cloud-bigquery", "google-api-core",
    "azure-storage-blob", "azure-identity", "azure-core",
    "docker", "kubernetes", "ansible", "ansible-core",
    "terraform", "pulumi",
    # Serialization
    "protobuf", "grpcio-tools", "msgpack", "cbor2", "avro-python3",
    "orjson", "ujson", "simplejson", "rapidjson",
    # Linting & formatting
    "ruff", "black", "isort", "flake8", "pylint", "autopep8", "yapf",
    "mypy", "pyright", "pytype", "bandit", "safety",
    # Packaging
    "setuptools", "wheel", "pip", "pipenv", "poetry", "poetry-core",
    "build", "twine", "flit", "hatch", "hatchling", "pdm",
    # Misc popular
    "beautifulsoup4", "lxml", "html5lib", "cssselect",
    "scrapy", "selenium", "playwright", "pyppeteer",
    "openpyxl", "xlsxwriter", "xlrd", "python-pptx", "python-docx",
    "reportlab", "pypdf2", "pdfplumber", "camelot-py",
    "pyqt5", "pyqt6", "pyside2", "pyside6", "tkinter",
    "pygments", "sphinx", "mkdocs", "mkdocs-material",
    "watchdog", "schedule", "apscheduler",
    "psutil", "py-cpuinfo", "gputil",
    "typing-extensions", "importlib-metadata", "packaging", "distlib",
    "wrapt", "decorator", "deprecated", "six", "future",
    "multidict", "yarl", "frozenlist", "aiosignal",
    "charset-normalizer", "idna", "chardet",
    "filelock", "portalocker", "fasteners",
    "python-magic", "filetype",
    "shortuuid", "nanoid", "uuid6",
]

# ── Popular npm Packages (top 500+) ───────────────────────────────────────

NPM_PACKAGES = [
    # Frameworks
    "express", "koa", "fastify", "hapi", "nest", "@nestjs/core",
    "next", "nuxt", "gatsby", "remix", "astro",
    "react", "react-dom", "react-router", "react-router-dom",
    "vue", "vuex", "vue-router", "@vue/cli",
    "angular", "@angular/core", "@angular/cli",
    "svelte", "solid-js", "preact", "lit",
    # Build tools
    "webpack", "vite", "esbuild", "rollup", "parcel", "turbopack",
    "babel-core", "@babel/core", "@babel/preset-env",
    "typescript", "ts-node", "tsx",
    # Testing
    "jest", "mocha", "chai", "sinon", "jasmine", "ava",
    "vitest", "playwright", "@playwright/test",
    "cypress", "puppeteer", "selenium-webdriver",
    "@testing-library/react", "@testing-library/jest-dom",
    "supertest", "nock", "msw",
    # Utilities
    "lodash", "underscore", "ramda", "immer",
    "moment", "dayjs", "date-fns", "luxon",
    "uuid", "nanoid", "shortid", "cuid",
    "chalk", "ora", "inquirer", "commander", "yargs", "meow",
    "debug", "winston", "pino", "bunyan", "morgan",
    "dotenv", "cross-env", "env-cmd",
    "glob", "minimatch", "micromatch", "fast-glob",
    "fs-extra", "graceful-fs", "chokidar",
    "path-to-regexp", "qs", "query-string",
    "cheerio", "jsdom", "node-html-parser",
    "marked", "remark", "markdown-it", "showdown",
    "handlebars", "ejs", "pug", "mustache", "nunjucks",
    # HTTP
    "axios", "got", "node-fetch", "undici", "superagent",
    "http-proxy", "http-proxy-middleware", "cors",
    "body-parser", "multer", "formidable",
    "cookie-parser", "express-session",
    # Database
    "mongoose", "sequelize", "typeorm", "prisma", "@prisma/client",
    "knex", "objection", "bookshelf", "waterline",
    "redis", "ioredis", "bull", "bullmq",
    "pg", "mysql2", "sqlite3", "better-sqlite3",
    "mongodb", "dynamodb",
    # Auth & security
    "jsonwebtoken", "passport", "passport-local", "passport-jwt",
    "bcrypt", "bcryptjs", "argon2",
    "helmet", "csurf", "express-rate-limit",
    "cors", "hpp", "xss-clean",
    # Linting & formatting
    "eslint", "prettier", "stylelint",
    "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
    "eslint-config-airbnb", "eslint-config-standard",
    # State management
    "redux", "@reduxjs/toolkit", "zustand", "jotai", "recoil",
    "mobx", "mobx-react", "valtio", "xstate",
    # Styling
    "tailwindcss", "postcss", "autoprefixer", "sass", "less",
    "styled-components", "@emotion/react", "@emotion/styled",
    "classnames", "clsx",
    # Misc
    "socket.io", "ws", "socket.io-client",
    "sharp", "jimp", "canvas",
    "nodemailer", "sendgrid", "@sendgrid/mail",
    "stripe", "@stripe/stripe-js",
    "aws-sdk", "@aws-sdk/client-s3",
    "firebase", "firebase-admin",
    "zod", "yup", "joi", "ajv",
    "rxjs", "highland", "most",
    "p-limit", "p-queue", "p-retry", "async", "bluebird",
    "lru-cache", "node-cache", "keyv",
    "semver", "compare-versions",
]

# ── Popular Crates.io Packages ────────────────────────────────────────────

CRATES_PACKAGES = [
    # Core
    "serde", "serde_json", "serde_yaml", "toml",
    "tokio", "async-std", "futures", "smol",
    "reqwest", "hyper", "actix-web", "axum", "warp", "rocket",
    "clap", "structopt", "argh",
    "log", "env_logger", "tracing", "tracing-subscriber",
    "anyhow", "thiserror", "eyre", "miette",
    "rand", "uuid", "chrono", "time",
    "regex", "once_cell", "lazy_static",
    "rayon", "crossbeam", "parking_lot",
    "bytes", "memmap2", "byteorder",
    # Database
    "sqlx", "diesel", "sea-orm", "rusqlite",
    "redis", "deadpool-redis", "bb8", "r2d2",
    "mongodb", "elasticsearch",
    # Crypto
    "ring", "rustls", "openssl", "aes", "sha2",
    "argon2", "bcrypt", "ed25519-dalek",
    "jsonwebtoken", "oauth2",
    # Serialization
    "bincode", "postcard", "rmp-serde", "ciborium",
    "prost", "tonic",
    # CLI
    "indicatif", "console", "dialoguer", "colored",
    "tui", "ratatui", "crossterm", "termion",
    # Testing
    "criterion", "proptest", "quickcheck", "mockall",
    "rstest", "test-case", "fake",
    # Web
    "tower", "tower-http", "http", "url",
    "cookie", "mime",
    # Misc
    "itertools", "num", "nalgebra", "ndarray",
    "image", "png", "gif",
    "walkdir", "globset", "ignore",
    "tempfile", "directories", "dirs",
    "config", "figment", "dotenv",
    "tera", "askama", "handlebars",
    "pulldown-cmark", "comrak",
]


def main() -> None:
    """Build bloom filter files for all registries."""
    data_dir = project_root / "data"
    data_dir.mkdir(exist_ok=True)

    registries = {
        "pypi": (PYPI_PACKAGES, "pypi_packages.bloom"),
        "npm": (NPM_PACKAGES, "npm_packages.bloom"),
        "crates": (CRATES_PACKAGES, "crates_packages.bloom"),
    }

    for registry, (packages, filename) in registries.items():
        # Deduplicate
        unique_packages = sorted(set(p.lower() for p in packages))
        output_path = data_dir / filename

        bf = BloomFilter(expected_items=max(len(unique_packages) * 2, 1000))
        bf.add_many(unique_packages)
        bf.save(str(output_path))

        # Verify
        loaded = BloomFilter.load(str(output_path))
        verified = sum(1 for p in unique_packages if p in loaded)

        print(f"  {registry}: {len(unique_packages)} packages → {output_path.name} "
              f"({output_path.stat().st_size:,} bytes, {verified}/{len(unique_packages)} verified)")

    print("\nDone! Bloom filters saved to data/")


if __name__ == "__main__":
    main()
