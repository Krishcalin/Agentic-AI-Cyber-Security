"""Model Serialization Scanner — detects backdoors in ML model files.

Scans ML model files for security risks:
- Pickle deserialization exploits (arbitrary code execution via __reduce__)
- Unsafe model loading patterns (torch.load, joblib.load without safeguards)
- Backdoor indicators in model metadata and architecture
- Suspicious file structure in model archives (tar/zip with path traversal)
- SafeTensors vs unsafe format detection
- Model file integrity checks

Covers ATLAS techniques:
- AML.T0018 — Backdoor ML Model
- AML.T0018.001 — Inject Payload
- AML.T0011.000 — Unsafe ML Artifacts
- AML.T0010.003 — ML Supply Chain Compromise (Model)
"""

from __future__ import annotations

import io
import os
import re
import struct
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger("model_scanner")


# ── Data Models ───────────────────────────────────────────────────────────

@dataclass
class ModelFinding:
    """A security finding in a model file."""
    finding_id: str
    category: str
    risk: str  # critical, high, medium, low, info
    title: str
    description: str
    file_path: str
    atlas_technique: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "file": self.file_path,
            "atlas_technique": self.atlas_technique,
            "remediation": self.remediation,
        }


@dataclass
class ModelScanResult:
    """Result of scanning a model file."""
    file_path: str
    file_size: int
    format_detected: str
    findings: list[ModelFinding] = field(default_factory=list)
    scan_time_ms: float = 0.0

    @property
    def is_safe(self) -> bool:
        return not any(f.risk in ("critical", "high") for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def risk_level(self) -> str:
        if any(f.risk == "critical" for f in self.findings):
            return "critical"
        if any(f.risk == "high" for f in self.findings):
            return "high"
        if any(f.risk == "medium" for f in self.findings):
            return "medium"
        if self.findings:
            return "low"
        return "safe"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "file_size_bytes": self.file_size,
            "format": self.format_detected,
            "is_safe": self.is_safe,
            "risk_level": self.risk_level,
            "findings_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time_ms": round(self.scan_time_ms, 1),
        }


# ── Pickle Opcodes (subset relevant for security) ────────────────────────

# These opcodes indicate potentially dangerous operations in pickle streams
DANGEROUS_PICKLE_OPCODES = {
    b"\x63": "GLOBAL — loads arbitrary module.class (code execution vector)",
    b"\x69": "INST — instantiates class (code execution vector)",
    b"\x52": "REDUCE — calls callable with args (primary code execution vector)",
    b"\x81": "NEWOBJ — creates new object (code execution via __new__)",
    b"\x82": "NEWOBJ_EX — extended NEWOBJ (code execution)",
    b"\x93": "STACK_GLOBAL — stack-based GLOBAL (code execution)",
    b"\x92": "REDUCE_EX — extended REDUCE (code execution)",
}

# Modules commonly used in pickle exploits
EXPLOIT_MODULES = [
    b"os",
    b"subprocess",
    b"builtins",
    b"commands",
    b"nt",
    b"posix",
    b"sys",
    b"shutil",
    b"socket",
    b"http",
    b"urllib",
    b"ctypes",
    b"importlib",
    b"runpy",
    b"code",
    b"webbrowser",
]

# Functions commonly used in pickle exploits
EXPLOIT_FUNCTIONS = [
    b"system", b"exec", b"eval", b"popen", b"call",
    b"check_output", b"Popen", b"run",
    b"getattr", b"__import__",
    b"execfile", b"compile",
    b"load", b"loads",
    b"connect", b"urlopen",
    b"remove", b"rmtree", b"unlink",
]

# Known safe model formats
SAFE_FORMATS = {"safetensors", "onnx", "tflite", "mlmodel"}
UNSAFE_FORMATS = {"pickle", "pkl", "pt", "pth", "joblib", "npy", "npz", "h5", "hdf5", "pb"}


# ── Model Scanner ─────────────────────────────────────────────────────────

class ModelScanner:
    """Scans ML model files for serialization attacks and backdoors.

    Usage:
        scanner = ModelScanner()

        # Scan a single model file
        result = scanner.scan_file("model.pkl")
        print(result.risk_level)

        # Scan a directory for model files
        results = scanner.scan_directory("/models/")

        # Check if a file format is safe
        is_safe = scanner.is_safe_format("model.safetensors")
    """

    def __init__(self) -> None:
        self._finding_counter = 0

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"MODEL-{self._finding_counter:04d}"

    def scan_file(self, file_path: str | Path) -> ModelScanResult:
        """Scan a model file for security issues."""
        start = time.time()
        path = Path(file_path)

        if not path.exists():
            return ModelScanResult(
                file_path=str(path), file_size=0, format_detected="unknown",
                findings=[ModelFinding(
                    finding_id=self._next_id(), category="error", risk="low",
                    title="File not found", description=f"Model file not found: {path}",
                    file_path=str(path), atlas_technique="", remediation="Check file path",
                )],
            )

        file_size = path.stat().st_size
        ext = path.suffix.lower().lstrip(".")
        format_detected = self._detect_format(path, ext)

        findings: list[ModelFinding] = []

        # Format-level checks
        findings.extend(self._check_format_safety(path, format_detected))

        # Content-level checks (for pickle-based formats)
        if format_detected in ("pickle", "pkl", "pt", "pth", "joblib"):
            findings.extend(self._scan_pickle_content(path, format_detected))

        # Archive checks (for formats that are zip-based)
        if format_detected in ("pt", "pth", "onnx", "h5", "npz"):
            findings.extend(self._scan_archive_content(path))

        # Size anomaly check
        findings.extend(self._check_size_anomaly(path, file_size, format_detected))

        # Metadata checks
        findings.extend(self._check_metadata(path, format_detected))

        elapsed = (time.time() - start) * 1000

        return ModelScanResult(
            file_path=str(path),
            file_size=file_size,
            format_detected=format_detected,
            findings=findings,
            scan_time_ms=elapsed,
        )

    def scan_directory(self, directory: str | Path) -> list[ModelScanResult]:
        """Scan a directory for model files."""
        directory = Path(directory)
        results = []

        model_extensions = {
            ".pkl", ".pickle", ".pt", ".pth", ".h5", ".hdf5",
            ".onnx", ".pb", ".tflite", ".safetensors", ".joblib",
            ".npy", ".npz", ".mlmodel", ".bin",
        }

        for path in directory.rglob("*"):
            if path.suffix.lower() in model_extensions:
                results.append(self.scan_file(path))

        return results

    def scan_code_for_unsafe_loading(self, code: str, language: str = "python") -> list[ModelFinding]:
        """Scan source code for unsafe model loading patterns."""
        findings: list[ModelFinding] = []

        unsafe_patterns = [
            (r"torch\.load\s*\(", "torch.load() deserializes pickle — use weights_only=True or SafeTensors",
             "critical", "AML.T0011.000"),
            (r"pickle\.load\s*\(", "pickle.load() executes arbitrary code — use SafeTensors or JSON",
             "critical", "AML.T0011.000"),
            (r"pickle\.loads\s*\(", "pickle.loads() executes arbitrary code from bytes",
             "critical", "AML.T0011.000"),
            (r"joblib\.load\s*\(", "joblib.load() uses pickle internally — verify model source",
             "high", "AML.T0011.000"),
            (r"np\.load\s*\(.*allow_pickle\s*=\s*True", "numpy.load with allow_pickle=True enables code execution",
             "high", "AML.T0011.000"),
            (r"keras\.models\.load_model\s*\(", "Keras load_model can execute arbitrary code in Lambda layers",
             "medium", "AML.T0018.001"),
            (r"tf\.saved_model\.load\s*\(", "TensorFlow SavedModel can contain arbitrary ops — verify source",
             "medium", "AML.T0018.001"),
            (r"onnx\.load\s*\(", "ONNX model loading — verify model source and integrity",
             "low", "AML.T0010.003"),
            (r"from_pretrained\s*\(.*trust_remote_code\s*=\s*True",
             "HuggingFace trust_remote_code=True executes arbitrary Python from model repo",
             "critical", "AML.T0011.000"),
            (r"AutoModel.*trust_remote_code\s*=\s*True",
             "AutoModel with trust_remote_code allows arbitrary code execution",
             "critical", "AML.T0011.000"),
            (r"pipeline\s*\(.*trust_remote_code\s*=\s*True",
             "HuggingFace pipeline with trust_remote_code executes untrusted code",
             "critical", "AML.T0011.000"),
        ]

        for pattern, description, risk, atlas_tech in unsafe_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            for match in matches:
                line_num = code[:match.start()].count("\n") + 1
                findings.append(ModelFinding(
                    finding_id=self._next_id(),
                    category="unsafe_loading",
                    risk=risk,
                    title=f"Unsafe model loading at line {line_num}",
                    description=description,
                    file_path="<code>",
                    atlas_technique=atlas_tech,
                    remediation="Use SafeTensors format or verify model source and integrity",
                    metadata={"line": line_num, "matched": match.group()[:80]},
                ))

        return findings

    @staticmethod
    def is_safe_format(file_path: str | Path) -> bool:
        """Check if a model file format is inherently safe."""
        ext = Path(file_path).suffix.lower().lstrip(".")
        return ext in SAFE_FORMATS

    # ── Internal Scan Methods ─────────────────────────────────────────

    def _detect_format(self, path: Path, ext: str) -> str:
        """Detect model file format from extension and magic bytes."""
        # Map common extensions
        ext_map = {
            "pkl": "pickle", "pickle": "pickle",
            "pt": "pt", "pth": "pth",
            "h5": "h5", "hdf5": "h5",
            "onnx": "onnx",
            "pb": "pb",
            "tflite": "tflite",
            "safetensors": "safetensors",
            "joblib": "joblib",
            "npy": "npy", "npz": "npz",
            "mlmodel": "mlmodel",
            "bin": "bin",
        }
        return ext_map.get(ext, ext or "unknown")

    def _check_format_safety(self, path: Path, fmt: str) -> list[ModelFinding]:
        """Check if the model format is inherently unsafe."""
        findings = []

        if fmt in ("pickle", "pkl"):
            findings.append(ModelFinding(
                finding_id=self._next_id(),
                category="unsafe_format",
                risk="high",
                title="Pickle model format — arbitrary code execution risk",
                description="Python pickle files can execute arbitrary code during deserialization. "
                           "An attacker can embed malicious __reduce__ methods that run on load.",
                file_path=str(path),
                atlas_technique="AML.T0011.000",
                remediation="Convert to SafeTensors format. Never load pickle models from untrusted sources.",
            ))

        elif fmt in ("pt", "pth"):
            findings.append(ModelFinding(
                finding_id=self._next_id(),
                category="unsafe_format",
                risk="high",
                title="PyTorch .pt/.pth format uses pickle internally",
                description="PyTorch's default save format uses pickle serialization, "
                           "enabling code execution on torch.load(). Use weights_only=True.",
                file_path=str(path),
                atlas_technique="AML.T0011.000",
                remediation="Use torch.load(path, weights_only=True) or convert to SafeTensors.",
            ))

        elif fmt == "joblib":
            findings.append(ModelFinding(
                finding_id=self._next_id(),
                category="unsafe_format",
                risk="high",
                title="Joblib format uses pickle internally",
                description="Joblib serialization is based on pickle and inherits all its "
                           "code execution risks.",
                file_path=str(path),
                atlas_technique="AML.T0011.000",
                remediation="Use ONNX or SafeTensors for model distribution.",
            ))

        elif fmt == "safetensors":
            findings.append(ModelFinding(
                finding_id=self._next_id(),
                category="safe_format",
                risk="info",
                title="SafeTensors format — safe serialization",
                description="SafeTensors is a safe serialization format that does not execute code.",
                file_path=str(path),
                atlas_technique="",
                remediation="No action needed — this is the recommended format.",
            ))

        return findings

    def _scan_pickle_content(self, path: Path, fmt: str) -> list[ModelFinding]:
        """Scan pickle-based files for dangerous opcodes and payloads."""
        findings = []

        try:
            # Read first 10MB max to avoid memory issues
            max_read = 10 * 1024 * 1024
            with open(path, "rb") as f:
                data = f.read(max_read)
        except (OSError, PermissionError) as e:
            log.warning("model_read_error", file=str(path), error=str(e))
            return findings

        # For PyTorch files, try to find pickle data within ZIP
        if fmt in ("pt", "pth"):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".pkl") or "data" in name.lower():
                            pkl_data = zf.read(name)[:max_read]
                            findings.extend(self._analyze_pickle_bytes(pkl_data, str(path), name))
                    return findings
            except (zipfile.BadZipFile, Exception):
                pass  # Not a ZIP — scan raw bytes

        findings.extend(self._analyze_pickle_bytes(data, str(path)))
        return findings

    def _analyze_pickle_bytes(
        self, data: bytes, file_path: str, inner_name: str = ""
    ) -> list[ModelFinding]:
        """Analyze raw pickle bytes for exploit indicators."""
        findings = []
        location = f"{file_path}:{inner_name}" if inner_name else file_path

        # Check for dangerous opcodes
        for opcode, description in DANGEROUS_PICKLE_OPCODES.items():
            count = data.count(opcode)
            if count > 0:
                # REDUCE and GLOBAL are normal in legit pickles, but check context
                if opcode in (b"\x52", b"\x63", b"\x93"):
                    # Check if combined with exploit modules
                    for module in EXPLOIT_MODULES:
                        if module in data:
                            for func in EXPLOIT_FUNCTIONS:
                                if func in data:
                                    findings.append(ModelFinding(
                                        finding_id=self._next_id(),
                                        category="pickle_exploit",
                                        risk="critical",
                                        title=f"Pickle exploit: {module.decode()}.{func.decode()} via {description.split(' — ')[0]}",
                                        description=f"Found dangerous module '{module.decode()}' with function "
                                                   f"'{func.decode()}' referenced alongside {description}. "
                                                   f"This is a strong indicator of a code execution payload.",
                                        file_path=location,
                                        atlas_technique="AML.T0018.001",
                                        remediation="DO NOT load this model. It likely contains malicious code.",
                                        metadata={"opcode": description, "module": module.decode(),
                                                  "function": func.decode()},
                                    ))
                                    break
                            break

        # Check for shell commands embedded in pickle data
        shell_patterns = [
            (rb"curl\s+.*http", "curl command — possible download-and-execute"),
            (rb"wget\s+.*http", "wget command — possible download-and-execute"),
            (rb"/bin/(bash|sh|zsh)", "Shell reference — possible reverse shell"),
            (rb"powershell", "PowerShell reference — possible malicious script"),
            (rb"cmd\.exe", "cmd.exe reference — possible Windows command execution"),
            (rb"rm\s+-rf", "Recursive delete command embedded in model"),
            (rb"base64\s+-d", "Base64 decode — possible encoded payload"),
            (rb"nc\s+-[elp]", "Netcat listener — possible reverse shell"),
        ]

        for pattern, description in shell_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                findings.append(ModelFinding(
                    finding_id=self._next_id(),
                    category="embedded_command",
                    risk="critical",
                    title=f"Embedded shell command: {description}",
                    description=f"Found suspicious shell command pattern in model binary data: {description}",
                    file_path=location,
                    atlas_technique="AML.T0018.001",
                    remediation="DO NOT load this model. Inspect binary contents manually.",
                ))

        # Check for suspicious URLs
        url_pattern = rb"https?://[a-zA-Z0-9._/\-?&=]+"
        urls = re.findall(url_pattern, data)
        suspicious_domains = [b"ngrok", b"requestbin", b"hookbin", b"pipedream",
                            b"pastebin", b"githubusercontent"]
        for url in urls:
            for domain in suspicious_domains:
                if domain in url.lower():
                    findings.append(ModelFinding(
                        finding_id=self._next_id(),
                        category="suspicious_url",
                        risk="high",
                        title=f"Suspicious URL in model: {url[:80].decode(errors='ignore')}",
                        description="Model contains URL pointing to known exfiltration/staging service",
                        file_path=location,
                        atlas_technique="AML.T0018.001",
                        remediation="Investigate URL purpose. Model may phone home on load.",
                    ))
                    break

        return findings

    def _scan_archive_content(self, path: Path) -> list[ModelFinding]:
        """Scan ZIP/archive-based model files for path traversal."""
        findings = []

        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    # Check for path traversal (zip slip)
                    if ".." in info.filename or info.filename.startswith("/"):
                        findings.append(ModelFinding(
                            finding_id=self._next_id(),
                            category="path_traversal",
                            risk="critical",
                            title=f"Path traversal in archive: {info.filename}",
                            description="Model archive contains entry with path traversal "
                                       "(../ or absolute path) — Zip Slip attack vector",
                            file_path=str(path),
                            atlas_technique="AML.T0018.001",
                            remediation="Do not extract this archive. It may overwrite system files.",
                        ))

                    # Check for executable files in archive
                    if info.filename.endswith((".exe", ".sh", ".bat", ".ps1", ".py", ".dll", ".so")):
                        findings.append(ModelFinding(
                            finding_id=self._next_id(),
                            category="embedded_executable",
                            risk="high",
                            title=f"Executable file in model archive: {info.filename}",
                            description="Model archive contains an executable file which should "
                                       "not be present in a legitimate model",
                            file_path=str(path),
                            atlas_technique="AML.T0018.001",
                            remediation="Inspect the executable. Remove if not needed for model inference.",
                        ))
        except (zipfile.BadZipFile, Exception):
            pass  # Not a valid ZIP

        return findings

    def _check_size_anomaly(self, path: Path, size: int, fmt: str) -> list[ModelFinding]:
        """Check for suspicious file size anomalies."""
        findings = []

        # Very small model files might be decoys/droppers
        if fmt in ("pt", "pth", "h5", "onnx") and size < 1024:
            findings.append(ModelFinding(
                finding_id=self._next_id(),
                category="size_anomaly",
                risk="medium",
                title=f"Suspiciously small model file ({size} bytes)",
                description=f"Model file is only {size} bytes — legitimate models are typically "
                           "much larger. This could be a dropper or decoy.",
                file_path=str(path),
                atlas_technique="AML.T0018",
                remediation="Verify model file is complete and from a trusted source.",
            ))

        return findings

    def _check_metadata(self, path: Path, fmt: str) -> list[ModelFinding]:
        """Check model metadata for suspicious indicators."""
        findings = []

        # For HDF5/H5 files, check for custom metadata (would need h5py)
        # For now, check filename patterns
        name_lower = path.name.lower()

        suspicious_names = [
            ("backdoor", "File named with 'backdoor'"),
            ("exploit", "File named with 'exploit'"),
            ("payload", "File named with 'payload'"),
            ("trojan", "File named with 'trojan'"),
            ("malicious", "File named with 'malicious'"),
        ]

        for keyword, description in suspicious_names:
            if keyword in name_lower:
                findings.append(ModelFinding(
                    finding_id=self._next_id(),
                    category="suspicious_name",
                    risk="medium",
                    title=f"Suspicious model filename: {path.name}",
                    description=description,
                    file_path=str(path),
                    atlas_technique="AML.T0018",
                    remediation="Verify model provenance and integrity.",
                ))
                break

        return findings
