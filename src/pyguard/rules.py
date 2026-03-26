"""
Detection rules. Each rule takes a package + environment context and returns
a list of Finding objects.
"""

from __future__ import annotations

import ast
import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pyguard.environment import InstalledPackage, EnvironmentInfo, get_package_directory


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    severity: Severity
    message: str
    detail: str = ""


# ---------------------------------------------------------------------------
# Patterns used in static analysis
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    r"os\.environ",
    r"os\.getenv",
    r"~/\.ssh",
    r"~/\.aws",
    r"~/\.kube",
    r"\.kube/config",
    r"OPENAI_API_KEY",
    r"AWS_SECRET_ACCESS_KEY",
    r"AWS_ACCESS_KEY_ID",
    r"GITHUB_TOKEN",
    r"ANTHROPIC_API_KEY",
    r"HUGGING_FACE_HUB_TOKEN",
    r"private_key",
    r"id_rsa",
    r"credentials",
]

NETWORK_CALL_PATTERNS = [
    r"\.post\s*\(",
    r"\.get\s*\(",
    r"\.put\s*\(",
    r"\.delete\s*\(",
    r"urllib\.request\.urlopen",
    r"socket\.connect\s*\(",
    r"socket\.create_connection\s*\(",
]

NETWORK_IMPORT_PATTERNS = [
    r"import requests",
    r"from requests",
    r"import httpx",
    r"from httpx",
    r"import urllib",
    r"from urllib",
    r"import aiohttp",
    r"from aiohttp",
    r"import socket",
]

# Packages that legitimately read credentials and make network calls.
# Flagging these as HIGH would be pure noise.
NETWORK_CREDENTIAL_WHITELIST = {
    "requests", "httpx", "aiohttp", "urllib3", "boto3", "botocore",
    "google-auth", "google-cloud-core", "azure-identity", "azure-core",
    "paramiko", "fabric", "tweepy", "stripe", "sendgrid", "twilio",
    "openai", "anthropic", "cohere", "mistralai",
}

_SECRET_RE = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)
_NETWORK_CALL_RE = re.compile("|".join(NETWORK_CALL_PATTERNS))
_NETWORK_IMPORT_RE = re.compile("|".join(NETWORK_IMPORT_PATTERNS))
_PTH_EXECUTABLE_RE = re.compile(r"^\s*(import\s+|exec\s*\(|__import__)", re.MULTILINE)

# Obfuscation signals: common in malicious packages.
# Each pattern must be specific enough to avoid false positives:
# - exec/eval wrapping a base64 decode is almost never legitimate
# - marshal.loads on arbitrary data is a strong signal
# - __import__ alone is too common (used in legitimate compat shims)
_OBFUSCATION_RE = re.compile(
    r"exec\s*\(\s*base64"
    r"|eval\s*\(\s*base64"
    r"|exec\s*\(.*b64decode"
    r"|eval\s*\(.*b64decode"
    r"|exec\s*\(\s*__import__"
    r"|marshal\.loads\s*\("
    r"|exec\s*\(\s*zlib\.decompress",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Rule: CVE lookup via OSV
# ---------------------------------------------------------------------------

def rule_cve_lookup(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    """Query the OSV database for known vulnerabilities."""
    payload = json.dumps({
        "version": pkg.version,
        "package": {"name": pkg.name, "ecosystem": "PyPI"},
    }).encode()

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []

    findings = []
    for vuln in data.get("vulns", []):
        vuln_id = vuln.get("id", "unknown")
        summary = vuln.get("summary", "no summary available")
        aliases = vuln.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        findings.append(Finding(
            severity=Severity.MEDIUM,
            message=f"known vulnerability: {cve}",
            detail=summary,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule: known bad version denylist
# ---------------------------------------------------------------------------

_KNOWN_BAD: dict | None = None


def _load_known_bad() -> dict:
    global _KNOWN_BAD
    if _KNOWN_BAD is None:
        data_file = Path(__file__).parent / "data" / "known_bad.json"
        with open(data_file) as f:
            _KNOWN_BAD = json.load(f)
    return _KNOWN_BAD


def rule_known_bad_version(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    known_bad = _load_known_bad()
    entry = known_bad.get(pkg.name.lower())
    if not entry:
        return []
    if pkg.version in entry["versions"]:
        return [Finding(
            severity=Severity.HIGH,
            message=f"known malicious version {pkg.version}",
            detail=entry["reason"],
        )]
    return []


# ---------------------------------------------------------------------------
# Rule: .pth startup execution
# ---------------------------------------------------------------------------

def rule_pth_startup(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    findings = []
    pkg_name_normalized = pkg.name.lower().replace("-", "_").replace(".", "_")

    for pth_file in env.pth_files:
        stem = pth_file.stem.lower().replace("-", "_").replace(".", "_")
        if pkg_name_normalized not in stem and stem not in pkg_name_normalized:
            continue
        try:
            content = pth_file.read_text(errors="replace")
        except OSError:
            continue
        if _PTH_EXECUTABLE_RE.search(content):
            findings.append(Finding(
                severity=Severity.HIGH,
                message=f"startup .pth file with executable code: {pth_file.name}",
                detail="This file runs automatically when Python starts.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Rule: sitecustomize / usercustomize (environment-level, called once)
# ---------------------------------------------------------------------------

def check_startup_hooks(env: EnvironmentInfo) -> list[Finding]:
    findings = []
    if env.sitecustomize:
        findings.append(Finding(
            severity=Severity.HIGH,
            message="sitecustomize.py found in site-packages",
            detail=str(env.sitecustomize),
        ))
    if env.usercustomize:
        findings.append(Finding(
            severity=Severity.HIGH,
            message="usercustomize.py found in site-packages",
            detail=str(env.usercustomize),
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule: toplevel secret + network (HIGH) — AST-based, low false-positive
# ---------------------------------------------------------------------------

def rule_toplevel_secret_network(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    """
    Flags code that executes at import time (module top level, not inside a
    function or class) and both accesses secrets and makes network calls.

    This is the high-confidence poisoning signal: malicious packages run their
    payload immediately on import, legitimate packages put network calls inside
    functions.
    """
    if pkg.name.lower().replace("-", "_") in NETWORK_CREDENTIAL_WHITELIST:
        return []

    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    findings = []
    for py_file in pkg_dir.rglob("*.py"):
        try:
            source = py_file.read_text(errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        toplevel_source = _extract_toplevel_source(tree, source)
        if not toplevel_source:
            continue

        has_secret = bool(_SECRET_RE.search(toplevel_source))
        has_network = bool(_NETWORK_CALL_RE.search(toplevel_source))

        if has_secret and has_network:
            rel = py_file.relative_to(pkg_dir.parent)
            findings.append(Finding(
                severity=Severity.HIGH,
                message=f"top-level secret access + network call in {rel}",
                detail=(
                    "Code outside any function reads credentials and makes "
                    "network calls — executes automatically on import."
                ),
            ))
    return findings


def _extract_toplevel_source(tree: ast.Module, source: str) -> str:
    """Return only the source lines that belong to top-level statements
    (not inside function or class definitions)."""
    lines = source.splitlines()
    toplevel_lines: list[str] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
            start = node.lineno - 1
            end = node.end_lineno
            toplevel_lines.extend(lines[start:end])

    return "\n".join(toplevel_lines)


# ---------------------------------------------------------------------------
# Rule: obfuscation detection (HIGH)
# ---------------------------------------------------------------------------

def rule_obfuscation(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    """Detect common obfuscation techniques used in malicious packages."""
    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        if _OBFUSCATION_RE.search(content):
            rel = py_file.relative_to(pkg_dir.parent)
            return [Finding(
                severity=Severity.HIGH,
                message=f"obfuscated or dynamic code execution in {rel}",
                detail="Found exec/eval/base64-decode pattern — common in malicious packages.",
            )]
    return []


# ---------------------------------------------------------------------------
# Rule: secret access + network in same file (MEDIUM) — file-level heuristic
# ---------------------------------------------------------------------------

def rule_secret_plus_network(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    """
    Coarser file-level check: flags files that both reference credentials and
    make network calls, regardless of whether it happens at top level.
    Severity is MEDIUM because many legitimate packages (SDKs, API clients)
    naturally do this inside functions.
    """
    if pkg.name.lower().replace("-", "_") in NETWORK_CREDENTIAL_WHITELIST:
        return []

    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    flagged: list[str] = []
    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        if _SECRET_RE.search(content) and _NETWORK_CALL_RE.search(content):
            flagged.append(str(py_file.relative_to(pkg_dir.parent)))

    if flagged:
        return [Finding(
            severity=Severity.MEDIUM,
            message=f"credential access + network calls in {len(flagged)} file(s)",
            detail=", ".join(flagged[:3]) + (" ..." if len(flagged) > 3 else ""),
        )]
    return []


# ---------------------------------------------------------------------------
# Rule: secret access (LOW)
# ---------------------------------------------------------------------------

def rule_secret_access(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    flagged: list[str] = []
    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        if _SECRET_RE.search(content):
            flagged.append(str(py_file.relative_to(pkg_dir.parent)))

    if flagged:
        return [Finding(
            severity=Severity.LOW,
            message=f"references sensitive paths or credential names ({len(flagged)} file(s))",
            detail=", ".join(flagged[:3]) + (" ..." if len(flagged) > 3 else ""),
        )]
    return []


# ---------------------------------------------------------------------------
# All package-level rules in priority order
# ---------------------------------------------------------------------------

PACKAGE_RULES = [
    rule_known_bad_version,
    rule_cve_lookup,
    rule_pth_startup,
    rule_toplevel_secret_network,   # HIGH, AST-based, low false-positive
    rule_obfuscation,               # HIGH, obfuscation signals
    rule_secret_plus_network,       # MEDIUM, file-level heuristic
    rule_secret_access,             # LOW
]
