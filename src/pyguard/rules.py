"""
Detection rules. Each rule takes a package + environment context and returns
a list of Finding objects.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
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

NETWORK_PATTERNS = [
    r"import requests",
    r"from requests",
    r"import httpx",
    r"from httpx",
    r"import urllib",
    r"from urllib",
    r"import aiohttp",
    r"from aiohttp",
    r"socket\.connect",
    r"socket\.create_connection",
    r"\.post\(",
    r"\.get\(",
    r"urllib\.request\.urlopen",
]

_SECRET_RE = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)
_NETWORK_RE = re.compile("|".join(NETWORK_PATTERNS))
_PTH_EXECUTABLE_RE = re.compile(r"^\s*(import\s+|exec\s*\(|__import__)", re.MULTILINE)


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

    vulns = data.get("vulns", [])
    findings = []
    for vuln in vulns:
        vuln_id = vuln.get("id", "unknown")
        summary = vuln.get("summary", "no summary available")
        # Determine severity from CVSS if present
        severity = Severity.MEDIUM
        for severity_entry in vuln.get("severity", []):
            score = severity_entry.get("score", "")
            if score.startswith("CVSS:") and "/AV:" in score:
                # Extract base score if present
                pass
        aliases = vuln.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        findings.append(Finding(
            severity=severity,
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
# Rule: sitecustomize / usercustomize present
# ---------------------------------------------------------------------------

def rule_sitecustomize(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    # This is an environment-level check, not package-specific.
    # Only report it once, attributed to the first package alphabetically.
    # We handle attribution in scanner.py instead; here just return findings
    # for any package named "__env__" sentinel — scanner calls this separately.
    return []


def check_startup_hooks(env: EnvironmentInfo) -> list[Finding]:
    """Environment-level check, called once by the scanner."""
    findings = []
    if env.sitecustomize:
        findings.append(Finding(
            severity=Severity.HIGH,
            message=f"sitecustomize.py found in site-packages",
            detail=str(env.sitecustomize),
        ))
    if env.usercustomize:
        findings.append(Finding(
            severity=Severity.HIGH,
            message=f"usercustomize.py found in site-packages",
            detail=str(env.usercustomize),
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule: secret access + network in same file (HIGH combo)
# ---------------------------------------------------------------------------

def rule_secret_plus_network(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    findings = []
    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        has_secret = bool(_SECRET_RE.search(content))
        has_network = bool(_NETWORK_RE.search(content))
        if has_secret and has_network:
            rel = py_file.relative_to(pkg_dir.parent)
            findings.append(Finding(
                severity=Severity.HIGH,
                message=f"secret access + outbound network in {rel}",
                detail="Same file reads credentials and makes network calls.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Rule: secret access (MEDIUM)
# ---------------------------------------------------------------------------

def rule_secret_access(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    flagged_files: list[str] = []
    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        if _SECRET_RE.search(content):
            flagged_files.append(str(py_file.relative_to(pkg_dir.parent)))

    if flagged_files:
        return [Finding(
            severity=Severity.MEDIUM,
            message=f"references sensitive paths or credential names ({len(flagged_files)} file(s))",
            detail=", ".join(flagged_files[:3]) + (" ..." if len(flagged_files) > 3 else ""),
        )]
    return []


# ---------------------------------------------------------------------------
# Rule: network calls (LOW)
# ---------------------------------------------------------------------------

def rule_network_calls(pkg: InstalledPackage, env: EnvironmentInfo) -> list[Finding]:
    pkg_dir = get_package_directory(pkg)
    if not pkg_dir:
        return []

    for py_file in pkg_dir.rglob("*.py"):
        try:
            content = py_file.read_text(errors="replace")
        except OSError:
            continue
        if _NETWORK_RE.search(content):
            return [Finding(
                severity=Severity.LOW,
                message="makes outbound network calls",
                detail="",
            )]
    return []


# ---------------------------------------------------------------------------
# All package-level rules in priority order
# ---------------------------------------------------------------------------

PACKAGE_RULES = [
    rule_known_bad_version,
    rule_cve_lookup,
    rule_pth_startup,
    rule_secret_plus_network,
    rule_secret_access,
    rule_network_calls,
]
