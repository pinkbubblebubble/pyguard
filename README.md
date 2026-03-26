<div align="center">
  <img src="assets/logo.svg" width="100" alt="pyguard logo"/>
  <h1>pyguard</h1>
  <p><strong>Scan your Python environment for poisoned packages.</strong></p>

  <p>
    <a href="https://github.com/pinkbubblebubble/pyguard/actions"><img src="https://github.com/pinkbubblebubble/pyguard/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
    <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue" alt="Python versions"/>
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  </p>

  <p>
    <a href="README.md">English</a> · <a href="README.zh.md">中文</a>
  </p>
</div>

---

On March 24, 2025, litellm versions 1.82.7 and 1.82.8 were quietly poisoned. The malicious release added a `.pth` file that ran automatically on every Python startup — silently reading API keys, SSH credentials, and cloud tokens, then sending them to an external server.

No CVE was filed. pip-audit saw nothing. The package came from the real PyPI project.

**pyguard is built to catch exactly this.**

---

## What it checks

| Check | What it catches |
|---|---|
| **CVE lookup** | Known vulnerabilities via the [OSV database](https://osv.dev) |
| **Known bad versions** | Confirmed malicious releases (e.g. litellm 1.82.7 / 1.82.8) |
| **`.pth` startup backdoors** | Code that executes automatically before your program starts |
| **`sitecustomize` injection** | `sitecustomize.py` / `usercustomize.py` in site-packages |
| **Secret + network combo** | Files that read credentials *and* make outbound calls |
| **Secret access** | References to env vars, `~/.ssh`, `~/.aws`, kubeconfig, API key names |

---

## Install

```bash
pip install git+https://github.com/pinkbubblebubble/pyguard.git
```

---

## Usage

```bash
# Scan your entire environment
pyguard scan

# Scan a specific package
pyguard scan litellm

# Skip CVE network lookup (faster, offline)
pyguard scan --no-cve

# Show full details for every finding
pyguard scan --verbose
```

### Example output

```
Scanning: /Users/you/.venv/bin/python

[HIGH]  litellm 1.82.8
         • known malicious version (supply chain incident 2025-03-24)
           Supply chain attack via compromised CI/CD pipeline. Malicious .pth
           file exfiltrates secrets on Python startup.
         • startup .pth file with executable code: litellm_init.pth
           This file runs automatically when Python starts.

[HIGH]  requests 2.32.3
         • known vulnerability: CVE-2024-47081
           Credentials may be leaked to third-party servers via Authorization headers
         • secret access + outbound network in requests/sessions.py
           Same file reads credentials and makes network calls.

[MEDIUM] boto3 1.34.0
         • references sensitive paths or credential names (2 file(s))

47 packages scanned  2 HIGH  1 MEDIUM  44 clean
```

---

## How pyguard differs from existing tools

Most Python security tools look for CVEs. pyguard looks for **poisoned releases** — a legitimate package tampered with at the release level, often with no CVE filed.

| Capability | pip-audit | safety | bandit | semgrep | **pyguard** |
|---|:---:|:---:|:---:|:---:|:---:|
| CVE detection | ✅ | ✅ | ❌ | ❌ | ✅ |
| Static code analysis | ❌ | ❌ | ✅ | ✅ | ✅ |
| Scans local site-packages | ❌ | ❌ | ❌ | ❌ | ✅ |
| `.pth` startup backdoor detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Supply-chain poisoning detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Attributes findings to specific package | ❌ | ❌ | ❌ | ❌ | ✅ |
| Secret + exfiltration combo detection | ❌ | ❌ | partial | partial | ✅ |

**pip-audit / safety** are excellent for CVEs, but blind to poisoned releases with no CVE filed — the litellm incident had no CVE when it happened.

**bandit / semgrep** are great for scanning *your own* code, not for inspecting installed third-party packages as a unit and attributing risk back to the package.

---

## Use in CI

Exit code is `1` if any HIGH findings are detected, making it easy to fail a pipeline:

```yaml
- name: Check for poisoned packages
  run: pyguard scan --no-cve
```

---

## Contributing

PRs to [`data/known_bad.json`](src/pyguard/data/known_bad.json) are especially welcome when new supply-chain incidents are confirmed.

```json
{
  "package-name": {
    "versions": ["x.y.z"],
    "reason": "Brief description of the incident.",
    "reference": "https://link-to-issue-or-report"
  }
}
```

---

## License

MIT
