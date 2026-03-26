# pyguard

Scan your Python environment for poisoned packages.

pyguard combines two things most tools do separately: **CVE detection** and **supply-chain poisoning detection**.

CVE scanners miss poisoned releases with no filed vulnerability. Static analyzers miss the `.pth` backdoor that runs before your code starts. pyguard does both.

---

## Why this exists

In March 2025, litellm versions 1.82.7 and 1.82.8 were poisoned via a compromised CI/CD pipeline. The malicious versions added a `.pth` file that executed automatically on every Python startup — reading API keys, SSH credentials, and cloud tokens, then exfiltrating them to an external server.

No CVE was filed. No existing scanner caught it. `pip install litellm` gave you the real package from the real PyPI project.

pyguard is built to catch exactly this class of attack.

---

## Install

```bash
pip install pyguard
```

## Usage

```bash
pyguard scan                  # scan all packages in current environment
pyguard scan litellm          # scan one specific package
```

## Example output

```
Scanning: /Users/you/.venv/lib/python3.11/site-packages

[HIGH]   litellm 1.82.8
         • known malicious version (supply chain incident 2025-03-24)
         • startup .pth file detected: litellm_init.pth
         • .pth contains executable import statement
         • reads os.environ + makes outbound HTTP calls

[MEDIUM] requests-wrapper 0.3.1
         • references ~/.aws and ~/.ssh paths
         • contains outbound network calls

23 packages scanned — 1 HIGH, 1 MEDIUM, 21 clean
```

---

## How it works

pyguard runs four layers of checks against your installed packages:

**1. CVE lookup**
Queries the [OSV vulnerability database](https://osv.dev) for known CVEs and security advisories for every installed package and version.

**2. Startup execution check**
Detects `.pth` files, `sitecustomize.py`, and `usercustomize.py` that execute code automatically when Python starts — before your program runs a single line.

**3. Known bad versions**
Matches installed packages against a maintained denylist of confirmed malicious releases (e.g. litellm 1.82.7 / 1.82.8).

**4. Static behavior analysis**
Scans package source for high-risk signal combinations: files that both access secrets (env vars, `~/.ssh`, `~/.aws`, cloud credentials) and make outbound network calls.

---

## How pyguard differs from existing tools

Most Python security tools focus on CVEs or static code quality. pyguard focuses on a different threat model: **a legitimate package that has been poisoned at the release level**.

| Capability | pip-audit | safety | bandit | semgrep | pyguard |
|---|---|---|---|---|---|
| CVE detection | ✅ | ✅ | ❌ | ❌ | ✅ |
| Static code analysis | ❌ | ❌ | ✅ | ✅ | ✅ |
| Scans local environment (site-packages) | ❌ | ❌ | ❌ | ❌ | ✅ |
| Detects `.pth` startup backdoors | ❌ | ❌ | ❌ | ❌ | ✅ |
| Supply-chain poisoning detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Attributes findings to specific package | ❌ | ❌ | ❌ | ❌ | ✅ |
| Detects secret access + exfiltration combo | ❌ | ❌ | partial | partial | ✅ |

**pip-audit / safety**: excellent for known CVEs, but blind to poisoned releases with no CVE filed — the litellm incident had no CVE.

**bandit / semgrep**: great for scanning your own code, not designed to inspect installed third-party packages as a unit and attribute risk back to them.

pyguard combines both: *CVE coverage + runtime supply-chain inspection for Python environments*.

---

## Detection rules

| Rule | Severity | What it checks |
|------|----------|----------------|
| CVE lookup | HIGH / MEDIUM | queries OSV database for known vulnerabilities |
| Known malicious version | HIGH | matches against confirmed bad release denylist |
| `.pth` startup execution | HIGH | `.pth` file with executable Python statements |
| `sitecustomize` injection | HIGH | `sitecustomize.py` / `usercustomize.py` present |
| Secret + network combo | HIGH | same file reads credentials AND makes outbound calls |
| Secret access | MEDIUM | references to env vars, `~/.ssh`, `~/.aws`, kubeconfig, known key names |
| Network calls | LOW | uses `requests`, `httpx`, `urllib`, `socket` |

---

## Scope

pyguard v1 is intentionally narrow: **local environment, static analysis only**.

Out of scope for v1:
- Dynamic sandbox execution
- Network traffic monitoring
- GitHub Actions workflow scanning
- CI/CD integration

---

## Contributing

PRs to `data/known_bad.json` are especially welcome when new supply-chain incidents are confirmed.

---

## License

MIT
