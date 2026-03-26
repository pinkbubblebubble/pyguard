# pyguard — Python Environment Poison Detector

A lightweight CLI tool to detect poisoned Python packages in your local environment.

---

## What it does

Scans your Python environment for signs of supply-chain poisoning:

- Startup backdoors via `.pth`, `sitecustomize.py`, `usercustomize.py`
- Known malicious package versions (e.g. litellm 1.82.7 / 1.82.8)
- Static code signals: secret access + outbound network in same package

It is **not** a CVE scanner. It focuses on the class of attacks where a legitimate package is compromised at the release level — the kind that won't show up in Dependabot or Snyk.

---

## Install & usage

```bash
pip install pyguard

pyguard scan               # scan all packages in current environment
pyguard scan litellm       # scan one specific package
```

---

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

## Project structure

```
pyguard/
├── pyproject.toml
├── README.md
├── PLAN.md
├── src/
│   └── pyguard/
│       ├── __init__.py
│       ├── cli.py              # CLI entry point (typer)
│       ├── environment.py      # enumerate packages, find .pth / sitecustomize
│       ├── scanner.py          # orchestrate scanning per package
│       ├── rules.py            # detection rules, one function per rule
│       ├── reporter.py         # rich terminal output
│       └── data/
│           └── known_bad.json  # known malicious versions denylist
└── tests/
    ├── test_environment.py
    ├── test_rules.py
    └── test_scanner.py
```

---

## Module responsibilities

### `cli.py`
- Entry point via `typer`
- Commands: `scan`, `scan [package]`
- Passes results to `reporter.py`

### `environment.py`
- Detect current Python executable and site-packages path
- List all installed packages via `importlib.metadata`
- Find all `.pth` files in site-packages
- Find `sitecustomize.py` and `usercustomize.py`

### `scanner.py`
- For each package: run all rules, collect findings
- Assign severity: HIGH / MEDIUM / LOW / CLEAN
- Return structured result list

### `rules.py`
Rules are independent functions, each returns a list of findings.

| Rule | Severity | Logic |
|------|----------|-------|
| `rule_cve_lookup` | HIGH/MEDIUM | query OSV API (`https://api.osv.dev/v1/query`) with package name + version |
| `rule_known_bad_version` | HIGH | match against `known_bad.json` |
| `rule_pth_startup` | HIGH | `.pth` file in package, contains `import` or `exec` |
| `rule_sitecustomize` | HIGH | `sitecustomize.py` present in site-packages root |
| `rule_secret_plus_network` | HIGH | same file reads env/credentials AND makes network calls |
| `rule_secret_access` | MEDIUM | references `os.environ`, `~/.ssh`, `~/.aws`, kubeconfig, known key names |
| `rule_network_calls` | LOW | uses `requests`, `httpx`, `urllib`, `socket` |

### `reporter.py`
- Use `rich` for colored terminal output
- Per-package finding block
- Summary line at the end

### `data/known_bad.json`
```json
{
  "litellm": ["1.82.7", "1.82.8"]
}
```
Updated as new incidents are confirmed.

---

## Detection rules detail

### Startup execution check
Look for `.pth` files belonging to a package that contain Python statements (not just paths). Any line that starts with `import` or contains `exec(` is a signal.

Look for `sitecustomize.py` or `usercustomize.py` in the site-packages root — these run automatically on every Python startup.

### Static string scan
Walk all `.py` files in the package directory. Flag files that contain:

**Secret access patterns:**
- `os.environ`
- `os.getenv`
- `~/.ssh`, `~/.aws`, `/.kube`
- `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.

**Network patterns:**
- `import requests`, `import httpx`, `import urllib`
- `socket.connect`, `.post(`, `.get(`

**High risk combination:** same file contains both secret access + network call → HIGH

---

## Severity levels

| Level | Meaning |
|-------|---------|
| HIGH | Strong evidence of malicious intent or confirmed bad version |
| MEDIUM | Suspicious but could be legitimate (e.g. AWS SDK reading credentials) |
| LOW | Worth noting, low standalone risk |
| CLEAN | No findings |

---

## Development plan

### Day 1 — Scaffold
- [ ] `pyproject.toml` with typer, rich, importlib.metadata
- [ ] `src/pyguard/__init__.py`
- [ ] `cli.py` skeleton with `scan` command

### Day 2 — Environment
- [ ] `environment.py`: list packages, find site-packages, find .pth files
- [ ] `environment.py`: find sitecustomize.py / usercustomize.py

### Day 3 — Rules
- [ ] `known_bad.json` with initial entries
- [ ] `rules.py`: all 7 rules implemented (including OSV CVE lookup)

### Day 4 — Scanner + Reporter
- [ ] `scanner.py`: run rules per package, assign severity
- [ ] `reporter.py`: rich output, summary line

### Day 5 — Tests + README
- [ ] Unit tests for rules and environment
- [ ] README with install, usage, example output
- [ ] Publish to GitHub

---

## Out of scope for v1

- Dynamic analysis (sandbox execution, syscall tracing)
- Network traffic monitoring
- GitHub Actions workflow scanning
- LLM-powered explanations
- CI integration / GitHub App

These may come in v2 depending on interest.

---

## Inspiration

This tool was built in response to the March 2025 litellm supply-chain incident, where versions 1.82.7 and 1.82.8 were poisoned via a compromised CI/CD pipeline. The malicious versions added a startup `.pth` file that executed on every Python process launch, collecting environment secrets and exfiltrating them to an external domain.

pyguard is designed to catch exactly this class of attack.
