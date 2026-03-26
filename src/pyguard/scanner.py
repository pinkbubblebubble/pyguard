"""
Orchestrate scanning: run all rules against each package, assign severity,
return structured results.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from pyguard.environment import InstalledPackage, EnvironmentInfo
from pyguard.rules import (
    Finding,
    Severity,
    PACKAGE_RULES,
    check_startup_hooks,
)
from typing import Callable


@dataclass
class PackageResult:
    package: InstalledPackage
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


@dataclass
class ScanResult:
    env: EnvironmentInfo
    package_results: list[PackageResult]
    env_findings: list[Finding] = field(default_factory=list)

    @property
    def high(self) -> list[PackageResult]:
        return [r for r in self.package_results if r.severity == Severity.HIGH]

    @property
    def medium(self) -> list[PackageResult]:
        return [r for r in self.package_results if r.severity == Severity.MEDIUM]

    @property
    def low(self) -> list[PackageResult]:
        return [r for r in self.package_results if r.severity == Severity.LOW]

    @property
    def clean(self) -> list[PackageResult]:
        return [r for r in self.package_results if r.is_clean]


def scan(
    env: EnvironmentInfo,
    package_name: str | None = None,
    rules: list[Callable] | None = None,
) -> ScanResult:
    packages = env.packages
    if package_name:
        normalized = package_name.lower().replace("-", "_")
        packages = [
            p for p in packages
            if p.name.lower().replace("-", "_") == normalized
        ]

    active_rules = rules if rules is not None else PACKAGE_RULES
    env_findings = check_startup_hooks(env)
    results = _scan_packages(packages, env, active_rules)
    return ScanResult(env=env, package_results=results, env_findings=env_findings)


def _scan_single(pkg: InstalledPackage, env: EnvironmentInfo, rules: list[Callable]) -> PackageResult:
    findings: list[Finding] = []
    seen_messages: set[str] = set()

    for rule in rules:
        for finding in rule(pkg, env):
            # De-duplicate: skip if a higher-priority rule already caught this signal
            if finding.message not in seen_messages:
                # If we already have a HIGH finding for secret+network, skip
                # the lower-severity secret-only and network-only findings
                if finding.severity in (Severity.MEDIUM, Severity.LOW):
                    if any(
                        f.severity == Severity.HIGH and "secret" in f.message and "network" in f.message
                        for f in findings
                    ):
                        continue
                findings.append(finding)
                seen_messages.add(finding.message)

    return PackageResult(package=pkg, findings=findings)


def _scan_packages(packages: list[InstalledPackage], env: EnvironmentInfo, rules: list[Callable]) -> list[PackageResult]:
    results: list[PackageResult] = []

    # CVE lookups are network-bound; run them in threads.
    # Static rules are CPU-bound but fast; run them in-thread too for simplicity.
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_pkg = {
            executor.submit(_scan_single, pkg, env, rules): pkg
            for pkg in packages
        }
        for future in as_completed(future_to_pkg):
            try:
                results.append(future.result())
            except Exception:
                pkg = future_to_pkg[future]
                results.append(PackageResult(package=pkg))

    # Sort: HIGH first, then MEDIUM, LOW, clean; alphabetical within group
    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, None: 3}
    results.sort(key=lambda r: (severity_order[r.severity], r.package.name.lower()))
    return results
