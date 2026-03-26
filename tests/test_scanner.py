"""Tests for scanner orchestration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pyguard.environment import InstalledPackage, EnvironmentInfo
from pyguard.rules import Finding, Severity
from pyguard.scanner import scan, PackageResult, ScanResult


def make_env(packages=None) -> EnvironmentInfo:
    return EnvironmentInfo(
        python_executable="/usr/bin/python3",
        site_packages=[],
        packages=packages or [],
        pth_files=[],
        sitecustomize=None,
        usercustomize=None,
    )


def make_pkg(name="testpkg", version="1.0.0") -> InstalledPackage:
    return InstalledPackage(name=name, version=version, location=Path("/fake"))


class TestPackageResult:
    def test_severity_empty(self):
        r = PackageResult(package=make_pkg())
        assert r.severity is None
        assert r.is_clean

    def test_severity_high_wins(self):
        r = PackageResult(package=make_pkg(), findings=[
            Finding(Severity.LOW, "low"),
            Finding(Severity.HIGH, "high"),
            Finding(Severity.MEDIUM, "med"),
        ])
        assert r.severity == Severity.HIGH
        assert not r.is_clean


class TestScan:
    def test_scan_single_package(self):
        pkg = make_pkg(name="litellm", version="1.82.8")
        env = make_env(packages=[pkg])

        # Only run known_bad rule to keep test fast and deterministic
        with patch("pyguard.scanner.PACKAGE_RULES", new=__import__("pyguard.rules", fromlist=["rule_known_bad_version"]).PACKAGE_RULES[:1]):
            result = scan(env, package_name="litellm")

        assert len(result.package_results) == 1
        assert result.package_results[0].severity == Severity.HIGH

    def test_scan_filters_by_name(self):
        packages = [make_pkg("litellm", "1.82.8"), make_pkg("requests", "2.31.0")]
        env = make_env(packages=packages)

        with patch("pyguard.scanner.PACKAGE_RULES", []):
            result = scan(env, package_name="requests")

        assert len(result.package_results) == 1
        assert result.package_results[0].package.name == "requests"

    def test_scan_all_packages(self):
        packages = [make_pkg("pkgA"), make_pkg("pkgB")]
        env = make_env(packages=packages)

        with patch("pyguard.scanner.PACKAGE_RULES", []):
            result = scan(env)

        assert len(result.package_results) == 2

    def test_results_sorted_high_first(self):
        packages = [make_pkg("clean"), make_pkg("litellm", "1.82.8")]
        env = make_env(packages=packages)

        from pyguard.rules import rule_known_bad_version
        with patch("pyguard.scanner.PACKAGE_RULES", [rule_known_bad_version]):
            result = scan(env)

        assert result.package_results[0].package.name == "litellm"

    def test_high_low_properties(self):
        packages = [make_pkg("litellm", "1.82.8"), make_pkg("clean")]
        env = make_env(packages=packages)

        from pyguard.rules import rule_known_bad_version
        with patch("pyguard.scanner.PACKAGE_RULES", [rule_known_bad_version]):
            result = scan(env)

        assert len(result.high) == 1
        assert len(result.clean) == 1
