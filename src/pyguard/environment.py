"""
Inspect the current Python environment: installed packages, site-packages
paths, .pth files, and startup hooks.
"""

from __future__ import annotations

import sys
import site
from dataclasses import dataclass, field
from importlib.metadata import packages_distributions, distributions
from pathlib import Path


@dataclass
class InstalledPackage:
    name: str
    version: str
    location: Path


@dataclass
class EnvironmentInfo:
    python_executable: str
    site_packages: list[Path]
    packages: list[InstalledPackage]
    pth_files: list[Path]
    sitecustomize: Path | None
    usercustomize: Path | None


def get_environment() -> EnvironmentInfo:
    python_executable = sys.executable
    site_packages = _find_site_packages()
    packages = _list_packages()
    pth_files = _find_pth_files(site_packages)
    sitecustomize = _find_startup_file("sitecustomize.py", site_packages)
    usercustomize = _find_startup_file("usercustomize.py", site_packages)

    return EnvironmentInfo(
        python_executable=python_executable,
        site_packages=site_packages,
        packages=packages,
        pth_files=pth_files,
        sitecustomize=sitecustomize,
        usercustomize=usercustomize,
    )


def _find_site_packages() -> list[Path]:
    paths: list[Path] = []
    for p in site.getsitepackages():
        path = Path(p)
        if path.is_dir():
            paths.append(path)
    user_site = site.getusersitepackages()
    if user_site:
        path = Path(user_site)
        if path.is_dir() and path not in paths:
            paths.append(path)
    return paths


def _list_packages() -> list[InstalledPackage]:
    packages = []
    for dist in distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        if not name or not version:
            continue
        location = Path(str(dist._path)).parent if hasattr(dist, "_path") else None
        if location is None:
            try:
                location = Path(str(dist.locate_file(".")))
            except Exception:
                location = Path(sys.prefix) / "lib"
        packages.append(InstalledPackage(name=name, version=version, location=location))
    return packages


def _find_pth_files(site_packages: list[Path]) -> list[Path]:
    pth_files = []
    for sp in site_packages:
        pth_files.extend(sp.glob("*.pth"))
    return pth_files


def _find_startup_file(filename: str, site_packages: list[Path]) -> Path | None:
    for sp in site_packages:
        candidate = sp / filename
        if candidate.exists():
            return candidate
    return None


def get_package_directory(pkg: InstalledPackage) -> Path | None:
    """Return the directory where the package's Python files live."""
    for dist in distributions():
        if dist.metadata["Name"] == pkg.name and dist.metadata["Version"] == pkg.version:
            # Try to find the top-level package directory
            try:
                record = dist.read_text("RECORD")
                if record:
                    for line in record.splitlines():
                        parts = line.split(",")
                        if not parts:
                            continue
                        rel = parts[0]
                        if rel.endswith(".py") and not rel.startswith(".."):
                            candidate = dist.locate_file(rel).parent
                            # Walk up to find a real package dir
                            while candidate != candidate.parent:
                                if (candidate / "__init__.py").exists():
                                    return candidate
                                candidate = candidate.parent
            except Exception:
                pass
            # Fallback: look in site-packages for a dir named after the package
            try:
                sp = Path(str(dist.locate_file(".")))
                normalized = pkg.name.lower().replace("-", "_")
                candidate = sp / normalized
                if candidate.is_dir():
                    return candidate
            except Exception:
                pass
    return None
