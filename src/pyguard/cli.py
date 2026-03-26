"""
CLI entry point.
"""

from __future__ import annotations

from typing import Optional
import typer
from rich.console import Console

from pyguard import __version__

app = typer.Typer(
    name="pyguard",
    help="Scan your Python environment for poisoned packages.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"pyguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


@app.command()
def scan(
    package: Optional[str] = typer.Argument(
        None,
        help="Package name to scan. If omitted, scans all installed packages.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V",
        help="Show full details for every finding.",
    ),
    no_cve: bool = typer.Option(
        False, "--no-cve",
        help="Skip CVE lookup (faster, offline).",
    ),
) -> None:
    """Scan the current Python environment for poisoned or vulnerable packages."""
    from pyguard.environment import get_environment
    from pyguard.scanner import scan as run_scan
    from pyguard.reporter import print_scan_result
    from pyguard.rules import PACKAGE_RULES, rule_cve_lookup

    active_rules = [r for r in PACKAGE_RULES if not (no_cve and r is rule_cve_lookup)]

    env = get_environment()
    result = run_scan(env, package_name=package, rules=active_rules)
    print_scan_result(result, verbose=verbose)

    # Exit with non-zero if HIGH findings exist
    if result.high or result.env_findings:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
