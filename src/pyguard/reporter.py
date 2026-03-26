"""
Terminal output using rich.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from pyguard.rules import Severity
from pyguard.scanner import ScanResult, PackageResult

console = Console()

_SEVERITY_STYLE = {
    Severity.HIGH:   ("bold red",   "[HIGH]  "),
    Severity.MEDIUM: ("yellow",     "[MED]   "),
    Severity.LOW:    ("dim",        "[LOW]   "),
}


def print_scan_result(result: ScanResult, verbose: bool = False) -> None:
    console.print()
    console.print(
        f"[dim]Scanning:[/dim] [bold]{result.env.python_executable}[/bold]"
    )
    console.print()

    # Environment-level findings (sitecustomize etc.)
    if result.env_findings:
        console.print("[bold red]Environment warnings:[/bold red]")
        for f in result.env_findings:
            console.print(f"  [red]•[/red] {f.message}")
            if f.detail:
                console.print(f"    [dim]{f.detail}[/dim]")
        console.print()

    flagged = [r for r in result.package_results if not r.is_clean]

    if not flagged:
        console.print(
            f"[green]All {len(result.package_results)} packages clean.[/green]"
        )
        _print_summary(result)
        return

    for pkg_result in flagged:
        _print_package_result(pkg_result, verbose)

    _print_summary(result)


def _print_package_result(r: PackageResult, verbose: bool) -> None:
    style, label = _SEVERITY_STYLE.get(r.severity, ("white", "[???]   "))
    header = Text()
    header.append(label, style=style)
    header.append(f"{r.package.name} ", style="bold")
    header.append(r.package.version, style="dim")
    console.print(header)

    for finding in r.findings:
        f_style, f_label = _SEVERITY_STYLE.get(finding.severity, ("white", ""))
        console.print(f"         [dim]•[/dim] {finding.message}", style=f_style if finding.severity == Severity.HIGH else "")
        if finding.detail and verbose:
            console.print(f"           [dim]{finding.detail}[/dim]")
        elif finding.detail and finding.severity == Severity.HIGH:
            console.print(f"           [dim]{finding.detail}[/dim]")
    console.print()


def _print_summary(result: ScanResult) -> None:
    total = len(result.package_results)
    n_high = len(result.high)
    n_med = len(result.medium)
    n_low = len(result.low)
    n_clean = len(result.clean)

    parts = [f"[dim]{total} packages scanned[/dim]"]
    if n_high:
        parts.append(f"[bold red]{n_high} HIGH[/bold red]")
    if n_med:
        parts.append(f"[yellow]{n_med} MEDIUM[/yellow]")
    if n_low:
        parts.append(f"[dim]{n_low} LOW[/dim]")
    if n_clean:
        parts.append(f"[green]{n_clean} clean[/green]")

    console.print("  ".join(parts))
    console.print()
