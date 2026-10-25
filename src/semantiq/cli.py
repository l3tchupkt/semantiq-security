"""Command Line Interface (CLI) for Semantiq Security."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from semantiq import __version__
from semantiq.client import Semantiq
from semantiq.integrations.mcp.server import MCPServer
from semantiq.models import SeverityLevel, ValidationMode

app = typer.Typer(
    name="semantiq",
    help="Semantiq Security - security research SDK and CLI.",
    add_completion=False,
)
console = Console()

SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 4,
    SeverityLevel.HIGH: 3,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 1,
    SeverityLevel.INFORMATIONAL: 0,
}


@app.command()
def version() -> None:
    """Print Semantiq version and author information."""
    console.print(f"[bold cyan]Semantiq Security[/bold cyan] version [green]{__version__}[/green]")
    console.print("Author: Lakshmikanthan K ([bold]letchupkt[/bold])")


@app.command()
def inspect(
    path: str = typer.Argument(".", help="Path to repository to inspect"),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """Inspect repository structure, detected languages, and security scope."""
    async def _run() -> None:
        async with Semantiq() as security:
            insp = await security.inspect_repository(path)
            if json_output:
                console.print(insp.model_dump_json(indent=2))
                return

            console.print(f"\n[bold green]Repository Inspection:[/bold green] {insp.root_path}")
            console.print(f"Git: {'Yes' if insp.is_git else 'No'} | Revision: {insp.git_revision or 'N/A'} | Dirty: {insp.is_dirty}")
            console.print(f"Total files on disk: {insp.total_files} | In-scope: {len(insp.in_scope_files)} | Excluded: {len(insp.excluded_files)}")
            console.print(f"Security policy: {insp.security_policy_path or 'None found'}")

            table = Table(title="Language Distribution")
            table.add_column("Language", style="cyan")
            table.add_column("File Count", style="magenta")
            for lang, count in sorted(insp.languages.items(), key=lambda x: -x[1]):
                table.add_row(lang.capitalize(), str(count))
            console.print(table)

    asyncio.run(_run())


@app.command()
def scan(
    path: str = typer.Argument(".", help="Target repository directory"),
    focus: str | None = typer.Option(None, "--focus", help="Comma-separated vulnerability classes (e.g., sql-injection,ssrf)"),
    mode: str = typer.Option("standard", "--mode", help="Scan mode: standard or deep"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save report to file"),
    format_type: str = typer.Option("markdown", "--format", help="Report format: markdown, json, sarif"),
    fail_on: str | None = typer.Option(None, "--fail-on-severity", help="Fail with exit code 1 if findings at or above level (critical, high, medium, low)"),
) -> None:
    """Execute vulnerability scan over repository."""
    async def _run() -> None:
        focus_list = [f.strip() for f in focus.split(",")] if focus else None
        async with Semantiq() as security:
            with console.status("[bold green]Scanning repository for vulnerabilities...[/bold green]"):
                result = await security.scan(target=path, focus=focus_list, mode=mode)

            console.print(f"\n[bold]Scan ID:[/bold] [cyan]{result.scan_id}[/cyan]")
            console.print(f"[bold]Total Findings:[/bold] {len(result.findings)}")

            if result.findings:
                table = Table(title="Discovered Findings")
                table.add_column("Severity", style="bold")
                table.add_column("Rule ID")
                table.add_column("Title")
                table.add_column("Location")
                table.add_column("Validation")

                for f in result.findings:
                    sev_style = "red" if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "yellow"
                    table.add_row(
                        f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
                        f.rule_id,
                        f.title,
                        f"{f.file_path}:{f.start_line}",
                        f.validation_status.value,
                    )
                console.print(table)
            else:
                console.print("[green]No vulnerabilities detected within scope.[/green]")

            if output:
                report_str = await security.export_report(result.scan_id, format=format_type)
                Path(output).write_text(report_str, encoding="utf-8")
                console.print(f"[green]Saved {format_type.upper()} report to {output}[/green]")

            # Check failure threshold
            if fail_on:
                threshold_weight = SEVERITY_WEIGHTS.get(SeverityLevel(fail_on.lower()), 99)
                has_breach = any(
                    SEVERITY_WEIGHTS.get(f.severity, 0) >= threshold_weight for f in result.findings
                )
                if has_breach:
                    console.print(f"\n[bold red]FAILURE:[/bold red] Findings meet or exceed severity threshold '{fail_on}'.")
                    sys.exit(1)

    try:
        asyncio.run(_run())
    except Exception as error:
        console.print(f"[bold red]Scan error:[/bold red] {error}")
        sys.exit(2)


@app.command(name="scan-diff")
def scan_diff_command(
    path: str = typer.Argument(".", help="Target repository directory"),
    base: str = typer.Option(..., "--base", help="Base Git revision (e.g. origin/main)"),
    head: str | None = typer.Option(None, "--head", help="Head Git revision (defaults to HEAD)"),
) -> None:
    """Analyze security risks in Git diff between two revisions."""
    async def _run() -> None:
        async with Semantiq() as security:
            with console.status("[bold green]Analyzing Git diff changes...[/bold green]"):
                result = await security.scan_diff(target=path, base=base, head=head)

            console.print(f"\n[bold]Diff Scan ID:[/bold] [cyan]{result.scan_id}[/cyan]")
            console.print(f"Revision Range: {result.git_revision}")
            console.print(f"Findings in changed files: {len(result.findings)}")
            for f in result.findings:
                console.print(f"- [{f.severity.value.upper()}] {f.title} ({f.file_path}:{f.start_line})")

    asyncio.run(_run())


@app.command(name="threat-model")
def threat_model_command(
    path: str = typer.Argument(".", help="Target repository directory"),
    output: str | None = typer.Option(None, "--output", "-o", help="Save threat model to markdown/json file"),
) -> None:
    """Extract entry points, sensitive sinks, and threat boundaries."""
    async def _run() -> None:
        async with Semantiq() as security:
            with console.status("[bold green]Building codebase threat model...[/bold green]"):
                tm = await security.build_threat_model(path)

            console.print(f"\n[bold cyan]Threat Model for {tm.application_name}[/bold cyan]")
            console.print(f"Entry Points: {len(tm.entry_points)} | Trust Boundaries: {len(tm.trust_boundaries)} | Sinks: {len(tm.sensitive_operations)}")

            table = Table(title="Discovered Entry Points")
            table.add_column("Type")
            table.add_column("Identifier")
            table.add_column("Location")
            for ep in tm.entry_points[:10]:
                table.add_row(ep.kind, ep.identifier, f"{ep.file_path}:{ep.line_number}")
            console.print(table)

            if output:
                p = Path(output)
                if p.suffix.lower() == ".json":
                    p.write_text(tm.model_dump_json(indent=2), encoding="utf-8")
                else:
                    lines = [f"# Threat Model: {tm.application_name}\n\n## Entry Points"]
                    for ep in tm.entry_points:
                        lines.append(f"- **{ep.kind}**: `{ep.identifier}` ({ep.file_path}:{ep.line_number})")
                    p.write_text("\n".join(lines), encoding="utf-8")
                console.print(f"[green]Saved threat model to {output}[/green]")

    asyncio.run(_run())


@app.command()
def validate(
    finding_id: str = typer.Argument(..., help="Finding ID to validate"),
    mode: str = typer.Option("static", "--mode", help="Validation mode: static, test_based, manual_plan"),
) -> None:
    """Validate candidate finding evidence."""
    async def _run() -> None:
        async with Semantiq() as security:
            val_mode = ValidationMode(mode.lower())
            result = await security.validate(finding_id, mode=val_mode)
            console.print(f"\n[bold]Validation Result:[/bold] [{result.status.value.upper()}]")
            console.print(f"Mode: {result.mode.value} | Reproducible: {result.is_reproducible}")
            console.print(f"Summary: {result.summary}")
            if result.counter_evidence:
                console.print(f"Counter-Evidence: {result.counter_evidence}")

    asyncio.run(_run())


@app.command()
def patch(
    finding_id: str = typer.Argument(..., help="Finding ID to generate patch for"),
    output: str | None = typer.Option(None, "--output", "-o", help="File to write unified diff patch to"),
) -> None:
    """Generate a unified diff patch enforcing security invariants."""
    async def _run() -> None:
        async with Semantiq() as security:
            p = await security.propose_patch(finding_id)
            if not p.unified_diff:
                console.print(f"[yellow]Could not generate patch: {p.rationale}[/yellow]")
                return

            console.print(f"\n[bold cyan]Patch Proposal for {finding_id}[/bold cyan]")
            console.print(f"Invariant: {p.invariant_enforced}")
            console.print(f"Rationale: {p.rationale}\n")
            console.print(p.unified_diff)

            if output:
                Path(output).write_text(p.unified_diff, encoding="utf-8")
                console.print(f"[green]Saved patch to {output}[/green]")

    asyncio.run(_run())


@app.command(name="verify-patch")
def verify_patch_command(
    finding_id: str = typer.Argument(..., help="Finding ID"),
    patch_file: str | None = typer.Option(None, "--patch-file", help="Path to unified diff patch file"),
) -> None:
    """Verify proposed patch eliminates vulnerability in isolated test copy."""
    async def _run() -> None:
        async with Semantiq() as security:
            res = await security.verify_patch(finding_id)
            status_color = "green" if res.status == "fixed" else "red"
            console.print(f"\n[bold]Verification Status:[/bold] [{status_color}]{res.status.upper()}[/{status_color}]")
            console.print(f"Summary: {res.summary}")

    asyncio.run(_run())


@app.command()
def report(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID"),
    format_type: str = typer.Option("markdown", "--format", help="Report format: markdown, json, sarif"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Export report for an existing scan."""
    async def _run() -> None:
        async with Semantiq() as security:
            rep = await security.export_report(scan_id, format=format_type)
            if output:
                Path(output).write_text(rep, encoding="utf-8")
                console.print(f"[green]Exported {format_type.upper()} report to {output}[/green]")
            else:
                console.print(rep)

    asyncio.run(_run())


@app.command()
def doctor() -> None:
    """Inspect environment, dependencies, runtimes, and local capabilities."""
    import platform
    import shutil

    console.print("\n[bold cyan]Semantiq Security Doctor[/bold cyan]\n")
    console.print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
    console.print(f"Python: {platform.python_version()} ({sys.executable})")

    git_path = shutil.which("git")
    console.print(f"Git: {'[green]Found[/green] (' + git_path + ')' if git_path else '[yellow]Not installed[/yellow]'}")

    rg_path = shutil.which("rg")
    console.print(f"Ripgrep (rg): {'[green]Found[/green] (' + rg_path + ')' if rg_path else '[yellow]Not installed (fallback to Python walker)[/yellow]'}")

    pytest_path = shutil.which("pytest")
    console.print(f"Pytest: {'[green]Found[/green]' if pytest_path else '[yellow]Not installed[/yellow]'}")

    console.print("\n[bold]Security Configuration:[/bold]")
    console.print("Execution allowed by default: [bold green]False (Safe)[/bold green]")
    console.print("Outbound network required: [bold green]False (Offline-first)[/bold green]")
    console.print("Secret scanner redaction: [bold green]Active[/bold green]")


@app.command()
def mcp() -> None:
    """Start the Model Context Protocol (MCP) server over stdio."""
    server = MCPServer()
    asyncio.run(server.run_stdio())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
