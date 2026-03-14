"""
CLI entry point using Click.
"""

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from pathlib import Path

from fetcher import clone_repo, cleanup
from scanner import scan_directory

console = Console()


@click.command()
@click.argument("url")
@click.option("--output", "-o", default=None, help="Export findings to JSON file")
def main(url: str, output: str | None):
    """
    🔐 Scan a GitHub repository for leaked secrets.

    Usage: leak-scan https://github.com/user/repo
    """
    console.print(f"\n[bold cyan]🔐 GitHub Leak Scanner[/bold cyan]")
    console.print(f"[dim]Scanning:[/dim] {url}\n")

    # 1. Clone
    with console.status("[bold yellow]Cloning repository...[/bold yellow]"):
        try:
            temp_dir, repo_name = clone_repo(url)
        except ValueError as e:
            console.print(f"[bold red]❌ Error:[/bold red] {e}")
            raise SystemExit(1)

    # 2. Scan
    with console.status("[bold yellow]Scanning files...[/bold yellow]"):
        findings = scan_directory(temp_dir)

    # 3. Cleanup
    cleanup(temp_dir)

    # 4. Display results
    if not findings:
        console.print("[bold green]✅ No secrets found.[/bold green]\n")
        return

    console.print(f"[bold red]⚠️  {len(findings)} finding(s) detected:[/bold red]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=8)
    table.add_column("Pattern", width=28)
    table.add_column("File", width=35)
    table.add_column("Line", width=5)

    severity_colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}

    for f in findings:
        color = severity_colors.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["pattern"],
            f["file"].split("/")[-1],
            str(f["line"]),
        )

    console.print(table)

    # 5. JSON export optionnel
    if output:
        import json
        Path(output).write_text(json.dumps(findings, indent=2))
        console.print(f"\n[green]📄 Report saved to {output}[/green]")

    console.print()