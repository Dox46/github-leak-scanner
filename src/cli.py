import click
import tempfile
from rich.console import Console
from pathlib import Path

from fetcher import clone_repo
from scanner import scan_directory
from reporter import report_to_console, report_to_json

console = Console()

@click.command()
@click.argument("url")
@click.option("--output", "-o", default=None, help="Export findings to JSON file")
@click.option("--token", "-t", default=None, help="GitHub Personal Access Token for private repos")
@click.option("--history", is_flag=True, help="Scan the full git commit history instead of just the latest files")
def main(url: str, output: str | None, token: str | None, history: bool):
    """
    Scan a GitHub repository for leaked secrets.

    Usage: leak-scan https://github.com/user/repo
    """
    console.print(f"\n[bold cyan]GitHub Leak Scanner[/bold cyan]")
    console.print(f"[dim]Scanning:[/dim] {url}\n")
    
    findings = []
    
    # Using tempfile context manager to ensure guaranteed cleanup
    with tempfile.TemporaryDirectory(prefix="leak_scan_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        
        with console.status("[bold yellow]Cloning repository...[/bold yellow]"):
            try:
                # The fetcher must clone INTO the existing temp_dir
                repo_name = clone_repo(url, temp_dir, token=token, history=history)
            except ValueError as e:
                console.print(f"[bold red]Error:[/bold red] {e}")
                raise SystemExit(1)

        with console.status("[bold yellow]Scanning files...[/bold yellow]"):
            if history:
                from scanner import scan_git_history
                findings = scan_git_history(temp_dir)
            else:
                findings = scan_directory(temp_dir)

    # Reporting phase
    report_to_console(findings)
    
    if output:
        report_to_json(findings, output)

    console.print()