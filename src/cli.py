import click
import tempfile
import logging
from rich.console import Console
from rich.logging import RichHandler
from pathlib import Path

from fetcher import clone_repo
from scanner import scan_directory
from reporter import report_to_console, report_to_json, report_to_html

console = Console()

@click.command()
@click.argument("url")
@click.option("--output", "-o", default=None, help="Export findings to JSON file")
@click.option("--html", default=None, help="Export findings to a standalone interactive HTML Dashboard file")
@click.option("--token", "-t", default=None, help="GitHub Personal Access Token for private repos")
@click.option("--history", is_flag=True, help="Scan the full git commit history instead of just the latest files")
@click.option("--debug", is_flag=True, help="Enable debug logging output")
def main(url: str, output: str | None, html: str | None, token: str | None, history: bool, debug: bool) -> None:
    """
    Scan a GitHub repository for leaked secrets.

    Usage: leak-scan https://github.com/user/repo
    """
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console, show_path=False)]
    )
    logger = logging.getLogger("leak-scanner")

    console.print(f"\n[bold cyan]GitHub Leak Scanner[/bold cyan]")
    logger.debug(f"Starting scan for {url} (History: {history})")
    console.print(f"[dim]Scanning:[/dim] {url}\n")
    
    findings = []
    
    # Using tempfile context manager to ensure guaranteed cleanup
    with tempfile.TemporaryDirectory(prefix="leak_scan_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        
        with console.status("[bold yellow]Cloning repository...[/bold yellow]"):
            try:
                # The fetcher must clone INTO the existing temp_dir
                logger.debug("Calling fetcher to clone repository")
                repo_name = clone_repo(url, temp_dir, token=token, history=history)
            except ValueError as e:
                logger.error(f"Clone failed: {e}")
                console.print(f"[bold red]Error:[/bold red] {e}")
                raise SystemExit(1)

        with console.status("[bold yellow]Scanning files...[/bold yellow]"):
            if history:
                logger.debug("History mode enabled, invoking scan_git_history")
                from scanner import scan_git_history
                findings = scan_git_history(temp_dir)
            else:
                logger.debug("Invoking scan_directory")
                findings = scan_directory(temp_dir)
                
            # Normalize absolute paths down to relative repo-root formats
            for f in findings:
                try:
                    rel_path = Path(f.file).relative_to(temp_dir)
                    f.file = str(rel_path).replace('\\\\', '/')
                except ValueError:
                    pass

    # Reporting phase
    report_to_console(findings)
    
    if output:
        report_to_json(findings, output)
        
    if html:
        report_to_html(findings, url, html)

    console.print()

if __name__ == "__main__":
    main()