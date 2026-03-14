"""
Reporter module for formatting and exporting leak scan results.
"""

import json
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from typing import List
from typing import List
from models import Finding
from html_builder import build_html_report

import webbrowser
import os

console = Console()

def report_to_console(findings: List[Finding]) -> None:
    """Print the findings to the console using a Rich table."""
    if not findings:
        console.print("[bold green]No secrets found.[/bold green]\n")
        return

    console.print(f"[bold red]{len(findings)} finding(s) detected:[/bold red]\n")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=8)
    table.add_column("Pattern", width=28)
    table.add_column("File", width=35)
    table.add_column("Line", width=5)

    severity_colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}

    for f in findings:
        color = severity_colors.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.pattern,
            Path(f.file).name,
            str(f.line),
        )

    console.print(table)


def report_to_json(findings: List[Finding], output_path: str) -> None:
    """Export the findings to a JSON file."""
    try:
        path = Path(output_path)
        path.write_text(json.dumps([f.model_dump() for f in findings], indent=2))
        console.print(f"\n[bold green]Report successfully saved to {output_path}[/bold green]\n")
    except Exception as e:
        console.print(f"[bold red]Failed to save report to {output_path}: {e}[/bold red]\n")

def report_to_html(findings: List[Finding], repo_url: str, output_path: str) -> None:
    """Export the findings to an interactive standalone HTML Dashboard."""
    try:
        html_content = build_html_report(repo_url, findings)
        path = Path(output_path)
        path.write_text(html_content, encoding="utf-8")
        console.print(f"\n[bold green]HTML Dashboard successfully generated at {output_path}[/bold green]")
        
        # Auto-open in the default browser
        abs_path = os.path.abspath(output_path)
        file_uri = f"file:///{abs_path.replace(os.sep, '/')}"
        console.print(f"[dim]Opening {file_uri} in browser...[/dim]\n")
        webbrowser.open_new_tab(file_uri)
    except Exception as e:
        console.print(f"[bold red]Failed to generate HTML report: {e}[/bold red]\n")
