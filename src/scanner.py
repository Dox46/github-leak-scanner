"""
Core scanning engine.
Takes file content and returns all pattern matches found.
"""

import re
from pathlib import Path
from patterns import PATTERNS

# Extensions de fichiers à ignorer (binaires, inutiles)
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".zip", ".tar", ".gz", ".exe", ".pdf", ".bin",
    ".lock", ".woff", ".woff2", ".ttf", ".eot",
}

# Dossiers à ignorer
IGNORED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv",
    "venv", "dist", "build", ".idea", ".vscode",
}


def should_skip(file_path: Path) -> bool:
    """Return True if the file should be skipped."""
    if file_path.suffix.lower() in IGNORED_EXTENSIONS:
        return True
    for part in file_path.parts:
        if part in IGNORED_DIRS:
            return True
    return False


def scan_file(file_path: Path) -> list[dict]:
    """
    Scan a single file for secret patterns.
    Returns a list of findings.
    """
    findings = []

    if should_skip(file_path):
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern in PATTERNS:
            if re.search(pattern["regex"], line):
                findings.append({
                    "file": str(file_path),
                    "line": line_number,
                    "pattern": pattern["name"],
                    "severity": pattern["severity"],
                    "content": line.strip()[:120],  # max 120 chars pour sécurité
                })

    return findings


def scan_directory(directory: Path) -> list[dict]:
    """
    Recursively scan all files in a directory.
    Returns all findings sorted by severity.
    """
    all_findings = []

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            all_findings.extend(scan_file(file_path))

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return all_findings