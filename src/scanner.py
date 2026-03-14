"""
Core scanning engine.
Takes file content and returns all pattern matches found.
"""

import re
import git
import concurrent.futures
from pathlib import Path
from patterns import PATTERNS
from entropy import is_high_entropy

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
        # Prevent OOM by reading line by line
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                # 1. Regex pass
                regex_matched = False
                for pattern in PATTERNS:
                    if re.search(pattern["regex"], line):
                        regex_matched = True
                        findings.append({
                            "file": str(file_path),
                            "line": line_number,
                            "pattern": pattern["name"],
                            "severity": pattern["severity"],
                            "content": line.strip()[:120],  # max 120 chars pour sécurité
                        })
                
                # 2. Heuristic pass (Entropy) - only if no format matched to avoid duplicates
                if not regex_matched:
                    # Split line into words and evaluate long standalone sequences
                    words = re.findall(r'\S+', line)
                    for word in words:
                        if is_high_entropy(word, threshold=4.5, min_length=16):
                            findings.append({
                                "file": str(file_path),
                                "line": line_number,
                                "pattern": "High Entropy String",
                                "severity": "MEDIUM",
                                "content": word[:120],
                            })
                            break # Limit to 1 generic entropy finding per line to avoid spam
    except Exception as e:
        # Log or print error ideally. For now, we skip safely without crashing.
        # print(f"Warning: Failed to read {file_path}: {e}")
        pass

    return findings


def scan_directory(directory: Path) -> list[dict]:
    """
    Recursively scan all files in a directory using multiprocessing.
    Returns all findings sorted by severity.
    """
    all_findings = []
    files_to_scan = []

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            # Check for .env files directly by filename synchronously
            if file_path.name == ".env" or file_path.suffix == ".env":
                all_findings.append({
                    "file": str(file_path),
                    "line": 0,
                    "pattern": ".env file detected",
                    "severity": "LOW",
                    "content": "File name match",
                })
            
            # Queue files for content scanning
            files_to_scan.append(file_path)

    # Parallelize file scanning
    if files_to_scan:
        with concurrent.futures.ProcessPoolExecutor() as executor:
            # Map returns results in the same order as files_to_scan
            results = executor.map(scan_file, files_to_scan)
            for file_findings in results:
                all_findings.extend(file_findings)

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return all_findings


def scan_git_history(directory: Path) -> list[dict]:
    """
    Scan the entire Git commit history via git log diffs.
    Only scans added lines (+) in the diffs to avoid duplicate alerts 
    on context lines or removed lines.
    """
    all_findings = []
    
    try:
        repo = git.Repo(directory)
    except git.exc.InvalidGitRepositoryError:
        return []
        
    try:
        # Fetch the entire git patch history efficiently
        log_output = repo.git.log('-p', '--all')
    except git.exc.GitCommandError:
        return []
        
    current_commit = "unknown"
    current_file = "unknown"
    
    for line in log_output.splitlines():
        if line.startswith('commit '):
            current_commit = line.split()[1][:7]
        elif line.startswith('diff --git '):
            # Typical format: diff --git a/backend/app.py b/backend/app.py
            parts = line.split(' b/')
            if len(parts) == 2:
                current_file = parts[1]
                
        elif line.startswith('+') and not line.startswith('+++'):
            # This is a newly added line in this specific commit diff
            added_text = line[1:]
            
            # 1. Regex Pass
            regex_matched = False
            for pattern in PATTERNS:
                if re.search(pattern["regex"], added_text):
                    regex_matched = True
                    all_findings.append({
                        "file": str(current_file),
                        "line": f"commit:{current_commit}",
                        "pattern": pattern["name"],
                        "severity": pattern["severity"],
                        "content": added_text.strip()[:120],
                    })
                    
            # 2. Heuristic Pass
            if not regex_matched:
                words = re.findall(r'\S+', added_text)
                for word in words:
                    if is_high_entropy(word, threshold=4.5, min_length=16):
                        all_findings.append({
                            "file": str(current_file),
                            "line": f"commit:{current_commit}",
                            "pattern": "High Entropy String",
                            "severity": "MEDIUM",
                            "content": word[:120],
                        })
                        break
                        
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return all_findings