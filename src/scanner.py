"""
Core scanning engine.
Takes file content and returns all pattern matches found.
"""

import re
import git
import logging
import concurrent.futures
import os
import tempfile
from pathlib import Path
from typing import List, Literal, cast
from entropy import is_high_entropy
from models import Finding
from yara_engine import scan_file_with_yara
from validator import enrich_with_verification
import fnmatch

logger = logging.getLogger("leak-scanner")

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


def scan_file(file_path: Path) -> List[Finding]:
    """
    Scan a single file for secret patterns using YARA and Entropy.
    Returns a list of findings.
    """
    findings: List[Finding] = []

    if should_skip(file_path):
        return findings
        
    yara_findings_raw = scan_file_with_yara(file_path)
    
    yara_lines_dict = {}
    for f in yara_findings_raw:
        if isinstance(f.line, int):
            yara_lines_dict.setdefault(f.line, []).append(f)

    try:
        # 1-pass read to simultaneously check leak-ignore and apply entropy
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                
                # Check for inline ignore flag
                if "leak-ignore" in line:
                    continue
                    
                # If YARA flagged this line, we keep the YARA findings
                if line_number in yara_lines_dict:
                    findings.extend(yara_lines_dict[line_number])
                    continue
                    
                # Otherwise, fallback to entropy analysis
                words = re.findall(r'\S+', line)
                for word in words:
                    if is_high_entropy(word, threshold=4.5, min_length=16):
                        findings.append(Finding(
                            file=str(file_path),
                            line=line_number,
                            pattern="High Entropy String",
                            severity="MEDIUM",
                            content=word[:120],
                        ))
                        break # Limit to 1 generic entropy finding per line
                        
    except Exception as e:
        logger.debug(f"Skipping unreadable file {file_path}: {e}")

    # Active Validation Pass
    for f in findings:
        f.verified = enrich_with_verification(f.pattern, f.content)

    return findings


def scan_directory(directory: Path) -> List[Finding]:
    """
    Recursively scan all files in a directory using multiprocessing.
    Returns all findings sorted by severity.
    """
    all_findings: List[Finding] = []
    files_to_scan = []

    leakignore_path = directory / ".leakignore"
    ignored_patterns = []
    if leakignore_path.exists():
        try:
            ignored_patterns = [line.strip() for line in leakignore_path.read_text("utf-8").splitlines() if line.strip() and not line.startswith("#")]
        except Exception as e:
            logger.debug(f"Failed to read .leakignore: {e}")

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            
            # Sub-path relative to repo root for ignore matching
            try:
                rel_path_str = str(file_path.relative_to(directory)).replace('\\\\', '/')
                skip = False
                for pat in ignored_patterns:
                    # Very basic fnmatch support for .leakignore lines
                    if fnmatch.fnmatch(rel_path_str, pat) or fnmatch.fnmatch(rel_path_str, f"*/{pat}") or fnmatch.fnmatch(rel_path_str, f"{pat}/*"):
                        skip = True
                        break
                if skip:
                    continue
            except ValueError:
                pass
            
            # Check for .env files directly by filename synchronously
            if file_path.name == ".env" or file_path.suffix == ".env":
                all_findings.append(Finding(
                    file=str(file_path),
                    line=0,
                    pattern=".env file detected",
                    severity="LOW",
                    content="File name match",
                ))
            
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
    all_findings.sort(key=lambda x: severity_order.get(x.severity, 99))

    return all_findings


def scan_git_history(directory: Path) -> List[Finding]:
    """
    Scan the entire Git commit history via git log diffs.
    Only scans added lines (+) in the diffs to avoid duplicate alerts 
    on context lines or removed lines.
    """
    all_findings: List[Finding] = []
    
    try:
        repo = git.Repo(directory)
    except git.exc.InvalidGitRepositoryError:
        logger.debug(f"Invalid git repository at {directory}")
        return []
        
    try:
        # Fetch the entire git patch history efficiently
        logger.debug("Executing git log -p --all")
        log_output = repo.git.log('-p', '--all')
    except git.exc.GitCommandError as e:
        logger.debug(f"Git command error: {e}")
        return []
        
    current_commit = "unknown"
    current_file = "unknown"
    
    tmp_fd, tmp_path_str = tempfile.mkstemp(text=True)
    tmp_path = Path(tmp_path_str)
    
    line_mapping = {}
    current_temp_line = 1
    
    with os.fdopen(tmp_fd, "w", encoding="utf-8", errors="ignore") as tmp:
        for line in log_output.splitlines():
            if line.startswith('commit '):
                current_commit = line.split()[1][:7]
            elif line.startswith('diff --git '):
                parts = line.split(' b/')
                if len(parts) == 2:
                    current_file = parts[1]
                    
            elif line.startswith('+') and not line.startswith('+++'):
                added_text = line[1:]
                tmp.write(added_text + "\\n")
                line_mapping[current_temp_line] = (current_commit, current_file)
                current_temp_line += 1
                
    # Batch process the temp file through YARA
    yara_findings_raw = scan_file_with_yara(tmp_path)
    yara_lines_dict = {}
    for yf in yara_findings_raw:
        if isinstance(yf.line, int):
            yara_lines_dict.setdefault(yf.line, []).append(yf)
            
    valid_findings = []
    
    # 1-pass read for ignore flag and entropy
    try:
        with tmp_path.open("r", encoding="utf-8", errors="ignore") as tmp:
            for i, line_content in enumerate(tmp, start=1):
                if "leak-ignore" in line_content:
                    continue
                    
                if i in yara_lines_dict:
                    commit_sha, src_file = line_mapping.get(i, ("unknown", "unknown"))
                    for yf in yara_lines_dict[i]:
                        valid_findings.append(Finding(
                            file=str(src_file),
                            line=f"commit:{commit_sha}",
                            pattern=yf.pattern,
                            severity=yf.severity,
                            content=yf.content,
                        ))
                    continue
                    
                words = re.findall(r'\S+', line_content)
                for word in words:
                    if is_high_entropy(word, threshold=4.5, min_length=16):
                        commit_sha, src_file = line_mapping.get(i, ("unknown", "unknown"))
                        valid_findings.append(Finding(
                            file=str(src_file),
                            line=f"commit:{commit_sha}",
                            pattern="High Entropy String",
                            severity="MEDIUM",
                            content=word[:120],
                        ))
                        break
    finally:
        tmp_path.unlink(missing_ok=True)
                        
    # Active Validation Pass
    for f in valid_findings:
        f.verified = enrich_with_verification(f.pattern, f.content)
        
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    valid_findings.sort(key=lambda x: severity_order.get(x.severity, 99))

    return valid_findings