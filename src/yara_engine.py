"""
YARA Engine Wrapper.
Provides Python bindings to the portable YARA executable.
"""

import os
import re
import subprocess
import logging
from pathlib import Path
from typing import List, cast, Literal

from models import Finding
from yara_downloader import ensure_yara_binary

logger = logging.getLogger("leak-scanner")

# Global paths
ROOT_DIR = Path(__file__).parent.parent
RULES_FILE = ROOT_DIR / "rules" / "secrets.yar"

YARA_EXE_PATH: Path | None = None

def initialize_yara_engine() -> None:
    """Download or locate the YARA executable before scanning."""
    global YARA_EXE_PATH
    if not YARA_EXE_PATH:
        YARA_EXE_PATH = ensure_yara_binary()

def get_line_number(file_bytes: bytes, byte_offset: int) -> int:
    """Calculate the 1-indexed line number from a byte offset."""
    # Count newlines up to the offset
    return file_bytes[:byte_offset].count(b'\n') + 1

def parse_yara_output(output: str, file_path: Path) -> List[Finding]:
    """Parse the stdout of `yara -m -s` and build Finding objects."""
    findings: List[Finding] = []
    
    current_rule = None
    current_desc = "Unknown"
    current_severity = "MEDIUM"
    
    try:
        file_bytes = file_path.read_bytes()
    except Exception as e:
        logger.debug(f"Could not read bytes for {file_path}: {e}")
        return findings

    lines = output.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Check if it's a rule match header, e.g. "aws_access_key [description="X",severity="HIGH"] tests/test_patterns.py"
        # Or without meta: "aws_access_key tests/test_patterns.py"
        if not line.startswith("0x"):
            # This is a rule header
            parts = line.split(" ", 1)
            current_rule = parts[0]
            
            # Extract meta tags if present
            desc_match = re.search(r'description="([^"]+)"', line)
            sev_match = re.search(r'severity="([^"]+)"', line)
            
            current_desc = desc_match.group(1) if desc_match else current_rule
            current_severity = sev_match.group(1).upper() if sev_match else "MEDIUM"
        else:
            # It's a string match line, e.g. "0x23a:$re1: AKIAIOSFODNN7EXAMPLE"
            # Format: OFFSET:STRING_IDENTIFIER: CONTENT
            if ":" in line:
                offset_str, rest = line.split(":", 1)
                string_id, content = rest.split(":", 1) if ":" in rest else ("$x", rest)
                content = content.strip()
                
                # Convert hex offset to int
                try:
                    offset = int(offset_str, 16)
                    line_num = get_line_number(file_bytes, offset)
                except ValueError:
                    offset = 0
                    line_num = 0
                
                findings.append(Finding(
                    file=str(file_path),
                    line=line_num,
                    pattern=current_desc,
                    severity=cast(Literal["HIGH", "MEDIUM", "LOW"], current_severity),
                    content=content[:120]
                ))
                
    return findings

def scan_file_with_yara(file_path: Path) -> List[Finding]:
    """
    Spawns the YARA executable to scan a single file.
    """
    if not YARA_EXE_PATH:
        initialize_yara_engine()
        
    findings: List[Finding] = []
    
    if not RULES_FILE.exists():
        logger.error(f"Missing YARA rules file at {RULES_FILE}")
        return findings

    try:
        # Run `yara -m -s <rules> <file>`
        # -m prints metadata (severity, desc)
        # -s prints matched strings and offsets
        result = subprocess.run(
            [str(YARA_EXE_PATH), "-m", "-s", str(RULES_FILE), str(file_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
        
        if result.returncode == 0 or result.returncode == 1:
            # yara returns 0 on match and no match usually, but sometimes 1 if nothing found depending on the OS/version.
            # We just parse the stdout
            if result.stdout:
                findings = parse_yara_output(result.stdout, file_path)
                
    except subprocess.SubprocessError as e:
        logger.debug(f"YARA subprocess error on {file_path}: {e}")
        
    return findings
