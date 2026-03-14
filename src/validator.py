"""
Active Secret Validator.
Takes raw findings and queries 3rd party APIs (GitHub, etc.) to determine if the leaked credentials are actually valid and active.
"""
import logging
import requests
from typing import Literal

logger = logging.getLogger("leak-scanner")

def verify_github_token(token: str) -> Literal["True", "False", "Unknown"]:
    """Verify if a GitHub token (PAT or OAuth) is currently valid."""
    try:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        response = requests.get("https://api.github.com/user", headers=headers, timeout=5)
        
        if response.status_code == 200:
            return "True"
        elif response.status_code == 401:
            return "False"
        return "Unknown"
    except Exception as e:
        logger.debug(f"GitHub token verification failed: {e}")
        return "Unknown"

def enrich_with_verification(pattern: str, content: str) -> Literal["True", "False", "Unknown"]:
    """
    Routes the token to the appropriate 3rd-party API validator based on the YARA pattern matched.
    Only self-contained tokens (like GitHub) can be verified without secondary keys.
    """
    # content might contain whitespace or quotes depending on YARA regex boundaries. 
    # For GitHub, we can extract the gh[p|o]... pattern directly.
    
    if "GitHub" in pattern:
        import re
        match = re.search(r'(gh[p|o|u|s|r]_[A-Za-z0-9_]{36,})', content)
        if match:
            clean_token = match.group(1)
            logger.debug("Actively verifying GitHub token via API...")
            return verify_github_token(clean_token)
            
    return "Unknown"
