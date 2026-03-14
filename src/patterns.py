"""
Regex patterns for detecting secrets in source code.
Each pattern has a name, regex, and severity level.
"""

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "HIGH",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "GitHub Personal Access Token",
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "severity": "HIGH",
    },
    {
        "name": "GitHub OAuth Token",
        "regex": r"gho_[A-Za-z0-9]{36}",
        "severity": "HIGH",
    },
    {
        "name": "Private Key Header",
        "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "HIGH",
    },
    {
        "name": "Generic API Key",
        "regex": r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Password",
        "regex": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Token",
        "regex": r"(?i)(token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        "severity": "MEDIUM",
    },
    {
        "name": ".env file detected",
        "regex": r"^\.env$",
        "severity": "LOW",
    },
]