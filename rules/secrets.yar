/*
  YARA Rules for Secret Detection
  Replaces the legacy Python Regex engine for industrial-grade scanning.
*/

rule aws_access_key {
    meta:
        description = "AWS Access Key ID"
        severity = "HIGH"
    strings:
        // AKIA or ASIA followed by 16 alphanumeric characters
        $re1 = /A[SK]IA[0-9A-Z]{16}/
    condition:
        $re1
}

rule aws_secret_key {
    meta:
        description = "AWS Secret Access Key"
        severity = "HIGH"
    strings:
        // Looking for explicit assignment to reduce false positives on generic 40-char strings
        $re1 = /aws_secret(_access_key)?[ \t]*[=:][ \t]*["'][A-Za-z0-9\/+=]{40}["']/ nocase
    condition:
        $re1
}

rule github_personal_token {
    meta:
        description = "GitHub Personal Access Token"
        severity = "HIGH"
    strings:
        // Classic GitHub PAT format
        $re1 = /ghp_[0-9a-zA-Z]{36}/
    condition:
        $re1
}

rule github_oauth_token {
    meta:
        description = "GitHub OAuth Token"
        severity = "HIGH"
    strings:
        $re1 = /gho_[0-9a-zA-Z]{36}/
    condition:
        $re1
}

rule private_key {
    meta:
        description = "Private Key Header"
        severity = "HIGH"
    strings:
        $re1 = /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/
    condition:
        $re1
}

rule generic_api_key {
    meta:
        description = "Generic API Key"
        severity = "MEDIUM"
    strings:
        // Generic key/token variable names assigned a long string
        $re1 = /(api[_-]?key|secret|token)[ \t]*[=:][ \t]*["'][A-Za-z0-9_\-\.]{20,}["']/ nocase
    condition:
        $re1
}

rule generic_password {
    meta:
        description = "Generic Password"
        severity = "MEDIUM"
    strings:
        // Looking for hardcoded generic passwords (e.g., db_password = "xyz")
        $re1 = /(password|passwd|pwd)[ \t]*[=:][ \t]*["'][^"'\s]{8,}["']/ nocase
    condition:
        $re1
}
