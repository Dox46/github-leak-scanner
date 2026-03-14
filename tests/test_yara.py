"""
Unit tests for YARA secret pattern detection.
We test patterns against known fake secrets — never real ones.
"""

import tempfile
from pathlib import Path
from src.yara_engine import scan_file_with_yara

def scan_string(content: str) -> list:
    """Helper to scan a raw string with YARA via a temp file."""
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
        
    findings = scan_file_with_yara(tmp_path)
    tmp_path.unlink()
    return findings

class TestAWSPatterns:
    def test_aws_access_key_detected(self):
        findings = scan_string("AKIAIOSFODNN7EXAMPLE")
        assert any(f.pattern == "AWS Access Key ID" for f in findings)
        assert any(f.severity == "HIGH" for f in findings)

    def test_aws_access_key_wrong_prefix(self):
        findings = scan_string("BKIAIOSFODNN7EXAMPLE")
        assert not any(f.pattern == "AWS Access Key ID" for f in findings)

    def test_aws_secret_key_detected(self):
        findings = scan_string('aws_secret_access_key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"')
        assert any(f.pattern == "AWS Secret Access Key" for f in findings)
        assert any(f.severity == "HIGH" for f in findings)

class TestGitHubTokenPatterns:
    def test_github_pat_detected(self):
        fake_token = "ghp_" + "A" * 36
        findings = scan_string(fake_token)
        assert any(f.pattern == "GitHub Personal Access Token" for f in findings)

    def test_github_oauth_detected(self):
        fake_token = "gho_" + "B" * 36
        findings = scan_string(fake_token)
        assert any(f.pattern == "GitHub OAuth Token" for f in findings)

class TestPrivateKeyPattern:
    def test_rsa_key_detected(self):
        findings = scan_string("-----BEGIN RSA PRIVATE KEY-----")
        assert any(f.pattern == "Private Key Header" for f in findings)

    def test_openssh_key_detected(self):
        findings = scan_string("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert any(f.pattern == "Private Key Header" for f in findings)

class TestGenericPatterns:
    def test_generic_api_key_detected(self):
        findings = scan_string('api_key = "abcdefghij1234567890"')
        assert any(f.pattern == "Generic API Key" for f in findings)

    def test_generic_password_detected(self):
        findings = scan_string('password = "supersecret123"')
        assert any(f.pattern == "Generic Password" for f in findings)

    def test_short_password_ignored(self):
        """Passwords under 8 chars should not match."""
        findings = scan_string('password = "abc"')
        assert not any(f.pattern == "Generic Password" for f in findings)