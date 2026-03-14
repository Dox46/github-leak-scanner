"""
Unit tests for secret pattern detection.
We test patterns against known fake secrets — never real ones.
"""

import re
import pytest
from src.patterns import PATTERNS


def get_pattern(name: str) -> dict:
    """Helper to retrieve a pattern by name."""
    for p in PATTERNS:
        if p["name"] == name:
            return p
    raise ValueError(f"Pattern '{name}' not found")


class TestAWSPatterns:
    def test_aws_access_key_detected(self):
        pattern = get_pattern("AWS Access Key ID")
        assert re.search(pattern["regex"], "AKIAIOSFODNN7EXAMPLE")

    def test_aws_access_key_wrong_prefix(self):
        pattern = get_pattern("AWS Access Key ID")
        assert not re.search(pattern["regex"], "BKIAIOSFODNN7EXAMPLE")

    def test_aws_severity_is_high(self):
        pattern = get_pattern("AWS Access Key ID")
        assert pattern["severity"] == "HIGH"


class TestGitHubTokenPatterns:
    def test_github_pat_detected(self):
        pattern = get_pattern("GitHub Personal Access Token")
        fake_token = "ghp_" + "A" * 36
        assert re.search(pattern["regex"], fake_token)

    def test_github_oauth_detected(self):
        pattern = get_pattern("GitHub OAuth Token")
        fake_token = "gho_" + "B" * 36
        assert re.search(pattern["regex"], fake_token)


class TestPrivateKeyPattern:
    def test_rsa_key_detected(self):
        pattern = get_pattern("Private Key Header")
        assert re.search(pattern["regex"], "-----BEGIN RSA PRIVATE KEY-----")

    def test_openssh_key_detected(self):
        pattern = get_pattern("Private Key Header")
        assert re.search(pattern["regex"], "-----BEGIN OPENSSH PRIVATE KEY-----")


class TestGenericPatterns:
    def test_generic_api_key_detected(self):
        pattern = get_pattern("Generic API Key")
        assert re.search(pattern["regex"], 'api_key = "abcdefghij1234567890"')

    def test_generic_password_detected(self):
        pattern = get_pattern("Generic Password")
        assert re.search(pattern["regex"], 'password = "supersecret123"')

    def test_short_password_ignored(self):
        """Passwords under 8 chars should not match."""
        pattern = get_pattern("Generic Password")
        assert not re.search(pattern["regex"], 'password = "abc"')