"""
Integration tests for the scanner engine.
Uses temporary files with fake secrets.
"""

import pytest
from pathlib import Path
from src.scanner import scan_file, scan_directory, should_skip


class TestShouldSkip:
    def test_skips_png(self, tmp_path):
        f = tmp_path / "image.png"
        assert should_skip(f)

    def test_skips_node_modules(self, tmp_path):
        f = tmp_path / "node_modules" / "index.js"
        assert should_skip(f)

    def test_does_not_skip_python_file(self, tmp_path):
        f = tmp_path / "main.py"
        assert not should_skip(f)


class TestScanFile:
    def test_detects_aws_key(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_file(f)
        assert len(findings) >= 1
        assert any(finding.severity == "HIGH" for finding in findings)

    def test_clean_file_returns_empty(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text('print("Hello, world!")')
        findings = scan_file(f)
        assert findings == []

    def test_finding_contains_required_fields(self, tmp_path):
        f = tmp_path / "secrets.env"
        f.write_text("AKIAIOSFODNN7EXAMPLE")
        findings = scan_file(f)
        assert len(findings) > 0
        finding = findings[0]
        assert hasattr(finding, "file")
        assert hasattr(finding, "line")
        assert hasattr(finding, "pattern")
        assert hasattr(finding, "severity")


class TestScanDirectory:
    def test_scans_multiple_files(self, tmp_path):
        (tmp_path / "a.py").write_text('token = "ghp_' + "A" * 36 + '"')
        (tmp_path / "b.py").write_text('print("clean")')
        findings = scan_directory(tmp_path)
        assert len(findings) >= 1

    def test_results_sorted_by_severity(self, tmp_path):
        (tmp_path / "high.py").write_text("AKIAIOSFODNN7EXAMPLE")
        (tmp_path / "medium.py").write_text('api_key = "abcdefghij1234567890"')
        findings = scan_directory(tmp_path)
        severities = [f.severity for f in findings]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        assert severities == sorted(severities, key=lambda s: order.get(s, 99))