"""
Tests for the HTML builder module.
"""

from src.models import Finding
from src.html_builder import build_html_report

def test_build_html_report_contains_kpis_and_data():
    findings = [
        Finding(file="app.py", line=12, pattern="AWS Access Key ID", severity="HIGH", content="AKIA123..."),
        Finding(file="config.js", line=4, pattern="Generic Password", severity="MEDIUM", content="pwd=secret"),
        Finding(file=".env", line=0, pattern=".env file detected", severity="LOW", content="File name match"),
    ]
    
    html = build_html_report("https://github.com/Fake/Repo", findings)
    
    # Check Header
    assert "https://github.com/Fake/Repo" in html
    assert "Total Leaks Detected" in html
    
    # Check KPIs
    assert 'text-red-500">1</p>' in html
    assert 'text-yellow-500">1</p>' in html
    assert 'text-blue-400">1</p>' in html
    
    # Check Pydantic injects strings safely
    assert 'AWS Access Key ID' in html
    assert 'app.py' in html
    assert 'pwd=secret' in html
