import pytest
from src.fetcher import validate_github_url

class TestValidateGithubUrl:
    def test_valid_url_passes(self):
        validate_github_url("https://github.com/user/repo")

    def test_non_github_url_raises(self):
        with pytest.raises(ValueError):
            validate_github_url("https://gitlab.com/user/repo")

    def test_missing_repo_raises(self):
        with pytest.raises(ValueError):
            validate_github_url("https://github.com/user")

    def test_http_raises(self):
        with pytest.raises(ValueError):
            validate_github_url("http://github.com/user/repo")
