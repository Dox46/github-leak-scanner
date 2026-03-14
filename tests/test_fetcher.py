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

class TestCloneRepo:
    def test_clone_repo_injects_token(self, mocker):
        mock_clone = mocker.patch("src.fetcher.Repo.clone_from")
        from src.fetcher import clone_repo
        from pathlib import Path
        
        target_dir = Path("/tmp/fake")
        clone_repo("https://github.com/user/priv_repo", target_dir, token="ghp_FAKETOKEN123")
        
        # Verify the URL passed to clone_from contains the injected token
        mock_clone.assert_called_once()
        args, kwargs = mock_clone.call_args
        assert args[0] == "https://x-access-token:ghp_FAKETOKEN123@github.com/user/priv_repo"
        assert args[1] == target_dir
        
    def test_clone_repo_history_flag(self, mocker):
        mock_clone = mocker.patch("src.fetcher.Repo.clone_from")
        from src.fetcher import clone_repo
        from pathlib import Path
        
        target_dir = Path("/tmp/fake")
        # Without history, we should see depth=1
        clone_repo("https://github.com/user/repo", target_dir, history=False)
        assert mock_clone.call_args[1].get("depth") == 1
        
        mock_clone.reset_mock()
        # With history, depth=1 should be omitted
        clone_repo("https://github.com/user/repo", target_dir, history=True)
        assert "depth" not in mock_clone.call_args[1]
