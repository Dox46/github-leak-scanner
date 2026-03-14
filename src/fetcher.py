"""
GitHub repository fetcher.
Clones a repo into a given directory.
"""

from pathlib import Path
from git import Repo, GitCommandError

def validate_github_url(url: str) -> None:
    """Raise ValueError if the URL is not a valid GitHub repo URL."""
    if not url.startswith("https://github.com/"):
        raise ValueError("URL must start with https://github.com/")
    parts = url.rstrip("/").split("/")
    if len(parts) < 5:
        raise ValueError("URL must point to a repository: https://github.com/user/repo")

def clone_repo(url: str, target_dir: Path) -> str:
    """
    Clone a GitHub repo to a given target directory.
    Returns the repository name.
    Raises ValueError on failure.
    """
    validate_github_url(url)
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")

    try:
        Repo.clone_from(url, target_dir, depth=1)  # depth=1 = faster
        return repo_name
    except GitCommandError as e:
        raise ValueError(f"Could not clone repository. Check the URL and try again.") from e