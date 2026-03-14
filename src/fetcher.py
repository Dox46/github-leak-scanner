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

def clone_repo(url: str, target_dir: Path, token: str | None = None, history: bool = False) -> str:
    """
    Clone a GitHub repo to a given target directory.
    If 'token' is provided, it uses it for private repo authentication.
    If 'history' is True, it fetches the full git history instead of a shallow clone.
    Returns the repository name.
    Raises ValueError on failure.
    """
    validate_github_url(url)
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")

    clone_url = url
    if token:
        # Inject the token into the URL payload
        clone_url = url.replace("https://", f"https://x-access-token:{token}@")

    try:
        if history:
            Repo.clone_from(clone_url, target_dir)
        else:
            Repo.clone_from(clone_url, target_dir, depth=1)  # fast shallow clone
        return repo_name
    except GitCommandError:
        # We catch and raise a sanitized message so we don't leak the token in the stack trace
        raise ValueError("Could not clone repository. Check the URL, permissions, and try again.")