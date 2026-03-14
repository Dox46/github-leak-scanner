"""
GitHub repository fetcher.
Clones a repo into a given directory.
"""

from pathlib import Path
from git import Repo, GitCommandError

def clone_repo(url: str, target_dir: Path) -> str:
    """
    Clone a GitHub repo to a given target directory.
    Returns the repository name.
    Raises ValueError on failure.
    """
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")

    try:
        Repo.clone_from(url, target_dir, depth=1)  # depth=1 = faster
        return repo_name
    except GitCommandError as e:
        raise ValueError(f"Failed to clone repository: {e}") from e