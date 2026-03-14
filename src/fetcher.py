"""
GitHub repository fetcher.
Clones a repo into a temporary directory.
"""

import tempfile
import shutil
from pathlib import Path
from git import Repo, GitCommandError


def clone_repo(url: str) -> tuple[Path, str]:
    """
    Clone a GitHub repo to a temp directory.
    Returns (temp_dir_path, repo_name).
    Raises ValueError on failure.
    """
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    temp_dir = Path(tempfile.mkdtemp(prefix="leak_scan_"))

    try:
        Repo.clone_from(url, temp_dir, depth=1)  # depth=1 = plus rapide
        return temp_dir, repo_name
    except GitCommandError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ValueError(f"Failed to clone repository: {e}") from e


def cleanup(temp_dir: Path) -> None:
    """Remove the temporary cloned directory."""
    shutil.rmtree(temp_dir, ignore_errors=True)