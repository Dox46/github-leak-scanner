"""
YARA Downloader Helper
Fetches portable YARA binaries from GitHub releases so the user doesn't need C++ build tools.
"""

import os
import sys
import json
import urllib.request
import urllib.error
import zipfile
import tarfile
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).parent.parent
BIN_DIR = ROOT_DIR / ".bin"
YARA_VERSION = "v4.5.2"

def get_yara_binary_path() -> Path:
    """Returns the expected path to the YARA executable for this OS."""
    if sys.platform == "win32":
        return BIN_DIR / "yara64.exe"
    return BIN_DIR / "yara"

def ensure_yara_binary() -> Path:
    """
    Ensures that the portable YARA binary is present in ./.bin/.
    If not, downloads and extracts it from official VirusTotal GitHub releases.
    Returns the path to the executable.
    """
    exe_path = get_yara_binary_path()
    if exe_path.exists():
        return exe_path

    BIN_DIR.mkdir(exist_ok=True)
    print(f"[YARA Provisioning] Missing YARA engine. Downloading portable binary for {sys.platform}...")
    
    # VirusTotal YARA releases page
    # Because of unpredictable release asset names or links across versions, we query the GH API
    api_url = f"https://api.github.com/repos/VirusTotal/yara/releases/tags/{YARA_VERSION}"
    
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "github-leak-scanner-provisioner"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            
        assets = data.get("assets", [])
        asset_url = None
        asset_name = None
        
        # Determine the correct asset for the platform
        for asset in assets:
            name = asset["name"].lower()
            if sys.platform == "win32" and "win64" in name and name.endswith(".zip"):
                asset_url = asset["browser_download_url"]
                asset_name = name
                break
            elif sys.platform == "darwin" and "mac" in name and name.endswith(".tar.gz"):
                asset_url = asset["browser_download_url"]
                asset_name = name
                break
            elif sys.platform.startswith("linux") and "linux" in name and name.endswith(".tar.gz"):
                asset_url = asset["browser_download_url"]
                asset_name = name
                break
                
        if not asset_url:
            raise RuntimeError(f"Could not find a pre-compiled YARA release for platform '{sys.platform}'")

        archive_path = BIN_DIR / asset_name
        print(f"[YARA Provisioning] Fetching {asset_url}...")
        
        # Download
        urllib.request.urlretrieve(asset_url, str(archive_path))
        
        # Extract
        print("[YARA Provisioning] Extracting archive...")
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(BIN_DIR)
        elif archive_path.name.endswith(".tar.gz"):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(BIN_DIR)
                
        # Cleanup archive
        archive_path.unlink()
        
        # In the zip/tar, the executable might be in a subfolder or named yara64.exe
        # On Windows, VirusTotal zips usually contain yara64.exe right in the root.
        # On Linux/Mac, we might have to make it executable.
        if sys.platform != "win32":
            if exe_path.exists():
                os.chmod(exe_path, 0o755)
        
        if not exe_path.exists():
            # Sometimes it's extracted inside a folder, let's find it
            for f in BIN_DIR.rglob("yara*"):
                if f.is_file() and (f.name == "yara" or f.name == "yara64.exe"):
                    f.rename(exe_path)
                    break
        
        if sys.platform != "win32":
            os.chmod(exe_path, 0o755)
                    
        if exe_path.exists():
            print(f"[YARA Provisioning] Successfully provisioned at {exe_path}")
            return exe_path
        else:
            raise FileNotFoundError("YARA executable not found after extraction.")
            
    except Exception as e:
        raise RuntimeError(f"Failed to auto-provision YARA binary: {e}\n"
                           "Please manually download the YARA executable and place it in the '.bin' folder.")

if __name__ == "__main__":
    ensure_yara_binary()
