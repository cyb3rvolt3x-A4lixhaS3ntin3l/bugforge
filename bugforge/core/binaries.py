"""
Pre-compiled binary manager — downloads static binaries from GitHub releases.
No Go, no Docker, no manual installs. First run downloads, cached after.
"""
from __future__ import annotations
import os
import platform
import stat
import urllib.request
import urllib.error
import json
import shutil
from typing import Optional
from ..utils.logger import get_logger

log = get_logger()


def _get_platform() -> tuple[str, str]:
    """Return (os, arch) for binary selection."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "linux", "darwin": "macos", "windows": "windows"}
    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "arm64": "arm64", "aarch64": "arm64",
        "armv7l": "arm", "armv6l": "arm",
    }
    return os_map.get(system, system), arch_map.get(machine, machine)


# Tool definitions: name → (github repo, binary_name, version_tag or "latest")
# These are the tools that publish pre-compiled binaries on GitHub releases
BINARY_TOOLS = {
    "subfinder": ("projectdiscovery/subfinder", "subfinder", "latest"),
    "httpx": ("projectdiscovery/httpx", "httpx", "latest"),
    "nuclei": ("projectdiscovery/nuclei", "nuclei", "latest"),
    "dalfox": ("hahwul/dalfox", "dalfox", "latest"),
    "gitleaks": ("gitleaks/gitleaks", "gitleaks", "latest"),
    "ffuf": ("ffuf/ffuf", "ffuf", "latest"),
}

# Tools that need special handling
SPECIAL_TOOLS = {
    "sqlmap": ("sqlmapproject/sqlmap", None, "latest"),  # Python, pip install
    "nmap": (None, "nmap", None),  # system package
    "amass": ("owasp-amass/amass", "amass", "latest"),
    "assetfinder": ("tomnomnom/assetfinder", "assetfinder", "latest"),
}


class BinaryManager:
    """Manages pre-compiled tool binaries."""

    def __init__(self, bin_dir: str):
        self.bin_dir = bin_dir
        self.os_name, self.arch_name = _get_platform()
        os.makedirs(bin_dir, exist_ok=True)
        # Ensure bin_dir is in PATH
        if bin_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")

    def is_available(self, name: str) -> bool:
        """Check if a tool binary is available."""
        # Check bin_dir first
        binary_path = os.path.join(self.bin_dir, name)
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return True
        # Check system PATH
        return shutil.which(name) is not None

    def get_path(self, name: str) -> str:
        """Get the path to a tool binary."""
        binary_path = os.path.join(self.bin_dir, name)
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return binary_path
        system_path = shutil.which(name)
        return system_path or binary_path

    def get_latest_release(self, repo: str) -> dict:
        """Fetch latest release info from GitHub API."""
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={
            "User-Agent": "BugForge/3.0",
            "Accept": "application/vnd.github.v3+json",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            log.debug(f"Failed to fetch release for {repo}: {e}")
            return {}

    def find_asset(self, release: dict, tool_name: str) -> Optional[str]:
        """Find the right binary asset for our platform from a release."""
        assets = release.get("assets", [])
        if not assets:
            return None

        # Build expected patterns
        patterns = []
        if self.os_name == "linux":
            patterns = [
                f"{tool_name}_{self.os_name}_{self.arch_name}",
                f"{tool_name}-linux-{self.arch_name}",
                f"{tool_name}_{self.os_name}_{self.arch_name}.zip",
            ]
        elif self.os_name == "macos":
            patterns = [
                f"{tool_name}_macOS_{self.arch_name}",
                f"{tool_name}_darwin_{self.arch_name}",
                f"{tool_name}-macos-{self.arch_name}",
            ]
        elif self.os_name == "windows":
            patterns = [f"{tool_name}_windows_{self.arch_name}.zip", f"{tool_name}.exe"]

        for pattern in patterns:
            for asset in assets:
                name = asset["name"].lower()
                if pattern.lower() in name:
                    return asset["browser_download_url"]

        # Fallback: try any asset with our OS name
        for asset in assets:
            name = asset["name"].lower()
            if self.os_name in name or ("linux" in name and self.os_name == "linux"):
                return asset["browser_download_url"]

        return None

    def download_file(self, url: str, dest: str) -> bool:
        """Download a file to dest."""
        for attempt in range(2):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "BugForge/3.0"})
                with urllib.request.urlopen(req, timeout=120) as resp:
                    with open(dest, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                return True
            except Exception as e:
                log.error(f"Download attempt {attempt+1} failed: {url} → {e}")
                if attempt == 1:
                    return False
                import time; time.sleep(2)
        return False

    @staticmethod
    def _is_zip(path: str) -> bool:
        """Check if a file is a zip archive."""
        try:
            with open(path, 'rb') as f:
                return f.read(4) == b'PK\x03\x04'
        except Exception:
            return False

    def install(self, name: str) -> bool:
        """Download and install a tool binary."""
        if name in SPECIAL_TOOLS:
            return self._install_special(name)

        if name not in BINARY_TOOLS:
            log.error(f"Unknown tool: {name}")
            return False

        repo, binary_name, _ = BINARY_TOOLS[name]
        log.info(f"Installing {name} from {repo}...")

        release = self.get_latest_release(repo)
        if not release:
            log.error(f"No releases found for {repo}")
            return False

        download_url = self.find_asset(release, name)
        if not download_url:
            log.error(f"No binary found for {name} on {self.os_name}/{self.arch_name}")
            return False

        dest = os.path.join(self.bin_dir, binary_name)
        if not self.download_file(download_url, dest):
            return False

        # Handle zip files
        import zipfile
        if dest.endswith(".zip") or self._is_zip(dest):
            try:
                with zipfile.ZipFile(dest, "r") as z:
                    z.extractall(self.bin_dir)
                os.remove(dest)
                dest = os.path.join(self.bin_dir, binary_name)
            except Exception as e:
                log.error(f"Failed to extract {dest}: {e}")
                return False

        # Make executable
        os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        log.info(f"✓ {name} installed at {dest}")
        return True

    def _install_special(self, name: str) -> bool:
        """Handle tools that need special installation."""
        if name == "sqlmap":
            import subprocess, sys
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "sqlmap"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                log.info(f"✓ sqlmap installed via pip")
                return True
            log.error(f"sqlmap install failed: {result.stderr[:200]}")
            return False

        if name == "nmap":
            log.warning("nmap requires system installation: apt install nmap / brew install nmap")
            return shutil.which("nmap") is not None

        # amass, assetfinder — try binary download
        if name in ("amass", "assetfinder"):
            repo, binary_name, _ = SPECIAL_TOOLS[name]
            release = self.get_latest_release(repo)
            if not release:
                return False
            download_url = self.find_asset(release, name)
            if not download_url:
                return False
            dest = os.path.join(self.bin_dir, binary_name or name)
            if self.download_file(download_url, dest):
                os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC)
                log.info(f"✓ {name} installed")
                return True
        return False

    def ensure_installed(self, name: str) -> bool:
        """Ensure a tool is installed, downloading if needed."""
        if self.is_available(name):
            return True
        # Don't try to install if it's not in our known tools
        if name not in BINARY_TOOLS and name not in SPECIAL_TOOLS:
            return False
        return self.install(name)

    def install_all(self) -> dict:
        """Install all tools. Returns {name: success}."""
        results = {}
        all_tools = list(BINARY_TOOLS.keys()) + list(SPECIAL_TOOLS.keys())
        for name in all_tools:
            results[name] = self.ensure_installed(name)
        return results

    def status(self) -> list[dict]:
        """Return status of all tools."""
        all_tools = {}
        all_tools.update(BINARY_TOOLS)
        all_tools.update(SPECIAL_TOOLS)
        return [
            {
                "name": name,
                "installed": self.is_available(name),
                "path": self.get_path(name) if self.is_available(name) else None,
            }
            for name in all_tools
        ]
