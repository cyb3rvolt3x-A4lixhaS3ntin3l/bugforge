"""
Tool Resolver — intelligently finds tools without breaking existing installs.

Resolution order:
  1. User-configured override path (~/.gungnir/config.yaml)
  2. Gungnir's own bin directory (~/.gungnir/bin/)
  3. System PATH (user's existing install)
  4. Not found → download to ~/.gungnir/bin/ (NEVER to system paths)

NEVER overwrites, modifies, or shadows existing system tools.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict
from pathlib import Path
from ..utils.logger import get_logger

log = get_logger()


class ToolSource(str, Enum):
    USER_OVERRIDE = "user_override"
    GUNGNIR = "gungnir"
    SYSTEM = "system"
    NOT_FOUND = "not_found"


@dataclass
class ToolLocation:
    path: Optional[str]
    source: ToolSource
    version: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.path is not None and os.path.isfile(self.path) and os.access(self.path, os.X_OK)


class ToolResolver:
    """Resolves tool binaries without conflicting with existing installs."""

    def __init__(self, bin_dir: str, config_path: Optional[str] = None):
        self.bin_dir = Path(bin_dir)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = Path(config_path) if config_path else Path.home() / ".gungnir" / "config.yaml"

        # Ensure bin_dir is in PATH for this process only
        path_str = os.environ.get("PATH", "")
        if str(self.bin_dir) not in path_str:
            os.environ["PATH"] = str(self.bin_dir) + os.pathsep + path_str

        self._overrides: Dict[str, str] = {}
        self._never_install: set = set()
        self._min_versions: Dict[str, str] = {}
        self._load_config()

    def _load_config(self):
        """Load tool overrides from config.yaml if it exists."""
        if not self.config_path.exists():
            return
        try:
            import yaml
            with open(self.config_path) as f:
                config = yaml.safe_load(f) or {}
            self._overrides = config.get("tool_overrides", {})
            self._never_install = set(config.get("never_install", []))
            self._min_versions = config.get("tool_versions", {})
        except Exception as e:
            log.debug(f"Config load error: {e}")

    def resolve(self, name: str) -> ToolLocation:
        """Resolve a tool to its binary path. Returns ToolLocation."""
        # 1. User override
        if name in self._overrides:
            path = os.path.expanduser(self._overrides[name])
            if os.path.isfile(path) and os.access(path, os.X_OK):
                version = self._get_version(path)
                return ToolLocation(path=path, source=ToolSource.USER_OVERRIDE, version=version)

        # 2. Gungnir bin
        gungnir_path = self.bin_dir / name
        if gungnir_path.is_file() and os.access(str(gungnir_path), os.X_OK):
            version = self._get_version(str(gungnir_path))
            return ToolLocation(path=str(gungnir_path), source=ToolSource.GUNGNIR, version=version)

        # 3. System PATH
        system_path = shutil.which(name)
        if system_path:
            version = self._get_version(system_path)
            return ToolLocation(path=system_path, source=ToolSource.SYSTEM, version=version)

        # 4. Not found
        return ToolLocation(path=None, source=ToolSource.NOT_FOUND)

    def ensure_available(self, name: str, install_fn=None) -> ToolLocation:
        """Ensure a tool is available. Downloads if needed and allowed."""
        loc = self.resolve(name)
        if loc.available:
            # Check version if minimum specified
            if name in self._min_versions and loc.version:
                if self._version_is_older(loc.version, self._min_versions[name]):
                    log.warning(f"{name} v{loc.version} found ({self._min_versions[name]}+ recommended) at {loc.path}")
            return loc

        # Don't install if user said not to
        if name in self._never_install:
            log.info(f"{name} skipped (in never_install list)")
            return loc

        # Try to install
        if install_fn:
            log.info(f"{name} not found, downloading to {self.bin_dir}...")
            if install_fn(name, str(self.bin_dir)):
                return self.resolve(name)

        return loc

    @staticmethod
    def _get_version(binary_path: str) -> Optional[str]:
        """Try to get the version of a tool binary."""
        for flag in ["--version", "-V", "version", "-v"]:
            try:
                r = subprocess.run([binary_path, flag], capture_output=True, text=True, timeout=5)
                output = (r.stdout + r.stderr).strip()
                # Extract version number
                match = re.search(r'v?(\d+\.\d+\.\d+)', output)
                if match:
                    return match.group(1)
                # Try shorter version
                match = re.search(r'v?(\d+\.\d+)', output)
                if match:
                    return match.group(1)
            except Exception:
                continue
        return None

    @staticmethod
    def _version_is_older(found: str, minimum: str) -> bool:
        """Check if found version is older than minimum."""
        try:
            f_parts = [int(x) for x in found.split('.')]
            m_parts = [int(x) for x in minimum.split('.')]
            return f_parts < m_parts
        except Exception:
            return False

    def status(self) -> list[dict]:
        """Return status of all known tools."""
        from .binaries import BINARY_TOOLS, SPECIAL_TOOLS
        all_tools = {**BINARY_TOOLS, **SPECIAL_TOOLS}
        results = []
        for name in all_tools:
            loc = self.resolve(name)
            results.append({
                "name": name,
                "available": loc.available,
                "path": loc.path or "(not found)",
                "source": loc.source.value,
                "version": loc.version or "unknown",
            })
        return results
