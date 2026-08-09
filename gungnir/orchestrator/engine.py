"""
The orchestration engine — the heart of Gungnir v2.0.

Responsibilities:
  1. Check if a tool is installed (shutil.which)
  2. Auto-install if missing (go install / pip / docker)
  3. Run the tool as a subprocess with optimal flags
  4. Parse JSON output into standardized results
  5. Stream progress via callbacks (for WebSocket updates)
  6. Handle timeouts, errors, and fallbacks gracefully

The user never manually installs Subfinder, ffuf, Nuclei, etc.
Gungnir does it all behind the scenes.
"""
from __future__ import annotations
import asyncio
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Callable, Dict, Any, Awaitable

from .registry import TOOL_REGISTRY, ToolDefinition, ToolCategory, InstallMethod
from ..utils.logger import get_logger

log = get_logger()


class ToolStatus(str, Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolResult:
    tool_name: str
    category: str
    status: ToolStatus
    target: str
    findings: List[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    elapsed: float = 0.0
    command: str = ""


class ToolOrchestrator:
    """
    Manages tool lifecycle: detect → install → run → parse.

    Usage:
        orch = ToolOrchestrator()
        result = await orch.run("subfinder", "example.com")
        print(result.findings)  # list of {"subdomain": "...", "source": "..."}
    """

    def __init__(self, auto_install: bool = True, go_path: str = ""):
        self.auto_install = auto_install
        self.go_path = go_path or shutil.which("go") or ""
        self._installed_cache: Dict[str, bool] = {}

    def is_installed(self, tool_name: str) -> bool:
        """Check if a tool binary is available on PATH."""
        if tool_name in self._installed_cache:
            return self._installed_cache[tool_name]

        tool = TOOL_REGISTRY.get(tool_name)
        if not tool:
            return False

        installed = shutil.which(tool.binary) is not None
        # For go-installed tools, also check GOPATH/bin
        if not installed and tool.install_method == InstallMethod.GO:
            import os
            gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
            gobin = os.path.join(gopath, "bin", tool.binary)
            installed = os.path.isfile(gobin) and os.access(gobin, os.X_OK)
            if installed:
                # Add to PATH for future runs
                gobin_dir = os.path.join(gopath, "bin")
                if gobin_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = gobin_dir + os.pathsep + os.environ.get("PATH", "")

        self._installed_cache[tool_name] = installed
        return installed

    def install(self, tool_name: str) -> bool:
        """Auto-install a tool using its defined install method."""
        tool = TOOL_REGISTRY.get(tool_name)
        if not tool:
            log.error(f"Unknown tool: {tool_name}")
            return False

        if tool.install_method == InstallMethod.BUILTIN:
            return True  # already part of Gungnir

        if not self.auto_install:
            log.warning(f"Auto-install disabled. {tool_name} not found.")
            return False

        log.info(f"Installing {tool_name} via {tool.install_method.value}...")

        try:
            if tool.install_method == InstallMethod.GO:
                if not self.go_path:
                    log.error("Go not installed. Install Go first: https://go.dev/dl/")
                    return False
                result = subprocess.run(
                    tool.install_command, shell=True, capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    log.error(f"go install failed for {tool_name}: {result.stderr[:200]}")
                    return False

            elif tool.install_method == InstallMethod.PIP:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", tool.install_command.replace("pip install ", "").strip()],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    log.error(f"pip install failed for {tool_name}: {result.stderr[:200]}")
                    return False

            elif tool.install_method == InstallMethod.SYSTEM:
                log.warning(f"System package required: run '{tool.install_command}' manually")
                return False

            elif tool.install_method == InstallMethod.DOCKER:
                result = subprocess.run(
                    tool.install_command, shell=True, capture_output=True, text=True, timeout=300
                )
                if result.returncode != 0:
                    log.error(f"docker pull failed for {tool_name}: {result.stderr[:200]}")
                    return False

            self._installed_cache[tool_name] = True
            log.info(f"✓ {tool_name} installed successfully")
            return True

        except subprocess.TimeoutExpired:
            log.error(f"Installation timed out for {tool_name}")
            return False
        except Exception as e:
            log.error(f"Installation error for {tool_name}: {e}")
            return False

    def ensure_installed(self, tool_name: str) -> bool:
        """Ensure a tool is installed, auto-installing if needed."""
        if self.is_installed(tool_name):
            return True
        return self.install(tool_name)

    async def run(self, tool_name: str, target: str,
                  options: Optional[Dict[str, Any]] = None,
                  progress_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
                  ) -> ToolResult:
        """
        Run a tool against a target.

        :param tool_name: registered tool name (e.g. "subfinder")
        :param target: target domain/URL/repo
        :param options: tool-specific options dict
        :param progress_callback: async callback(stage, message) for WebSocket updates
        """
        tool = TOOL_REGISTRY.get(tool_name)
        if not tool:
            return ToolResult(tool_name, "", ToolStatus.FAILED, target,
                              error=f"Unknown tool: {tool_name}")

        options = options or {}
        result = ToolResult(tool_name=tool_name, category=tool.category.value,
                            target=target, status=ToolStatus.NOT_INSTALLED)

        # Step 1: ensure installed
        if progress_callback:
            await progress_callback(tool_name, "checking installation...")
        if not self.ensure_installed(tool_name):
            # Try fallback for this category
            fallback = self._find_fallback(tool.category)
            if fallback and fallback != tool_name:
                log.info(f"Falling back to {fallback} for {tool.category.value}")
                if progress_callback:
                    await progress_callback(tool_name, f"falling back to {fallback}...")
                return await self.run(fallback, target, options, progress_callback)
            result.error = f"{tool_name} not installed and auto-install failed"
            result.status = ToolStatus.FAILED
            return result

        result.status = ToolStatus.INSTALLED

        # Step 2: build command
        if not tool.run_builder:
            result.error = f"{tool_name} has no run builder"
            result.status = ToolStatus.FAILED
            return result

        try:
            cmd = tool.run_builder(target, options)
        except Exception as e:
            result.error = f"Command build error: {e}"
            result.status = ToolStatus.FAILED
            return result

        if not cmd:
            result.error = "Empty command"
            result.status = ToolStatus.FAILED
            return result

        # Resolve binary path (GOPATH/bin may not be in PATH yet)
        cmd[0] = self._resolve_binary(cmd[0])
        result.command = " ".join(cmd)

        # Step 3: run
        if progress_callback:
            await progress_callback(tool_name, f"running: {result.command}")
        result.status = ToolStatus.RUNNING

        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=tool.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = ToolStatus.TIMEOUT
                result.error = f"Timed out after {tool.timeout}s"
                result.elapsed = time.time() - start
                return result

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            result.raw_output = stdout
            result.elapsed = time.time() - start

            if proc.returncode != 0 and not stdout.strip():
                result.status = ToolStatus.FAILED
                result.error = stderr[:500] or f"exit code {proc.returncode}"
                return result

            # Step 4: parse output
            if tool.json_parser:
                try:
                    result.findings = tool.json_parser(stdout)
                except Exception as e:
                    log.debug(f"JSON parse error for {tool_name}: {e}")
                    result.findings = []
                    result.error = f"Parse error: {e}"

            result.status = ToolStatus.COMPLETED
            if progress_callback:
                count = len(result.findings)
                await progress_callback(tool_name, f"completed — {count} findings")

        except FileNotFoundError as e:
            result.status = ToolStatus.FAILED
            result.error = f"Binary not found: {e}"
        except Exception as e:
            result.status = ToolStatus.FAILED
            result.error = str(e)

        return result

    async def run_category(self, category: ToolCategory, target: str,
                           options: Optional[Dict] = None,
                           progress_callback: Optional[Callable] = None
                           ) -> List[ToolResult]:
        """Run all tools in a category sequentially (first success wins for
        overlapping tools, or all run for complementary tools)."""
        from .registry import get_tools_by_category
        tools = get_tools_by_category(category)
        results = []
        for tool in tools:
            if not tool.enabled:
                continue
            r = await self.run(tool.name, target, options, progress_callback)
            results.append(r)
            # If a tool found significant results, skip lower-priority tools
            if r.findings and len(r.findings) > 5:
                break
        return results

    def _find_fallback(self, category: ToolCategory) -> Optional[str]:
        """Find a builtin fallback tool for a category."""
        from .registry import get_tools_by_category
        tools = get_tools_by_category(category)
        for t in tools:
            if t.install_method == InstallMethod.BUILTIN:
                return t.name
        return None

    def _resolve_binary(self, binary: str) -> str:
        """Resolve binary path, checking GOPATH/bin if not on PATH."""
        path = shutil.which(binary)
        if path:
            return path
        # Check GOPATH/bin
        import os
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        gobin = os.path.join(gopath, "bin", binary)
        if os.path.isfile(gobin) and os.access(gobin, os.X_OK):
            return gobin
        return binary  # let it fail naturally

    def status(self) -> List[dict]:
        """Return installation status of all registered tools."""
        return [
            {
                "name": t.name,
                "category": t.category.value,
                "description": t.description,
                "installed": self.is_installed(t.name),
                "install_method": t.install_method.value,
                "github": t.github,
            }
            for t in TOOL_REGISTRY.values()
        ]
