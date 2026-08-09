"""
Parallel wave execution engine — fires all tools simultaneously.
Wave 1: discovery (subdomain enumeration)
Wave 2: deep scan (all scanners in parallel)
"""
from __future__ import annotations
import asyncio
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Awaitable, Dict, Any

from .binaries import BinaryManager
from .profiles import PROFILES, ToolProfile, Wave, get_wave_profiles
from .detect import TargetType, get_domain_from_url, normalize_target
from ..utils.logger import get_logger

log = get_logger()


@dataclass
class ToolResult:
    name: str
    target: str
    wave: int
    findings: List[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    elapsed: float = 0.0
    success: bool = False


@dataclass
class WaveResult:
    wave: int
    results: List[ToolResult] = field(default_factory=list)
    elapsed: float = 0.0
    assets_discovered: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    target_type: TargetType
    wave1: Optional[WaveResult] = None
    wave2: Optional[WaveResult] = None
    all_findings: List[dict] = field(default_factory=list)
    total_elapsed: float = 0.0

    def collect_findings(self):
        self.all_findings = []
        for wave_result in [self.wave1, self.wave2]:
            if wave_result:
                for tr in wave_result.results:
                    for f in tr.findings:
                        f["_source"] = tr.name
                        f["_wave"] = wave_result.wave
                        self.all_findings.append(f)


class ParallelEngine:
    """Executes tools in parallel waves."""

    def __init__(self, binary_manager: BinaryManager, max_concurrent: int = 20):
        self.bm = binary_manager
        self.max_concurrent = max_concurrent

    async def run_tool(self, profile: ToolProfile, target: str,
                       options: Optional[Dict] = None,
                       progress_cb: Optional[Callable] = None) -> ToolResult:
        """Run a single tool."""
        options = options or {}
        result = ToolResult(name=profile.name, target=target, wave=profile.wave.value)

        # Ensure binary is available
        if not self.bm.ensure_installed(profile.binary):
            result.error = f"{profile.binary} not available"
            if progress_cb:
                await progress_cb(profile.name, "skipped (not installed)")
            return result

        # Build command
        try:
            cmd = profile.command_builder(target, options)
        except Exception as e:
            result.error = f"command build error: {e}"
            return result

        binary_path = self.bm.get_path(profile.binary)
        cmd[0] = binary_path

        if progress_cb:
            await progress_cb(profile.name, f"running...")

        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=profile.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.error = f"timed out after {profile.timeout}s"
                result.elapsed = time.time() - start
                if progress_cb:
                    await progress_cb(profile.name, f"timed out")
                return result

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            result.raw_output = stdout
            result.elapsed = time.time() - start

            if proc.returncode != 0 and not stdout.strip():
                result.error = stderr[:300] or f"exit code {proc.returncode}"
                if progress_cb:
                    await progress_cb(profile.name, f"failed: {result.error[:80]}")
                return result

            # Parse results
            try:
                result.findings = profile.parser(stdout)
            except Exception as e:
                log.debug(f"Parse error for {profile.name}: {e}")
                result.findings = []

            result.success = True
            if progress_cb:
                await progress_cb(profile.name, f"✓ {len(result.findings)} findings ({result.elapsed:.1f}s)")

        except FileNotFoundError as e:
            result.error = f"binary not found: {e}"
        except Exception as e:
            result.error = str(e)

        return result

    async def run_wave(self, wave: Wave, target: str, target_type: TargetType,
                       assets: Optional[List[str]] = None,
                       progress_cb: Optional[Callable] = None,
                       options: Optional[Dict] = None) -> WaveResult:
        """Run all tools in a wave in parallel."""
        options = options or {}
        profiles = get_wave_profiles(wave, target_type.value)
        if not profiles:
            return WaveResult(wave=wave.value)

        tasks = []
        wave_start = time.time()

        if wave == Wave.DISCOVERY:
            # Run discovery tools against the target domain
            for p in profiles:
                tasks.append(self.run_tool(p, target, options, progress_cb))
        else:
            # Wave 2: run against each discovered asset
            scan_targets = assets or [target]
            # For ffuf, use a built-in wordlist if no custom one
            ffuf_opts = dict(options)
            if "wordlist" not in ffuf_opts:
                ffuf_opts["wordlist"] = self._get_builtin_wordlist()

            for t in scan_targets:
                for p in profiles:
                    # Only run web tools on web targets
                    if p.requires_web and not self._is_likely_web(t):
                        continue
                    tool_opts = ffuf_opts if p.name == "ffuf" else options
                    tasks.append(self.run_tool(p, t, tool_opts, progress_cb))

        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _run_with_limit(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[_run_with_limit(t) for t in tasks], return_exceptions=True)

        wave_result = WaveResult(wave=wave.value, elapsed=time.time() - wave_start)
        for r in results:
            if isinstance(r, Exception):
                log.error(f"Task error: {r}")
                continue
            wave_result.results.append(r)

        return wave_result

    async def full_scan(self, target: str, target_type: TargetType,
                        progress_cb: Optional[Callable] = None,
                        options: Optional[Dict] = None) -> ScanResult:
        """Run the complete two-wave scan."""
        options = options or {}
        result = ScanResult(target=target, target_type=target_type)
        scan_start = time.time()

        # Wave 1: Discovery
        if target_type == TargetType.DOMAIN:
            if progress_cb:
                await progress_cb("wave1", "starting discovery wave...")
            result.wave1 = await self.run_wave(Wave.DISCOVERY, target, target_type,
                                               progress_cb=progress_cb, options=options)
            # Collect discovered subdomains
            if result.wave1:
                for tr in result.wave1.results:
                    for f in tr.findings:
                        if f.get("type") == "subdomain":
                            result.wave1.assets_discovered.append(f["value"])
                # Dedupe + add original target
                assets = list(set([target] + result.wave1.assets_discovered))
                result.wave1.assets_discovered = assets
        else:
            # For IP/URL, skip discovery
            result.wave1 = WaveResult(wave=1, assets_discovered=[target])

        # Wave 2: Deep Scan
        if progress_cb:
            await progress_cb("wave2", "starting deep scan wave...")
        scan_assets = result.wave1.assets_discovered[:20]  # limit to avoid overload
        result.wave2 = await self.run_wave(Wave.DEEP_SCAN, target, target_type,
                                           assets=scan_assets,
                                           progress_cb=progress_cb, options=options)

        result.total_elapsed = time.time() - scan_start
        result.collect_findings()
        return result

    @staticmethod
    def _is_likely_web(target: str) -> bool:
        """Heuristic: is this target likely a web service?"""
        return target.startswith(("http://", "https://")) or "." in target

    @staticmethod
    def _get_builtin_wordlist() -> str:
        """Get or create a built-in wordlist for ffuf."""
        # Write a small high-value wordlist to a temp file
        wordlist = [
            "admin", "login", "api", "config", "backup", "test", "debug", "dev",
            ".git/config", ".env", "robots.txt", "sitemap.xml", ".well-known/",
            "swagger.json", "swagger-ui", "api-docs", "health", "status",
            "webhook", "upload", "graphql", "wp-admin", "wp-login.php",
            "phpinfo.php", "server-status", "metrics", "actuator", "console",
            "dashboard", "panel", "internal", "secret", "private", "old",
            ".git/HEAD", ".svn/entries", "composer.json", "package.json",
            "Dockerfile", "docker-compose.yml", ".DS_Store", "crossdomain.xml",
        ]
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="gungnir_wl_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(wordlist))
        return path
