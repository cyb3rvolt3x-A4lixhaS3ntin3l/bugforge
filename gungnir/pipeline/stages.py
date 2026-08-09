"""
Pipeline engine — chains tools into automated workflows.

A pipeline is a sequence of stages:
  1. RECON         → find subdomains
  2. PROBE         → check which subdomains are live
  3. FINGERPRINT   → identify tech stack
  4. DISCOVERY     → find hidden endpoints
  5. VULN_SCAN     → run Nuclei templates
  6. XSS           → test for XSS
  7. SQLI          → test for SQL injection
  8. SECRET        → scan for leaked secrets
  9. CORS          → check CORS misconfig
  10. REPORT       → generate consolidated report

Each stage feeds its output into the next. Results accumulate and are
streamed to the web UI via WebSocket.
"""
from __future__ import annotations
import asyncio
import json
import tempfile
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Callable, Awaitable, Dict, Any

from ..orchestrator.engine import ToolOrchestrator, ToolResult, ToolStatus
from ..orchestrator.registry import ToolCategory
from ..utils.logger import get_logger
from ..scope.validator import Scope, parse_brief

log = get_logger()


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PipelineStage:
    name: str
    category: Optional[ToolCategory]
    tool_name: Optional[str] = None  # specific tool, or None = all in category
    description: str = ""
    status: StageStatus = StageStatus.PENDING
    results: List[ToolResult] = field(default_factory=list)
    elapsed: float = 0.0
    enabled: bool = True


@dataclass
class PipelineResult:
    target: str
    stages: List[PipelineStage] = field(default_factory=list)
    all_findings: List[dict] = field(default_factory=list)
    total_elapsed: float = 0.0
    scope: Optional[Scope] = None

    def findings_by_category(self, category: str) -> List[dict]:
        return [f for f in self.all_findings if f.get("_category") == category]

    def summary(self) -> dict:
        cats: Dict[str, int] = {}
        for f in self.all_findings:
            cat = f.get("_category", "unknown")
            cats[cat] = cats.get(cat, 0) + 1
        return {
            "target": self.target,
            "total_findings": len(self.all_findings),
            "by_category": cats,
            "stages": [
                {"name": s.name, "status": s.status.value, "findings": len(s.results)}
                for s in self.stages
            ],
        }


class Pipeline:
    """
    Orchestrates a full bug-bounty pipeline against a target.

    Usage:
        pipe = Pipeline(orchestrator, scope=parse_brief(open("brief.txt").read()))
        result = await pipe.run("example.com", on_progress=ws_callback)
    """

    def __init__(self, orchestrator: ToolOrchestrator,
                 scope: Optional[Scope] = None,
                 stages: Optional[List[PipelineStage]] = None):
        self.orch = orchestrator
        self.scope = scope
        self.stages = stages or self._default_stages()

    def _default_stages(self) -> List[PipelineStage]:
        return [
            PipelineStage("recon", ToolCategory.RECON, "subfinder",
                          "Subdomain enumeration"),
            PipelineStage("probe", ToolCategory.FINGERPRINT, "httpx",
                          "HTTP probing — find live hosts"),
            PipelineStage("fingerprint", ToolCategory.FINGERPRINT, "httpx",
                          "Tech stack fingerprinting"),
            PipelineStage("discovery", ToolCategory.DISCOVERY, "ffuf",
                          "Content/endpoint discovery"),
            PipelineStage("vuln_scan", ToolCategory.VULN_SCAN, "nuclei",
                          "Template-based vulnerability scan"),
            PipelineStage("xss", ToolCategory.XSS, "dalfox",
                          "XSS scanning"),
            PipelineStage("sqli", ToolCategory.SQLI, "sqlmap",
                          "SQL injection testing"),
            PipelineStage("secret", ToolCategory.SECRET, "gitleaks",
                          "Secret scanning"),
            PipelineStage("cors", ToolCategory.CORS, "corsy",
                          "CORS misconfiguration check"),
        ]

    async def run(self, target: str,
                  on_progress: Optional[Callable[[str, str, str], Awaitable[None]]] = None,
                  skip_stages: Optional[List[str]] = None
                  ) -> PipelineResult:
        """
        Execute the full pipeline.

        :param target: domain or URL
        :param on_progress: async callback(stage_name, tool_name, message)
        :param skip_stages: list of stage names to skip
        """
        skip = skip_stages or []
        result = PipelineResult(target=target, scope=self.scope)
        import time
        pipeline_start = time.time()

        # Validate scope first
        if self.scope:
            ok, reason = self.scope.is_in_scope(target)
            if not ok:
                log.error(f"Target {target} is OUT OF SCOPE: {reason}")
                if on_progress:
                    await on_progress("scope", "", f"BLOCKED: {reason}")
                return result

        # Track discovered subdomains for later stages
        discovered_hosts: List[str] = [target]
        live_hosts: List[str] = []

        for stage in self.stages:
            if stage.name in skip or not stage.enabled:
                stage.status = StageStatus.SKIPPED
                continue

            stage.status = StageStatus.RUNNING
            if on_progress:
                await on_progress(stage.name, stage.tool_name or "", f"starting {stage.name}...")

            stage_start = time.time()

            try:
                if stage.name == "recon":
                    # Run subfinder against the target domain
                    r = await self.orch.run(stage.tool_name, target,
                                            progress_callback=self._make_cb(on_progress, stage.name))
                    stage.results = [r]
                    if r.findings:
                        for f in r.findings:
                            host = f.get("subdomain", "")
                            if host:
                                # Scope check
                                if self.scope is None or self.scope.is_in_scope(f"https://{host}/")[0]:
                                    discovered_hosts.append(host)
                                    result.all_findings.append({**f, "_category": "recon",
                                                                "_stage": stage.name})

                elif stage.name == "probe":
                    # Write discovered hosts to a temp file for httpx
                    hosts_file = self._write_hosts_file(discovered_hosts)
                    r = await self.orch.run(stage.tool_name, target,
                                            options={"input_file": hosts_file},
                                            progress_callback=self._make_cb(on_progress, stage.name))
                    stage.results = [r]
                    if r.findings:
                        for f in r.findings:
                            url = f.get("url", "")
                            if url:
                                live_hosts.append(url)
                                result.all_findings.append({**f, "_category": "probe",
                                                            "_stage": stage.name})

                elif stage.name in ("fingerprint", "discovery", "vuln_scan", "xss", "cors"):
                    # Run against each live host (limit to avoid overload)
                    targets = live_hosts[:10] if live_hosts else [target]
                    for t in targets:
                        r = await self.orch.run(stage.tool_name, t,
                                                progress_callback=self._make_cb(on_progress, stage.name))
                        stage.results.append(r)
                        if r.findings:
                            for f in r.findings:
                                result.all_findings.append({**f, "_category": stage.category.value,
                                                            "_stage": stage.name, "_target": t})

                elif stage.name == "sqli":
                    # Only test URLs with parameters
                    param_urls = [h for h in live_hosts if "?" in h]
                    if not param_urls:
                        stage.status = StageStatus.SKIPPED
                        if on_progress:
                            await on_progress(stage.name, "", "no parameterized URLs found, skipping")
                        continue
                    for url in param_urls[:5]:
                        r = await self.orch.run(stage.tool_name, url,
                                                progress_callback=self._make_cb(on_progress, stage.name))
                        stage.results.append(r)

                elif stage.name == "secret":
                    # Scan the target as a repo or directory
                    r = await self.orch.run(stage.tool_name, target,
                                            progress_callback=self._make_cb(on_progress, stage.name))
                    stage.results = [r]
                    if r.findings:
                        result.all_findings.extend(
                            {**f, "_category": "secret", "_stage": stage.name}
                            for f in (r.findings if isinstance(r.findings, list) else [r.findings])
                            if isinstance(f, dict)
                        )

                stage.status = StageStatus.COMPLETED

            except Exception as e:
                log.error(f"Stage {stage.name} failed: {e}")
                stage.status = StageStatus.FAILED
                if on_progress:
                    await on_progress(stage.name, "", f"failed: {e}")

            stage.elapsed = time.time() - stage_start
            if on_progress:
                count = sum(len(r.findings) for r in stage.results)
                await on_progress(stage.name, "", f"completed — {count} findings ({stage.elapsed:.1f}s)")

        result.total_elapsed = time.time() - pipeline_start
        return result

    def _make_cb(self, on_progress, stage_name):
        """Wrap the orchestrator's progress callback to include stage name."""
        async def cb(tool_name, message):
            if on_progress:
                await on_progress(stage_name, tool_name, message)
        return cb

    @staticmethod
    def _write_hosts_file(hosts: List[str]) -> str:
        """Write discovered hosts to a temp file for tools that need -l."""
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="gungnir_")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(hosts))
        return path
