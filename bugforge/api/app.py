"""
FastAPI application — BugForge v2.0 web backend.

Endpoints:
  GET  /                  → Web UI dashboard
  GET  /api/tools         → list all tools + install status
  POST /api/tools/{name}/install → manually install a tool
  POST /api/pipeline/run  → start a pipeline (returns run_id)
  GET  /api/pipeline/{id} → get pipeline results
  WS   /ws/pipeline/{id}  → WebSocket for live progress updates
  GET  /api/scope/check   → validate target against scope
  POST /api/report        → generate Markdown report from findings
"""
from __future__ import annotations
import asyncio
import json
import uuid
from typing import Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ..orchestrator.engine import ToolOrchestrator, ToolStatus
from ..orchestrator.registry import TOOL_REGISTRY, list_tools
from ..pipeline.stages import Pipeline, PipelineResult
from ..scope.validator import parse_brief
from ..reporting.report import ReportBuilder, ReportTemplate
from ..reporting.cvss import Cvss31, CvssVector
from ..utils.logger import get_logger, set_verbose

log = get_logger()


# ---- Models ----

class PipelineRequest(BaseModel):
    target: str
    brief: Optional[str] = None
    skip_stages: Optional[list[str]] = None
    auto_install: bool = True

class ScopeCheckRequest(BaseModel):
    target: str
    brief: str

class ReportRequest(BaseModel):
    title: str = "Security Finding"
    severity: str = "High"
    cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    summary: str = ""
    affected_url: str = ""
    steps: list[str] = []
    impact: str = ""
    poc: str = ""
    remediation: str = ""
    reporter: str = ""


# ---- App state ----

class AppState:
    def __init__(self):
        self.orchestrator = ToolOrchestrator(auto_install=True)
        self.pipelines: Dict[str, PipelineResult] = {}
        self.active_websockets: Dict[str, list[WebSocket]] = {}

state = AppState()


def create_app() -> FastAPI:
    app = FastAPI(
        title="BugForge v2.0",
        description="One-click bug bounty orchestration platform",
        version="2.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Static files
    import os
    static_dir = os.path.join(os.path.dirname(__file__), "..", "web", "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # ---- Routes ----

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve the web UI."""
        import os
        template_path = os.path.join(os.path.dirname(__file__), "..", "web", "templates", "dashboard.html")
        if os.path.isfile(template_path):
            with open(template_path) as f:
                return f.read()
        return "<h1>BugForge v2.0</h1><p>Web UI template not found. Use the API.</p>"

    @app.get("/api/tools")
    async def get_tools():
        """List all registered tools and their installation status."""
        return {"tools": state.orchestrator.status()}

    @app.post("/api/tools/{name}/install")
    async def install_tool(name: str):
        """Manually trigger tool installation."""
        if name not in TOOL_REGISTRY:
            raise HTTPException(404, f"Unknown tool: {name}")
        success = state.orchestrator.install(name)
        return {"tool": name, "installed": success,
                "status": state.orchestrator.is_installed(name)}

    @app.post("/api/pipeline/run")
    async def run_pipeline(req: PipelineRequest):
        """Start a pipeline run. Returns a run_id for WebSocket subscription."""
        run_id = str(uuid.uuid4())[:8]

        # Parse scope if provided
        scope = None
        if req.brief:
            scope = parse_brief(req.brief)
            ok, reason = scope.is_in_scope(req.target)
            if not ok:
                raise HTTPException(403, f"Target out of scope: {reason}")

        # Create pipeline
        pipe = Pipeline(state.orchestrator, scope=scope)

        # Start in background
        asyncio.create_task(_run_pipeline_task(run_id, pipe, req.target, req.skip_stages))

        return {"run_id": run_id, "target": req.target, "status": "started"}

    @app.get("/api/pipeline/{run_id}")
    async def get_pipeline(run_id: str):
        """Get pipeline results (if completed)."""
        if run_id not in state.pipelines:
            raise HTTPException(404, "Pipeline not found or still running")
        result = state.pipelines[run_id]
        return {
            "target": result.target,
            "summary": result.summary(),
            "findings": result.all_findings[:200],  # cap for API response
            "total_findings": len(result.all_findings),
            "elapsed": result.total_elapsed,
        }

    @app.websocket("/ws/pipeline/{run_id}")
    async def pipeline_websocket(websocket: WebSocket, run_id: str):
        """WebSocket for real-time pipeline progress."""
        await websocket.accept()
        state.active_websockets.setdefault(run_id, []).append(websocket)
        try:
            # Send initial status
            await websocket.send_json({"type": "connected", "run_id": run_id})
            # Keep connection alive until pipeline completes or client disconnects
            while True:
                await asyncio.sleep(1)
                if run_id in state.pipelines:
                    result = state.pipelines[run_id]
                    await websocket.send_json({
                        "type": "completed",
                        "summary": result.summary(),
                        "findings_count": len(result.all_findings),
                    })
                    break
        except WebSocketDisconnect:
            pass
        finally:
            if run_id in state.active_websockets:
                state.active_websockets[run_id] = [
                    ws for ws in state.active_websockets[run_id] if ws != websocket
                ]

    @app.post("/api/scope/check")
    async def check_scope(req: ScopeCheckRequest):
        """Validate a target against a scope brief."""
        scope = parse_brief(req.brief)
        ok, reason = scope.is_in_scope(req.target)
        return {"target": req.target, "in_scope": ok, "reason": reason}

    @app.post("/api/report")
    async def generate_report(req: ReportRequest):
        """Generate a Markdown bug report."""
        t = ReportTemplate(
            title=req.title, severity=req.severity,
            cvss_vector=req.cvss_vector, summary=req.summary,
            affected_url=req.affected_url, steps=req.steps,
            impact=req.impact, poc=req.poc,
            remediation=req.remediation, reporter=req.reporter,
        )
        md = ReportBuilder(t).build()
        return {"report": md, "cvss": Cvss31.full(CvssVector.parse(req.cvss_vector))}

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "2.0.0",
                "tools_registered": len(TOOL_REGISTRY),
                "tools_installed": sum(1 for t in TOOL_REGISTRY.values()
                                       if state.orchestrator.is_installed(t.name))}

    return app


async def _run_pipeline_task(run_id: str, pipe: Pipeline, target: str,
                              skip_stages: Optional[list[str]]):
    """Background task that runs the pipeline and broadcasts progress."""
    async def on_progress(stage_name, tool_name, message):
        # Broadcast to all connected WebSockets
        ws_list = state.active_websockets.get(run_id, [])
        dead = []
        for ws in ws_list:
            try:
                await ws.send_json({
                    "type": "progress",
                    "stage": stage_name,
                    "tool": tool_name,
                    "message": message,
                    "timestamp": asyncio.get_event_loop().time(),
                })
            except Exception:
                dead.append(ws)
        for ws in dead:
            ws_list.remove(ws)

    try:
        result = await pipe.run(target, on_progress=on_progress, skip_stages=skip_stages)
        state.pipelines[run_id] = result
        # Final broadcast
        for ws in state.active_websockets.get(run_id, []):
            try:
                await ws.send_json({
                    "type": "completed",
                    "summary": result.summary(),
                    "findings_count": len(result.all_findings),
                    "elapsed": result.total_elapsed,
                })
            except Exception:
                pass
    except Exception as e:
        log.error(f"Pipeline {run_id} failed: {e}")
        for ws in state.active_websockets.get(run_id, []):
            try:
                await ws.send_json({"type": "error", "message": str(e)})
            except Exception:
                pass


# Create the app instance
app = create_app()
