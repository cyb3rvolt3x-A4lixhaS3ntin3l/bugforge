"""
BugForge v3.1 Web Server — FastAPI with auth, full REST API, WebSocket,
and dashboard UI.

Features:
- Password-protected login (bcrypt)
- Session cookies + API key auth
- Full REST API for hunts, pipelines, tools, findings, history
- WebSocket for real-time scan progress
- Single-page dashboard UI
"""
from __future__ import annotations
import asyncio
import json
import os
import time
import uuid
from typing import Dict, Optional, List
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from ..core.config import get_config
from ..core.auth import AuthManager, Session
from ..core.pipelines import PipelineLoader
from ..core.custom_tools import CustomToolLoader
from ..core.binaries import BinaryManager
from ..core.detect import detect_target_type, TargetType
from ..core.parallel import ParallelEngine, ScanResult
from ..intelligence.correlate import correlate
from ..intelligence.prioritize import prioritize, prioritize_chains
from ..intelligence.filter import filter_fps
from ..intelligence.verify import verify_criticals
from ..storage.db import Database
from ..scope.validator import parse_brief
from ..reporting.report import ReportBuilder, ReportTemplate
from ..reporting.cvss import Cvss31, CvssVector
from ..utils.logger import get_logger

log = get_logger()


# ─── Pydantic Models ───

class LoginRequest(BaseModel):
    username: str
    password: str

class HuntRequest(BaseModel):
    target: str
    pipeline: Optional[str] = "Default"
    scope: Optional[str] = None
    no_tools: bool = False
    no_verify: bool = False

class PipelineCreateRequest(BaseModel):
    name: str
    description: str = ""
    stages: List[dict] = []
    target_types: List[str] = ["domain", "ip", "url"]
    scope_required: bool = False

class CustomToolRequest(BaseModel):
    name: str
    description: str = ""
    category: str = "vuln_scan"
    binary: str = ""
    command: str = ""
    parser: str = "none"
    timeout: int = 120
    wave: str = "deep_scan"
    tool_type: str = "executable"
    applies_to: List[str] = ["domain", "ip", "url"]

class PasswordChangeRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

class SetupRequest(BaseModel):
    username: str
    password: str


# ─── App State ───

class AppState:
    def __init__(self):
        config = get_config()
        self.config = config
        self.auth = AuthManager(str(config.home_dir / "auth.json"))
        self.pipelines = PipelineLoader(str(config.home_dir / "pipelines"))
        self.custom_tools = CustomToolLoader(str(config.home_dir / "tools"))
        self.bm = BinaryManager(str(config.bin_dir))
        self.db = Database(str(config.db_path))
        self.engine = ParallelEngine(self.bm, max_concurrent=config.max_concurrent)
        self.active_hunts: Dict[str, dict] = {}
        self.active_websockets: Dict[str, List[WebSocket]] = {}

state = AppState()


# ─── Auth Dependency ───

async def require_auth(request: Request) -> str:
    """Verify the user is authenticated. Returns username."""
    # Check session cookie
    session_token = request.cookies.get("bugforge_session")
    if session_token:
        session = state.auth.verify_session(session_token)
        if session:
            return session.username

    # Check API key header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        username = state.auth.verify_api_key(api_key)
        if username:
            return username

    # If auth not configured, allow all requests
    if not state.auth.is_configured():
        return "anonymous"

    raise HTTPException(status_code=401, detail="Not authenticated")


# ─── App Factory ───

def create_web_app() -> FastAPI:
    config = state.config
    app = FastAPI(title="BugForge v3.1", version="3.1.0")

    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )
    app.add_middleware(SessionMiddleware, secret_key=uuid.uuid4().hex)

    # Static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ═══ AUTH ROUTES ═══

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        if not state.auth.is_configured():
            return _render_setup_page()
        return _render_login_page()

    @app.post("/api/auth/setup")
    async def auth_setup(req: SetupRequest):
        if state.auth.is_configured():
            raise HTTPException(400, "Auth already configured")
        if state.auth.setup(req.username, req.password):
            session = state.auth.create_session(req.username)
            return {"status": "ok", "api_key": session.api_key,
                    "redirect": "/"}
        raise HTTPException(400, "Setup failed — password must be 6+ chars")

    @app.post("/api/auth/login")
    async def auth_login(req: LoginRequest):
        if not state.auth.verify(req.username, req.password):
            raise HTTPException(401, "Invalid credentials")
        session = state.auth.create_session(req.username)
        response = JSONResponse({"status": "ok", "api_key": session.api_key,
                                  "username": req.username})
        response.set_cookie("bugforge_session", session.token,
                            httponly=True, samesite="strict", max_age=86400)
        return response

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request):
        token = request.cookies.get("bugforge_session")
        if token:
            state.auth.logout(token)
        response = JSONResponse({"status": "ok"})
        response.delete_cookie("bugforge_session")
        return response

    @app.get("/api/auth/status")
    async def auth_status():
        return {"configured": state.auth.is_configured()}

    @app.post("/api/auth/password")
    async def auth_password(req: PasswordChangeRequest, username: str = Depends(require_auth)):
        if state.auth.change_password(req.username, req.old_password, req.new_password):
            return {"status": "ok"}
        raise HTTPException(400, "Password change failed")

    # ═══ HUNT ROUTES ═══

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, username: str = Depends(require_auth)):
        return _render_dashboard(username)

    @app.post("/api/hunt")
    async def start_hunt(req: HuntRequest, username: str = Depends(require_auth)):
        target = req.target.strip()
        target_type = detect_target_type(target)

        # Scope check
        if req.scope:
            scope = parse_brief(req.scope)
            ok, reason = scope.is_in_scope(target)
            if not ok:
                raise HTTPException(403, f"Target out of scope: {reason}")

        run_id = str(uuid.uuid4())[:12]
        state.active_hunts[run_id] = {"target": target, "status": "starting",
                                       "started_at": time.time(), "username": username}

        asyncio.create_task(_run_hunt_task(run_id, req, target, target_type))
        return {"run_id": run_id, "target": target, "status": "started"}

    @app.get("/api/hunt/{run_id}")
    async def get_hunt(run_id: str, username: str = Depends(require_auth)):
        if run_id not in state.active_hunts and run_id not in _completed_hunts:
            raise HTTPException(404, "Hunt not found")

        if run_id in _completed_hunts:
            return _completed_hunts[run_id]

        return {"run_id": run_id, **state.active_hunts[run_id]}

    @app.websocket("/ws/hunt/{run_id}")
    async def hunt_websocket(websocket: WebSocket, run_id: str):
        await websocket.accept()
        state.active_websockets.setdefault(run_id, []).append(websocket)
        try:
            await websocket.send_json({"type": "connected", "run_id": run_id})
            while True:
                await asyncio.sleep(1)
                if run_id in _completed_hunts:
                    await websocket.send_json({"type": "completed",
                                                **_completed_hunts[run_id]})
                    break
        except WebSocketDisconnect:
            pass
        finally:
            if run_id in state.active_websockets:
                state.active_websockets[run_id] = [
                    ws for ws in state.active_websockets[run_id] if ws != websocket
                ]

    # ═══ PIPELINE ROUTES ═══

    @app.get("/api/pipelines")
    async def list_pipelines(username: str = Depends(require_auth)):
        pipes = state.pipelines.load_all()
        return {"pipelines": [state.pipelines.to_dict(p) for p in pipes.values()]}

    @app.get("/api/pipelines/{name}")
    async def get_pipeline(name: str, username: str = Depends(require_auth)):
        pdef = state.pipelines.get(name)
        if not pdef:
            raise HTTPException(404, "Pipeline not found")
        return state.pipelines.to_dict(pdef)

    @app.post("/api/pipelines")
    async def create_pipeline(req: PipelineCreateRequest, username: str = Depends(require_auth)):
        path = state.pipelines.create(req.name, req.description, req.stages,
                                       req.target_types, req.scope_required)
        return {"status": "ok", "path": path}

    @app.delete("/api/pipelines/{name}")
    async def delete_pipeline(name: str, username: str = Depends(require_auth)):
        if state.pipelines.delete(name):
            return {"status": "ok"}
        raise HTTPException(400, "Cannot delete pipeline (built-in or not found)")

    # ═══ TOOL ROUTES ═══

    @app.get("/api/tools")
    async def list_tools(username: str = Depends(require_auth)):
        builtin = state.bm.status()
        custom = [state.custom_tools.to_dict(t) for t in state.custom_tools.load_all().values()]
        native = [
            {"name": "js-analyzer", "category": "analysis", "installed": True,
             "description": "JavaScript file analyzer", "type": "native"},
            {"name": "param-miner", "category": "discovery", "installed": True,
             "description": "Hidden parameter miner", "type": "native"},
            {"name": "api-discoverer", "category": "discovery", "installed": True,
             "description": "API endpoint discovery", "type": "native"},
        ]
        return {"builtin": builtin, "custom": custom, "native": native}

    @app.post("/api/tools")
    async def register_custom_tool(req: CustomToolRequest, username: str = Depends(require_auth)):
        path = state.custom_tools.register(
            req.name, req.description, req.category, req.binary,
            req.command, req.parser, req.timeout, req.wave, req.tool_type, req.applies_to
        )
        return {"status": "ok", "path": path}

    @app.delete("/api/tools/{name}")
    async def remove_custom_tool(name: str, username: str = Depends(require_auth)):
        if state.custom_tools.delete(name):
            return {"status": "ok"}
        raise HTTPException(404, "Custom tool not found")

    @app.post("/api/tools/{name}/install")
    async def install_tool(name: str, username: str = Depends(require_auth)):
        success = state.bm.install(name)
        return {"tool": name, "installed": success}

    # ═══ FINDINGS ROUTES ═══

    @app.get("/api/findings")
    async def list_findings(target: Optional[str] = None,
                            severity: Optional[str] = None,
                            username: str = Depends(require_auth)):
        if target:
            findings = state.db.get_all_findings(target)
        else:
            findings = []
            for t in state.db.get_history("") if False else []:
                findings.extend(state.db.get_all_findings(t["target"]))

        if severity:
            findings = [f for f in findings if f.get("severity") == severity]

        return {"findings": findings[:200], "total": len(findings)}

    # ═══ HISTORY ROUTES ═══

    @app.get("/api/history")
    async def list_history(target: Optional[str] = None,
                           username: str = Depends(require_auth)):
        if target:
            return {"history": state.db.get_history(target)}
        return {"history": []}

    @app.get("/api/history/{target}/diff")
    async def get_diff(target: str, username: str = Depends(require_auth)):
        current = state.db.get_all_findings(target)
        diff = state.db.diff(current, target)
        return {"new": len(diff.new), "resolved": len(diff.resolved),
                "recurring": len(diff.recurring)}

    # ═══ SCOPE ROUTES ═══

    @app.post("/api/scope/check")
    async def check_scope(target: str, brief: str,
                          username: str = Depends(require_auth)):
        scope = parse_brief(brief)
        ok, reason = scope.is_in_scope(target)
        return {"target": target, "in_scope": ok, "reason": reason}

    # ═══ REPORT ROUTES ═══

    @app.post("/api/reports")
    async def generate_report(target: str, username: str = Depends(require_auth)):
        findings = state.db.get_all_findings(target)
        if not findings:
            raise HTTPException(404, "No findings for target")

        lines = [f"# BugForge Report — {target}", ""]
        for i, f in enumerate(findings[:50], 1):
            lines.append(f"## #{i} [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}")
            lines.append(f"**Asset:** {f.get('asset', '')}  ")
            lines.append(f"**Source:** {f.get('source', '')}  ")
            lines.append(f"**Confidence:** {f.get('confidence', 0):.0%}\n")
            if f.get("url"):
                lines.append(f"**URL:** `{f['url']}`\n")
            if f.get("description"):
                lines.append(f"{f['description']}\n")
            lines.append("")

        report = "\n".join(lines)
        return {"report": report}

    # ═══ SETTINGS ═══

    @app.get("/api/settings")
    async def get_settings(username: str = Depends(require_auth)):
        return {
            "server": {"host": state.config.web_host, "port": state.config.web_port},
            "execution": {"max_concurrent": state.config.max_concurrent,
                          "verify_criticals": state.config.verify_criticals},
            "paths": {"bin": str(state.config.bin_dir),
                      "db": str(state.config.db_path),
                      "pipelines": str(state.config.home_dir / "pipelines"),
                      "tools": str(state.config.home_dir / "tools")},
            "auth_configured": state.auth.is_configured(),
        }

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": "3.1.0",
                "auth_configured": state.auth.is_configured()}

    return app


# ─── Completed hunts cache ───

_completed_hunts: Dict[str, dict] = {}


async def _run_hunt_task(run_id: str, req: HuntRequest, target: str, target_type: TargetType):
    """Background task that runs a hunt and broadcasts progress."""

    async def on_progress(tool_name, message):
        ws_list = state.active_websockets.get(run_id, [])
        dead = []
        for ws in ws_list:
            try:
                await ws.send_json({"type": "progress", "tool": tool_name,
                                    "message": message})
            except Exception:
                dead.append(ws)
        for ws in dead:
            ws_list.remove(ws)

        # Update hunt state
        if run_id in state.active_hunts:
            state.active_hunts[run_id].update({
                "current_tool": tool_name, "message": message,
                "status": "running"
            })

    try:
        # Run native modules
        native_findings = []
        from ..native.js_analyzer import analyze_js
        from ..native.param_miner import mine_parameters
        from ..native.api_discover import discover_apis

        async def run_native():
            await on_progress("native", "running JS analyzer, param miner, API discovery...")
            native_target = target
            if not native_target.startswith(("http://", "https://")):
                native_target = f"https://{native_target}"

            tasks = [
                asyncio.to_thread(analyze_js, native_target),
                asyncio.to_thread(discover_apis, native_target),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if not isinstance(r, Exception):
                    native_findings.extend(r)
            pm = mine_parameters(native_target)
            native_findings.extend(pm)
            await on_progress("native", f"✓ {len(native_findings)} native findings")

        native_task = asyncio.create_task(run_native())

        if req.no_tools:
            from ..core.parallel import ScanResult, WaveResult
            scan_result = ScanResult(target=target, target_type=target_type)
            scan_result.wave1 = WaveResult(wave=1, assets_discovered=[target])
            scan_result.wave2 = WaveResult(wave=2)
        else:
            scan_result = await state.engine.full_scan(target, target_type, progress_cb=on_progress)

        await native_task

        # Correlate
        await on_progress("correlate", f"analyzing {len(scan_result.all_findings + native_findings)} findings...")
        findings, chains = correlate(scan_result.all_findings + native_findings, target)
        findings = filter_fps(findings)
        findings = prioritize(findings, chains)
        chains = prioritize_chains(chains)

        # Verify
        if not req.no_verify and state.config.verify_criticals:
            await on_progress("verify", "re-testing criticals...")
            findings = await verify_criticals(findings)

        # Save
        await on_progress("save", "persisting to SQLite...")
        findings_dicts = [_finding_to_dict(f) for f in findings]
        for fd in findings_dicts:
            fd["dedup_key"] = f"{fd.get('type')}:{fd.get('asset')}:{fd.get('title', '')[:50]}"
        run_id_db = state.db.save_run(target, target_type.value,
                                       findings_count=len(findings))
        state.db.save_findings(findings_dicts, run_id_db, target)

        # Diff
        diff = state.db.diff(findings_dicts, target)

        # Complete
        result = {
            "run_id": run_id, "target": target, "status": "completed",
            "findings": findings_dicts[:100], "findings_count": len(findings),
            "attack_chains": [_chain_to_dict(ch) for ch in chains],
            "diff": {"new": len(diff.new), "resolved": len(diff.resolved),
                     "recurring": len(diff.recurring)},
            "elapsed": scan_result.total_elapsed,
            "completed_at": time.time(),
        }

        _completed_hunts[run_id] = result
        if run_id in state.active_hunts:
            state.active_hunts[run_id]["status"] = "completed"

        # Broadcast completion
        for ws in state.active_websockets.get(run_id, []):
            try:
                await ws.send_json({"type": "completed", **result})
            except Exception:
                pass

    except Exception as e:
        log.error(f"Hunt {run_id} failed: {e}")
        if run_id in state.active_hunts:
            state.active_hunts[run_id]["status"] = "failed"
            state.active_hunts[run_id]["error"] = str(e)
        for ws in state.active_websockets.get(run_id, []):
            try:
                await ws.send_json({"type": "error", "message": str(e)})
            except Exception:
                pass


def _finding_to_dict(f) -> dict:
    return {"title": f.title, "severity": f.severity.value, "asset": f.asset,
            "source": f.source, "type": f.finding_type, "description": f.description,
            "evidence": f.evidence, "url": f.url, "confidence": f.confidence,
            "verified": f.verified, "extra": f.extra}


def _chain_to_dict(ch) -> dict:
    return {"title": ch.title, "assets": ch.assets, "confidence": ch.confidence,
            "description": ch.description}


# ─── HTML Renderers ───

def _render_login_page() -> str:
    return """<!DOCTYPE html><html><head><title>BugForge Login</title>
<style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:350px}
h1{color:#58a6ff;text-align:center}
input{width:100%;padding:12px;margin:8px 0;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#fff;box-sizing:border-box}
button{width:100%;padding:12px;background:#58a6ff;border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:16px;margin-top:8px}
button:hover{opacity:0.85}
.err{color:#f85149;text-align:center;font-size:0.85rem}</style></head>
<body><div class="box"><h1>🐛 BugForge</h1>
<form onsubmit="login(event)"><input type="text" id="username" placeholder="Username" autofocus>
<input type="password" id="password" placeholder="Password">
<button type="submit">Login</button></form><div class="err" id="err"></div></div>
<script>
async function login(e){e.preventDefault();const u=document.getElementById('username').value;const p=document.getElementById('password').value;
try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
if(r.ok){window.location='/'}else{const d=await r.json();document.getElementById('err').textContent=d.detail||'Login failed'}}catch(err){document.getElementById('err').textContent=err}}
</script></body></html>"""


def _render_setup_page() -> str:
    return """<!DOCTYPE html><html><head><title>BugForge Setup</title>
<style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:400px}
h1{color:#58a6ff;text-align:center}p{color:#8b949e;text-align:center;font-size:0.85rem}
input{width:100%;padding:12px;margin:8px 0;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#fff;box-sizing:border-box}
button{width:100%;padding:12px;background:#3fb950;border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:16px;margin-top:8px}
.err{color:#f85149;text-align:center;font-size:0.85rem}</style></head>
<body><div class="box"><h1>🐛 BugForge Setup</h1>
<p>Create your admin account to get started.</p>
<form onsubmit="setup(event)"><input type="text" id="username" placeholder="Username" autofocus>
<input type="password" id="password" placeholder="Password (6+ characters)">
<button type="submit">Create Account</button></form><div class="err" id="err"></div></div>
<script>
async function setup(e){e.preventDefault();const u=document.getElementById('username').value;const p=document.getElementById('password').value;
try{const r=await fetch('/api/auth/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
if(r.ok){window.location='/'}else{const d=await r.json();document.getElementById('err').textContent=d.detail||'Setup failed'}}catch(err){document.getElementById('err').textContent=err}}
</script></body></html>"""


def _render_dashboard(username: str) -> str:
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    if template_path.is_file():
        html = template_path.read_text()
        return html.replace("{{USERNAME}}", username)
    return f"<h1>BugForge v3.1</h1><p>Welcome, {username}. Dashboard template not found.</p>"


# ─── Server launcher ───

def serve(host: str = "127.0.0.1", port: int = 8888, no_browser: bool = False):
    """Start the BugForge web server."""
    import uvicorn
    import threading, webbrowser, time

    app = create_web_app()

    if not no_browser:
        def _open():
            time.sleep(1.5)
            webbrowser.open(f"http://{host}:{port}")
        threading.Thread(target=_open, daemon=True).start()

    auth_status = "enabled" if state.auth.is_configured() else "NOT CONFIGURED (visit /login to setup)"
    print(f"""
╔══════════════════════════════════════════════════════╗
║  🐛 BugForge v3.1 — FORGE                             ║
║                                                      ║
║  Web UI:  http://{host}:{port:<5d}                       ║
║  API:     http://{host}:{port:<5d}/api/docs               ║
║  Auth:    {auth_status:<43s} ║
║                                                      ║
║  Press Ctrl+C to stop.                               ║
╚══════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host=host, port=port, log_level="info")
