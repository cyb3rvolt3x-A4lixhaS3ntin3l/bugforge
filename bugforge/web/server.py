"""
BugForge v2.0 server launcher.

Usage:
    bugforge serve [--host 0.0.0.0] [--port 8000]
    bugforge serve  → opens web UI at http://localhost:8000
"""
from __future__ import annotations
import argparse
import webbrowser
import threading


def serve(args):
    """Start the BugForge web server."""
    import uvicorn
    from ..api.app import app

    host = args.host
    port = args.port

    # Open browser after short delay
    if not args.no_browser:
        def _open():
            import time
            time.sleep(1.5)
            webbrowser.open(f"http://{host}:{port}")
        threading.Thread(target=_open, daemon=True).start()

    print(f"""
╔══════════════════════════════════════════════════════╗
║  🐝 BugForge v2.0 — Orchestration Platform           ║
║                                                      ║
║  Web UI:  http://{host}:{port:<5}                       ║
║  API:     http://{host}:{port:<5}/api/docs               ║
║                                                      ║
║  Tools auto-install on first use.                    ║
║  Press Ctrl+C to stop.                               ║
╚══════════════════════════════════════════════════════╝
""")

    uvicorn.run(app, host=host, port=port, log_level="info")
