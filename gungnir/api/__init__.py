"""FastAPI backend with WebSocket support for real-time pipeline updates."""
from .app import create_app, app

__all__ = ["create_app", "app"]
