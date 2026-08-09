"""Core modules: config, binary manager, target detection, scope guard, parallel engine, tool profiles, session manager."""
from .session import SessionManager, AuthContext

__all__ = ["SessionManager", "AuthContext"]
