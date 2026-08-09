"""Shared utilities: HTTP client, terminal colors, logging."""
from .colors import Colors, c
from .logger import get_logger, set_verbose
from .http import HttpClient

__all__ = ["Colors", "c", "get_logger", "set_verbose", "HttpClient"]
