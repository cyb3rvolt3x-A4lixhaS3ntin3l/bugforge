"""Scope management — program-brief parsing and in-scope validation."""
from .validator import Scope, ScopeValidator, parse_brief, load_brief_file

__all__ = ["Scope", "ScopeValidator", "parse_brief", "load_brief_file"]
