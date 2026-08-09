"""
Gungnir v2.0 — Tool Orchestration Engine

Auto-detects, auto-installs, and wraps industry-standard open-source security
tools. Users don't install Subfinder, ffuf, Nuclei, etc. individually —
Gungnir handles it.

Each tool wrapper:
  1. Checks if the tool binary is available
  2. Auto-installs if missing (go install / pip / docker)
  3. Runs with optimal flags
  4. Parses structured (JSON) output
  5. Returns standardized results
"""
from .engine import ToolOrchestrator, ToolResult, ToolStatus
from .registry import TOOL_REGISTRY, ToolDefinition

__all__ = ["ToolOrchestrator", "ToolResult", "ToolStatus",
           "TOOL_REGISTRY", "ToolDefinition"]
