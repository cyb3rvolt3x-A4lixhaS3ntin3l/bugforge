"""Severity helper for correlate.py."""
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @staticmethod
    def _from_str(s: str) -> "Severity":
        s = s.lower().strip()
        if s in ("critical", "crit"):
            return Severity.CRITICAL
        if s in ("high", "hrisk"):
            return Severity.HIGH
        if s in ("medium", "moderate"):
            return Severity.MEDIUM
        if s in ("low", "info", "informational"):
            return Severity.LOW
        return Severity.MEDIUM
