"""
False-positive filter — removes known noise patterns from findings.
"""
from __future__ import annotations
import re
from typing import List
from .correlate import Finding


def filter_fps(findings: List[Finding]) -> List[Finding]:
    """Remove false positives using rule-based filtering."""
    filtered = []
    for f in findings:
        if _is_fp(f):
            continue
        filtered.append(f)
    return filtered


def _is_fp(f: Finding) -> bool:
    """Check if a finding is a likely false positive."""

    # Nuclei favicon checks (info severity, favicon-based) — almost always noise
    if f.source == "nuclei" and f.severity.value == "info":
        if "favicon" in f.title.lower() or "tech-detect" in f.title.lower():
            return True

    # XSS reflected in <code> or <pre> blocks (not executable)
    if f.finding_type == "xss":
        if f.evidence and ("<code>" in f.evidence or "<pre>" in f.evidence):
            return True

    # CORS wildcard without credentials (not exploitable in modern browsers)
    if f.finding_type == "cors":
        detail = f.description + f.evidence
        if "wildcard" in detail.lower() and "credential" not in detail.lower():
            return True

    # Very low confidence + single source
    if f.confidence < 0.2 and not f.verified:
        return True

    # Nuclei info severity with no real impact
    if f.severity.value == "info" and f.source == "nuclei":
        if not f.description or len(f.description) < 20:
            return True

    # Duplicate subdomain findings (not vulnerabilities)
    if f.finding_type == "subdomain" and f.severity.value == "info":
        return True

    # HTTP probe results (informational, not vulnerabilities)
    if f.finding_type == "http_probe" and f.severity.value == "info":
        return True

    return False
