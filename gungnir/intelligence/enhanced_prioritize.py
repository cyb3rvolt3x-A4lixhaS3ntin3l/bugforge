"""
Enhanced prioritization engine — 10-factor priority scoring.

Each finding is scored on 10 independent factors (each 0.0–1.0), stored
individually in finding.extra["scores"]. The overall priority is a weighted
sum of those factors. A human-readable explanation is produced by
explain_priority().

This complements (does not replace) the basic prioritize.py single-number
scoring. The 10 factors give a much richer picture of why a finding matters.
"""
from __future__ import annotations
import time
from typing import Dict, List

from .correlate import Finding, AttackChain, Severity
from .severity import Severity
from ..utils.logger import get_logger

log = get_logger()


# ── Per-factor weights (sum to 1.0) ────────────────────────────────────
# Tuned so that raw severity and confidence dominate, with verified, chain
# membership and exploitability providing meaningful but bounded adjustments.
FACTOR_WEIGHTS: Dict[str, float] = {
    "severity":             0.20,
    "confidence":           0.15,
    "verified":             0.10,
    "endpoint_sensitivity": 0.10,
    "secret_type":          0.08,
    "tech_relevance":       0.07,
    "exposure_level":        0.08,
    "chain_member":         0.10,
    "novelty":              0.05,
    "exploitability":       0.07,
}
assert abs(sum(FACTOR_WEIGHTS.values()) - 1.0) < 1e-6, "Factor weights must sum to 1.0"


# ── Factor score tables ───────────────────────────────────────────────

_SEVERITY_SCORES: Dict[Severity, float] = {
    Severity.CRITICAL: 0.9,
    Severity.HIGH:     0.7,
    Severity.MEDIUM:   0.5,
    Severity.LOW:      0.3,
    Severity.INFO:     0.1,
}

# Endpoint path patterns → sensitivity. First match wins (ordered by specificity).
_ENDPOINT_SENSITIVITY: List[tuple] = [
    ("/admin",    0.9),
    ("/wp-admin", 0.9),
    ("/console",  0.9),
    ("/graphql",  0.8),
    ("/api/",     0.7),
    ("/api/v",    0.7),
    ("/actuator", 0.7),
    ("/debug",    0.6),
    ("/.git",     0.6),
    ("/.env",     0.6),
    ("/swagger",  0.5),
    ("/static",   0.1),
    ("/assets",   0.1),
    ("/images",   0.1),
]

# Secret type keywords → score.
_SECRET_TYPE_SCORES: List[tuple] = [
    ("aws_access_key", 0.9),
    ("aws_secret",     0.9),
    ("aws",            0.9),
    ("github_token",   0.8),
    ("github",         0.8),
    ("gcp",            0.85),
    ("google",         0.8),
    ("stripe",         0.85),
    ("private_key",    0.9),
    ("jwt",            0.7),
    ("slack",          0.6),
    ("twilio",         0.6),
    ("database_url",   0.7),
    ("generic",        0.3),
]


# ── Factor scorers (each returns 0.0–1.0) ─────────────────────────────

def _score_severity(f: Finding) -> float:
    return _SEVERITY_SCORES.get(f.severity, 0.3)


def _score_confidence(f: Finding) -> float:
    try:
        return max(0.0, min(1.0, float(f.confidence)))
    except (TypeError, ValueError):
        return 0.5


def _score_verified(f: Finding) -> float:
    return 0.1 if f.verified else 0.0


def _score_endpoint_sensitivity(f: Finding) -> float:
    url = (f.url or "").lower()
    if not url:
        # No URL — default to a neutral 0.4 so it neither helps nor hurts much.
        return 0.4
    for pattern, score in _ENDPOINT_SENSITIVITY:
        if pattern in url:
            return score
    # Unknown path: mild default.
    return 0.4


def _score_secret_type(f: Finding) -> float:
    if f.finding_type != "secret":
        # Non-secret findings don't get the secret-type boost; use a neutral
        # value so the factor contributes a small constant rather than zero.
        return 0.4
    blob = f"{f.title} {f.extra.get('secret_type', '')} {f.extra.get('rule', '')}".lower()
    for keyword, score in _SECRET_TYPE_SCORES:
        if keyword in blob:
            return score
    return 0.3  # generic / unknown secret


def _score_tech_relevance(f: Finding) -> float:
    """Old/known-vulnerable tech is more relevant to act on; brand-new tech less so."""
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    old_markers = ("outdated", "deprecated", "end of life", "eol", "old version",
                   "unsupported", "legacy", "cve-")
    new_markers = ("latest", "up to date", "current", "patched", "recent")
    if any(m in blob for m in old_markers):
        return 0.8
    if any(m in blob for m in new_markers):
        return 0.3
    return 0.5  # unknown / neutral


def _score_exposure_level(f: Finding) -> float:
    """How exposed is the affected asset: public > internal > localhost."""
    blob = f"{f.asset} {f.url}".lower()
    if "localhost" in blob or "127.0.0.1" in blob or "0.0.0.0" in blob:
        return 0.2
    if "10." in blob or "192.168." in blob or "172.16." in blob or "internal" in blob:
        return 0.5
    # Default: assume public internet-facing.
    return 0.9


def _score_chain_member(f: Finding) -> float:
    """+0.2 if the finding is part of an attack chain."""
    return 0.2 if f.extra.get("in_chain") else 0.0


def _score_novelty(f: Finding) -> float:
    """+0.15 if this finding is new since the last run."""
    first_seen = f.extra.get("first_seen")
    last_run = f.extra.get("last_run_ts")
    # If explicitly flagged as new, or first_seen is at/after last_run, it's novel.
    if f.extra.get("is_new"):
        return 0.15
    if first_seen is not None and last_run is not None:
        try:
            if float(first_seen) >= float(last_run):
                return 0.15
        except (TypeError, ValueError):
            pass
    # If there's no prior-run metadata at all, treat as first run → novel.
    if last_run is None and first_seen is None:
        return 0.15
    return 0.0


def _score_exploitability(f: Finding) -> float:
    """easy=0.9, medium=0.5, hard=0.2. Inferred from finding metadata/heuristics."""
    # Explicit override from upstream tooling wins.
    explicit = f.extra.get("exploitability")
    if isinstance(explicit, str):
        e = explicit.lower().strip()
        if e in ("easy", "trivial", "high"):
            return 0.9
        if e in ("medium", "moderate"):
            return 0.5
        if e in ("hard", "difficult", "low"):
            return 0.2
    elif isinstance(explicit, (int, float)):
        return max(0.0, min(1.0, float(explicit)))

    # Heuristic: verified findings with a working PoC / curl are easier.
    if f.verified and f.evidence and ("curl" in f.evidence.lower() or "poc" in f.evidence.lower()):
        return 0.9
    if f.verified:
        return 0.7
    # Known CVEs tend to have public exploits.
    blob = f"{f.title} {f.description}".lower()
    if "cve-" in blob:
        return 0.9
    # Info disclosures / fingerprinting are usually easy but low-impact.
    if f.finding_type in ("endpoint",) and f.severity in (Severity.LOW, Severity.INFO):
        return 0.9
    # SSRF / SSRF-adjacent findings are often gated by network position.
    if "ssrf" in blob:
        return 0.5
    # Default: medium.
    return 0.5


# Registry in canonical order.
_FACTOR_SCORERS = [
    ("severity",             _score_severity),
    ("confidence",           _score_confidence),
    ("verified",             _score_verified),
    ("endpoint_sensitivity", _score_endpoint_sensitivity),
    ("secret_type",          _score_secret_type),
    ("tech_relevance",       _score_tech_relevance),
    ("exposure_level",        _score_exposure_level),
    ("chain_member",         _score_chain_member),
    ("novelty",              _score_novelty),
    ("exploitability",       _score_exploitability),
]


def _weighted_sum(scores: Dict[str, float]) -> float:
    total = 0.0
    for name, weight in FACTOR_WEIGHTS.items():
        total += weight * scores.get(name, 0.0)
    return round(max(0.0, min(1.0, total)), 4)


def enhanced_prioritize(findings: List[Finding]) -> List[Finding]:
    """
    Score each finding on 10 factors and sort by overall priority.

    Each factor is stored individually in finding.extra["scores"] as a dict
    of factor_name → 0.0–1.0. The weighted overall priority is stored in
    finding.extra["priority_score"] (overwriting the basic scorer's value if
    present). Findings are sorted descending by overall priority.
    """
    for f in findings:
        scores: Dict[str, float] = {}
        for name, scorer in _FACTOR_SCORERS:
            try:
                scores[name] = round(max(0.0, min(1.0, float(scorer(f)))), 4)
            except Exception as e:
                log.debug(f"Scorer '{name}' raised on finding {f.title!r}: {e}")
                scores[name] = 0.0
        f.extra["scores"] = scores
        f.extra["priority_score"] = _weighted_sum(scores)

    findings.sort(key=lambda f: f.extra.get("priority_score", 0.0), reverse=True)
    return findings


# ── Human-readable explanation ────────────────────────────────────────

def _fmt(factor: str, score: float, weight: float) -> str:
    contribution = round(score * weight, 4)
    return f"  {factor:<22} score={score:.2f}  weight={weight:.2f}  →  {contribution:.3f}"


def explain_priority(finding: Finding) -> str:
    """
    Produce a human-readable explanation of a finding's priority score,
    listing each of the 10 factors, its raw score, its weight, its weighted
    contribution, and the overall priority.
    """
    scores = finding.extra.get("scores")
    if not isinstance(scores, dict) or not scores:
        # Score on the fly if not already scored.
        scores = {}
        for name, scorer in _FACTOR_SCORERS:
            try:
                scores[name] = round(max(0.0, min(1.0, float(scorer(finding)))), 4)
            except Exception:
                scores[name] = 0.0
        finding.extra["scores"] = scores
        finding.extra["priority_score"] = _weighted_sum(scores)

    overall = finding.extra.get("priority_score", _weighted_sum(scores))

    lines: List[str] = []
    lines.append(f"Priority explanation: {finding.title}")
    lines.append(f"  severity={finding.severity.value}  confidence={finding.confidence:.2f}  "
                 f"verified={finding.verified}  asset={finding.asset}")
    lines.append(f"  overall priority = {overall:.4f}")
    lines.append("  factors:")
    for name, weight in FACTOR_WEIGHTS.items():
        s = scores.get(name, 0.0)
        lines.append(_fmt(name, s, weight))
    lines.append("  notes:")
    notes = []
    if scores.get("chain_member", 0.0) > 0:
        notes.append("part of an attack chain")
    if scores.get("verified", 0.0) > 0:
        notes.append("verified on re-test")
    if scores.get("novelty", 0.0) > 0:
        notes.append("new since last run")
    if finding.finding_type == "secret":
        notes.append(f"secret type scored at {scores.get('secret_type', 0.0):.2f}")
    if not notes:
        notes.append("no special flags")
    lines.append("    " + "; ".join(notes))

    return "\n".join(lines)
