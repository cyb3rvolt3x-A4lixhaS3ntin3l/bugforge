"""
Prioritization engine — scores findings by real impact, not just scanner severity.
"""
from __future__ import annotations
from typing import List
from .correlate import Finding, AttackChain, Severity


def prioritize(findings: List[Finding], chains: List[AttackChain] = None) -> List[Finding]:
    """Score and sort findings by priority."""
    for f in findings:
        f.extra["priority_score"] = _score(f)

    findings.sort(key=lambda f: f.extra.get("priority_score", 0), reverse=True)
    return findings


def _score(f: Finding) -> float:
    """Calculate priority score 0.0-1.0."""
    score = 0.0

    # Base severity
    sev_scores = {
        Severity.CRITICAL: 0.9,
        Severity.HIGH: 0.7,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.3,
        Severity.INFO: 0.1,
    }
    score += sev_scores.get(f.severity, 0.3) * 0.5

    # Confidence
    score += f.confidence * 0.2

    # Verified boost
    if f.verified:
        score += 0.1

    # High-value endpoint boost
    high_value_paths = ["/admin", "/wp-admin", "/api/", "/graphql", "/console",
                        "/debug", "/.git", "/.env", "/actuator", "/swagger"]
    if any(p in f.url.lower() for p in high_value_paths):
        score += 0.15

    # Secret type boost
    if f.finding_type == "secret":
        high_value_secrets = ["aws_key", "github_token", "google_api_key", "stripe_key", "jwt"]
        if any(s in f.title.lower() or s in f.extra.get("secret_type", "").lower()
               for s in high_value_secrets):
            score += 0.2

    # Parameter SQLi indicator boost
    if f.finding_type == "parameter_sqli_indicator":
        score += 0.15

    return min(1.0, score)


def prioritize_chains(chains: List[AttackChain]) -> List[AttackChain]:
    """Sort attack chains by confidence."""
    chains.sort(key=lambda c: c.confidence, reverse=True)
    return chains
