"""
Correlation engine — cross-references findings from different tools,
builds attack chains, and groups related findings by asset.

This is the core intelligence layer. No database. No events. Just fast Python.
"""
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional
from .severity import Severity


@dataclass
class Finding:
    title: str
    severity: Severity
    asset: str
    source: str  # which tool found it
    finding_type: str  # vulnerability, secret, xss, cors, etc.
    description: str = ""
    evidence: str = ""
    url: str = ""
    confidence: float = 0.5
    verified: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        """Key for deduplication — same finding from different tools."""
        return f"{self.finding_type}:{self.asset}:{self.title.lower()[:50]}"


@dataclass
class AttackChain:
    title: str
    assets: List[str]
    findings: List[Finding]
    confidence: float
    description: str


def correlate(all_findings: List[dict], target: str) -> tuple[List[Finding], List[AttackChain]]:
    """
    Take raw findings from all tools, correlate them, build attack chains.

    Returns (findings, attack_chains).
    """
    # Convert raw dicts to Finding objects
    raw = [_to_finding(f, target) for f in all_findings]

    # Group by asset
    by_asset = defaultdict(list)
    for f in raw:
        asset = f.asset or target
        by_asset[asset].append(f)

    findings: List[Finding] = []
    chains: List[AttackChain] = []

    for asset, afs in by_asset.items():
        # Categorize findings for this asset
        vulns = [f for f in afs if f.finding_type == "vulnerability"]
        secrets = [f for f in afs if f.finding_type == "secret"]
        xss = [f for f in afs if f.finding_type == "xss"]
        cors = [f for f in afs if f.finding_type == "cors"]
        endpoints = [f for f in afs if f.finding_type == "endpoint"]
        api_routes = [f for f in afs if f.finding_type == "api_route"]
        graphql = [f for f in afs if "graphql" in f.finding_type]
        swagger = [f for f in afs if "swagger" in f.finding_type]
        git_exposed = [f for f in endpoints if ".git" in f.url or ".git" in f.extra.get("path", "")]

        # ── Attack chain detection ──

        # Chain 1: SSRF + secret exposure
        ssrf = [f for f in vulns if "ssrf" in f.title.lower() or "ssrf" in f.description.lower()]
        if ssrf and secrets:
            chains.append(AttackChain(
                title="SSRF → cloud metadata → credential theft",
                assets=[asset],
                findings=ssrf + secrets,
                confidence=0.9,
                description=(
                    f"SSRF vulnerability on {asset} combined with secret exposure. "
                    f"An attacker could use SSRF to access cloud metadata endpoints "
                    f"(169.254.169.254) and steal the exposed credentials."
                )))

        # Chain 2: .git exposed + secret
        if git_exposed and secrets:
            chains.append(AttackChain(
                title=".git directory exposed → source code → secrets leaked",
                assets=[asset],
                findings=git_exposed + secrets,
                confidence=0.95,
                description=(
                    f"Git repository exposed on {asset}. Combined with secrets found "
                    f"in the codebase, an attacker can download the full source and "
                    f"extract credentials."
                )))

        # Chain 3: Open redirect + SSRF
        open_redirects = [f for f in vulns if "redirect" in f.title.lower()]
        if open_redirects and ssrf:
            chains.append(AttackChain(
                title="Open redirect → SSRF bypass",
                assets=[asset],
                findings=open_redirects + ssrf,
                confidence=0.7,
                description=(
                    f"Open redirect on {asset} can be used to bypass SSRF filters "
                    f"by chaining through the redirect."
                )))

        # Chain 4: XSS + sensitive endpoint
        if xss and any("admin" in f.url.lower() or "account" in f.url.lower() for f in endpoints):
            chains.append(AttackChain(
                title="XSS on sensitive endpoint → session hijack → account takeover",
                assets=[asset],
                findings=xss + [f for f in endpoints if "admin" in f.url.lower()],
                confidence=0.8,
                description=(
                    f"XSS vulnerability on {asset} near admin/account endpoints. "
                    f"An attacker could steal session tokens and take over accounts."
                )))

        # Chain 5: GraphQL introspection + API routes
        if graphql and api_routes:
            chains.append(AttackChain(
                title="GraphQL introspection + API routes → full API mapping",
                assets=[asset],
                findings=graphql + api_routes,
                confidence=0.8,
                description=(
                    f"GraphQL introspection enabled on {asset} combined with discovered "
                    f"API routes. An attacker can map the entire API and find injection "
                    f"points."
                )))

        # Chain 6: Swagger exposed → endpoint enumeration
        if swagger:
            chains.append(AttackChain(
                title="Swagger/OpenAPI exposed → endpoint enumeration → IDOR testing",
                assets=[asset],
                findings=swagger,
                confidence=0.75,
                description=(
                    f"Swagger/OpenAPI specification exposed on {asset}. "
                    f"All API endpoints are documented — test for IDOR, BOLA, auth issues."
                )))

        # ── Tech-specific prioritization ──
        # If WordPress detected, boost WP-related findings
        wp_findings = [f for f in vulns if "wordpress" in f.title.lower() or "wp-" in f.url.lower()]
        for f in wp_findings:
            f.confidence = min(1.0, f.confidence + 0.2)
            f.extra["tech_specific"] = "wordpress"

        # If API endpoint found, boost injection findings
        if api_routes or graphql or swagger:
            injection_findings = [f for f in vulns if any(kw in f.title.lower()
                for kw in ["sqli", "injection", "idor", "auth"])]
            for f in injection_findings:
                f.confidence = min(1.0, f.confidence + 0.15)

        # ── Add all findings ──
        findings.extend(afs)

    # ── Deduplication ──
    findings = _dedupe(findings)

    return findings, chains


def _to_finding(raw: dict, default_target: str) -> Finding:
    """Convert a raw finding dict to a Finding object."""
    ftype = raw.get("type", "unknown")
    source = raw.get("_source", raw.get("source", "unknown"))
    asset = raw.get("target", raw.get("url", raw.get("asset", default_target)))

    # Extract asset domain from URL
    if asset.startswith("http"):
        from urllib.parse import urlparse
        asset = urlparse(asset).hostname or asset

    # Map type to severity
    severity_map = {
        "secret": Severity.HIGH,
        "vulnerability": Severity._from_str(raw.get("severity", "medium")),
        "xss": Severity.HIGH,
        "cors": Severity.MEDIUM,
        "graphql_introspection_enabled": Severity.MEDIUM,
        "swagger_exposed": Severity.MEDIUM,
        "source_map_exposed": Severity.LOW,
        "parameter_reflected": Severity.LOW,
        "parameter_sqli_indicator": Severity.HIGH,
        "actuator_exposed": Severity.HIGH,
    }
    severity = severity_map.get(ftype) or Severity._from_str(raw.get("severity", "medium"))

    # Build title
    title_map = {
        "secret": f"Secret exposed: {raw.get('secret_type', raw.get('rule', 'unknown'))}",
        "vulnerability": raw.get("name", raw.get("template", "Vulnerability")),
        "xss": "Cross-Site Scripting (XSS)",
        "cors": "CORS misconfiguration",
        "graphql_introspection_enabled": "GraphQL introspection enabled",
        "swagger_exposed": "Swagger/OpenAPI spec exposed",
        "graphql_endpoint": "GraphQL endpoint detected",
        "actuator_exposed": "Spring Boot Actuator exposed",
        "source_map_exposed": "Source map exposed",
        "parameter_reflected": f"Parameter reflected: {raw.get('parameter', '')}",
        "parameter_sqli_indicator": f"SQL error on parameter: {raw.get('parameter', '')}",
    }
    title = title_map.get(ftype, ftype.replace("_", " ").title())

    return Finding(
        title=title,
        severity=severity,
        asset=asset,
        source=source,
        finding_type=ftype,
        description=raw.get("description", raw.get("note", "")),
        evidence=raw.get("curl", raw.get("secret", raw.get("detail", ""))),
        url=raw.get("url", raw.get("route", "")),
        confidence=0.6 if source != "unknown" else 0.3,
        extra={k: v for k, v in raw.items() if k not in ("type", "_source", "_wave")},
    )


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings, keeping the one with highest confidence."""
    by_key = {}
    for f in findings:
        key = f.dedup_key
        if key not in by_key or f.confidence > by_key[key].confidence:
            by_key[key] = f
    return list(by_key.values())
