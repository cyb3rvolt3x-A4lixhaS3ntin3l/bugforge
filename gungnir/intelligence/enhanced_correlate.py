"""
Enhanced correlation engine — 25+ attack chain patterns for cross-referencing
findings from different tools.

This builds on the basic correlate.py by adding a much larger library of attack
chain patterns, each expressed as a declarative tuple so the patterns are easy
to audit and extend. No database. No events. Just fast Python.
"""
from __future__ import annotations
from typing import List, Tuple

from .correlate import Finding, AttackChain, Severity
from .severity import Severity
from ..utils.logger import get_logger

log = get_logger()


# Each chain pattern is a tuple of:
#   (condition_a_type, condition_b_type, chain_title, confidence, description)
#
# condition_a_type / condition_b_type are symbolic "condition" names (see
# _CONDITION_MATCHERS below) that map a single finding to a category. A chain
# fires when, for a given asset, at least one finding matches condition_a and
# at least one (different) finding matches condition_b.
ATTACK_CHAINS: List[Tuple[str, str, str, float, str]] = [
    # ── Secrets + cloud / source access ──────────────────────────────────
    ("ssrf", "secret",
     "SSRF → metadata → credentials", 0.9,
     "SSRF vulnerability combined with an exposed secret. The SSRF can be used "
     "to reach cloud metadata endpoints (169.254.169.254) and the leaked "
     "secret confirms real credentials exist in the environment."),
    ("git_exposed", "secret",
     "Source code → secrets", 0.95,
     "An exposed .git directory combined with a leaked secret. An attacker "
     "can reconstruct the full source tree and extract the embedded "
     "credentials, giving them offline access to every commit."),
    ("secret", "cloud_metadata",
     "Secret + SSRF → cloud takeover", 0.9,
     "A leaked secret plus evidence that cloud metadata endpoints are "
     "reachable. An attacker can combine the two to assume the cloud role "
     "and pivot to full account takeover."),
    ("backup_file", "secret",
     "Backup → source → secrets", 0.85,
     "A discovered backup file combined with a secret. Backup artifacts "
     "often contain the full source tree with credentials intact, bypassing "
     "the protections applied to the live codebase."),
    ("debug_mode", "secret",
     "Debug mode → stack trace → secrets", 0.7,
     "Debug mode enabled alongside a leaked secret. Verbose error pages "
     "leak stack traces and environment variables, and the exposed secret "
     "confirms the leaked values are valid."),
    ("jwt_exposed", "admin_endpoint",
     "JWT + admin → token replay", 0.7,
     "An exposed or weakly-signed JWT combined with an admin endpoint. An "
     "attacker can forge or replay the token to reach privileged "
     "functionality."),

    # ── Redirect / SSRF / CORS chaining ──────────────────────────────────
    ("open_redirect", "ssrf",
     "Redirect → SSRF bypass", 0.7,
     "An open redirect combined with an SSRF finding. The redirect can be "
     "used as a hop to bypass SSRF allow-lists or internal-network "
     "restrictions."),
    ("cors_misconfig", "auth_cookie",
     "CORS + credentials → cross-origin theft", 0.8,
     "A CORS misconfiguration that reflects arbitrary origins combined with "
     "an auth cookie finding. An attacker can read authenticated responses "
     "cross-origin and steal the session."),
    ("missing_hsts", "ssl_mitm",
     "No HSTS → MITM", 0.5,
     "Missing HSTS combined with an SSL/TLS MITM indicator. Without HSTS the "
     "connection can be downgraded, enabling credential interception on the "
     "wire."),
    ("subdomain_takeover", "auth_cookie",
     "Takeover + cookie → phishing", 0.7,
     "A vulnerable subdomain takeover combined with an auth cookie scoped to "
     "the parent domain. An attacker who claims the subdomain can host "
     "phishing pages that read the inherited cookies."),

    # ── XSS / CSRF / session chaining ────────────────────────────────────
    ("xss", "admin_endpoint",
     "XSS → session hijack → admin", 0.8,
     "XSS combined with an admin endpoint on the same asset. An attacker can "
     "steal an admin session cookie and reach privileged functions directly."),
    ("xss", "csrf_weak",
     "XSS + weak CSRF → account takeover", 0.75,
     "XSS combined with weak or missing CSRF protections. The XSS can be "
     "used to forge authenticated state-changing requests, leading to full "
     "account takeover."),
    ("param_reflection", "xss",
     "Param reflection → confirmed XSS", 0.8,
     "Reflected parameter output combined with a confirmed XSS finding. The "
     "reflection is the injection sink that makes the XSS exploitable."),
    ("trace_method", "auth_cookie",
     "XST + HttpOnly bypass → cookie theft", 0.65,
     "TRACE method enabled combined with an HttpOnly auth cookie. Cross-Site "
     "Tracing (XST) reads cookies that JavaScript cannot, defeating the "
     "HttpOnly flag."),
    ("weak_csp", "xss",
     "Weak CSP + XSS → easier exploitation", 0.6,
     "A weak or absent Content-Security-Policy combined with a confirmed "
     "XSS. The weak CSP removes the last browser-side defence, making the "
     "XSS trivial to weaponise."),

    # ── Injection / auth bypass ──────────────────────────────────────────
    ("sqli", "admin_panel",
     "SQLi → auth bypass → admin", 0.85,
     "SQL injection combined with an exposed admin panel. The SQLi enables "
     "authentication bypass straight into the admin surface."),
    ("sqli", "login_page",
     "SQLi → auth bypass", 0.85,
     "SQL injection on or near a login page. Classic auth-bypass primitive: "
     "the injection point is the login form itself."),
    ("graphql_introspection", "sqli",
     "GraphQL + SQLi → injection via API", 0.7,
     "GraphQL introspection enabled combined with SQL injection. The "
     "introspection maps every mutation/field, giving the attacker precise "
     "injection targets through the API layer."),
    ("mass_assignment", "admin_endpoint",
     "Mass assignment → privilege escalation", 0.75,
     "A mass-assignment vulnerability combined with an admin endpoint. An "
     "attacker can add an 'isAdmin' / 'role' field to a request and promote "
     "their own account."),

    # ── API surface / enumeration ───────────────────────────────────────
    ("graphql_introspection", "api_route",
     "Full API mapping", 0.8,
     "GraphQL introspection enabled combined with discovered API routes. "
     "Together they expose the complete API surface for targeted fuzzing."),
    ("swagger", "endpoint",
     "Endpoint enumeration → IDOR", 0.75,
     "An exposed Swagger/OpenAPI spec combined with discovered endpoints. "
     "The documented endpoints are prime IDOR / BOLA targets."),
    ("swagger", "idor",
     "Swagger + IDOR → unauthorized access", 0.7,
     "An exposed Swagger spec combined with an IDOR finding. The spec names "
     "the vulnerable object IDs, making the IDOR trivial to reproduce."),
    ("source_map", "api_route",
     "Source map → full app mapping", 0.8,
     "An exposed source map combined with discovered API routes. The source "
     "map reveals the un-minified client code, internal route names and "
     "undocumented endpoints."),
    ("git_exposed", "endpoint",
     "Git + endpoint → source disclosure", 0.8,
     "An exposed .git directory combined with discovered endpoints. The git "
     "history leaks the source behind those endpoints, including auth logic."),

    # ── Dangerous methods / files ───────────────────────────────────────
    ("put_method", "backup_file",
     "PUT + backup → write malicious file", 0.7,
     "Enabled PUT method combined with a discovered backup path. An "
     "attacker can write a malicious file (webshell) into the backup or "
     "backup-adjacent directory."),

    # ── Outdated tech / CVEs ────────────────────────────────────────────
    ("old_tech", "known_cve",
     "Old tech → known CVE → exploitation", 0.85,
     "Outdated technology fingerprint combined with a known CVE finding. "
     "The version is old enough that public exploits are reliable."),
]

assert len(ATTACK_CHAINS) >= 25, "ATTACK_CHAINS must contain at least 25 patterns"


# ── Condition matchers ────────────────────────────────────────────────────
# Each condition maps a single Finding to a boolean "does this finding satisfy
# this condition?". Conditions are matched against finding_type, title,
# description, url and relevant extra fields so they work regardless of which
# upstream tool produced the finding.

def _cond_ssrf(f: Finding) -> bool:
    if "ssrf" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "ssrf" in blob or "server-side request" in blob


def _cond_secret(f: Finding) -> bool:
    return f.finding_type == "secret" or "secret" in f.finding_type.lower()


def _cond_git_exposed(f: Finding) -> bool:
    if f.finding_type == "endpoint":
        if ".git" in f.url.lower() or ".git" in f.extra.get("path", "").lower():
            return True
    return ".git" in f.url.lower() or "git" in f.title.lower() and "exposed" in f.title.lower()


def _cond_open_redirect(f: Finding) -> bool:
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "redirect" in blob or "open_redirect" in blob


def _cond_xss(f: Finding) -> bool:
    if f.finding_type == "xss":
        return True
    return "xss" in f.finding_type.lower() or "cross-site scripting" in f.title.lower()


def _cond_admin_endpoint(f: Finding) -> bool:
    url = f.url.lower()
    blob = f"{f.title} {f.description}".lower()
    return ("admin" in url or "/wp-admin" in url or "/console" in url
            or "admin" in f.finding_type.lower() or "admin" in blob)


def _cond_graphql_introspection(f: Finding) -> bool:
    if "graphql" in f.finding_type and "introspect" in f.finding_type.lower():
        return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "introspect" in blob and "graphql" in blob


def _cond_api_route(f: Finding) -> bool:
    if f.finding_type == "api_route":
        return True
    url = f.url.lower()
    return "/api/" in url or "/api/v" in url or f.finding_type == "endpoint" and "/api" in url


def _cond_swagger(f: Finding) -> bool:
    if "swagger" in f.finding_type.lower():
        return True
    blob = f"{f.finding_type} {f.title} {f.url}".lower()
    return "swagger" in blob or "openapi" in blob or "/api-docs" in blob


def _cond_endpoint(f: Finding) -> bool:
    return f.finding_type == "endpoint"


def _cond_sqli(f: Finding) -> bool:
    if "sqli" in f.finding_type.lower() or "sql" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "sqli" in blob or "sql injection" in blob or "parameter_sqli" in f.finding_type.lower()


def _cond_admin_panel(f: Finding) -> bool:
    if f.finding_type == "endpoint":
        url = f.url.lower()
        if "admin" in url or "dashboard" in url or "panel" in url:
            return True
    blob = f"{f.title} {f.description}".lower()
    return "admin panel" in blob or "admin dashboard" in blob


def _cond_login_page(f: Finding) -> bool:
    url = f.url.lower()
    blob = f"{f.finding_type} {f.title}".lower()
    return "login" in url or "/signin" in url or "/auth" in url or "login" in blob


def _cond_csrf_weak(f: Finding) -> bool:
    if "csrf" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "csrf" in blob


def _cond_cors_misconfig(f: Finding) -> bool:
    if f.finding_type == "cors":
        return True
    blob = f"{f.title} {f.description}".lower()
    return "cors" in blob and ("misconfig" in blob or "wildcard" in blob or "reflect" in blob)


def _cond_auth_cookie(f: Finding) -> bool:
    blob = f"{f.finding_type} {f.title} {f.description} {f.evidence}".lower()
    if "cookie" in blob and ("auth" in blob or "session" in blob or "jwt" in blob):
        return True
    return "set-cookie" in f.evidence.lower() and "httponly" in f.evidence.lower()


def _cond_jwt_exposed(f: Finding) -> bool:
    if f.finding_type == "secret" and "jwt" in f.title.lower():
        return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "jwt" in blob and ("exposed" in blob or "leaked" in blob or "weak" in blob)


def _cond_cloud_metadata(f: Finding) -> bool:
    blob = f"{f.finding_type} {f.title} {f.description} {f.url}".lower()
    return ("169.254.169.254" in blob or "metadata" in blob
            or "cloud_metadata" in f.finding_type.lower())


def _cond_subdomain_takeover(f: Finding) -> bool:
    if "subdomain" in f.finding_type.lower() and "takeover" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "subdomain" in blob and ("takeover" in blob or "dangling" in blob)


def _cond_backup_file(f: Finding) ->bool:
    if f.finding_type == "endpoint":
        url = f.url.lower()
        if any(ext in url for ext in (".bak", ".backup", ".old", ".orig", ".sql", ".dump", ".tar", ".zip")):
            return True
    blob = f"{f.finding_type} {f.title} {f.description} {f.url}".lower()
    return "backup" in blob or ".bak" in blob or ".sql" in blob


def _cond_source_map(f: Finding) -> bool:
    if "source_map" in f.finding_type.lower() or "sourcemap" in f.finding_type.lower():
        return True
    return ".map" in f.url.lower() and "source" in f.title.lower()


def _cond_weak_csp(f: Finding) -> bool:
    if "csp" in f.finding_type.lower() or "header" in f.finding_type.lower():
        blob = f"{f.title} {f.description} {f.evidence}".lower()
        if "csp" in blob or "content-security" in blob:
            return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "content-security" in blob or "weak csp" in blob or "missing csp" in blob


def _cond_missing_hsts(f: Finding) -> bool:
    if "hsts" in f.finding_type.lower() or "header" in f.finding_type.lower():
        blob = f"{f.title} {f.description}".lower()
        if "hsts" in blob or "strict-transport" in blob:
            return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "hsts" in blob or "strict-transport" in blob


def _cond_ssl_mitm(f: Finding) -> bool:
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return ("ssl" in blob or "tls" in blob or "mitm" in blob
            or "certificate" in blob or "mixed content" in blob)


def _cond_put_method(f: Finding) -> bool:
    if "method" in f.finding_type.lower() or "http_method" in f.finding_type.lower():
        blob = f"{f.title} {f.description}".lower()
        if "put" in blob:
            return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "put method" in blob or "put enabled" in blob or "allow: put" in blob


def _cond_trace_method(f: Finding) -> bool:
    if "method" in f.finding_type.lower() or "http_method" in f.finding_type.lower():
        blob = f"{f.title} {f.description}".lower()
        if "trace" in blob:
            return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "trace method" in blob or "trace enabled" in blob or "xst" in blob


def _cond_mass_assignment(f: Finding) -> bool:
    if "mass_assignment" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "mass assignment" in blob or "mass_assignment" in blob


def _cond_idor(f: Finding) -> bool:
    if "idor" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "idor" in blob or "insecure direct object" in blob or "bola" in blob


def _cond_param_reflection(f: Finding) -> bool:
    if "parameter_reflected" in f.finding_type.lower() or "reflection" in f.finding_type.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "reflected" in blob and "parameter" in blob


def _cond_old_tech(f: Finding) -> bool:
    if "tech" in f.finding_type.lower() or "version" in f.finding_type.lower():
        blob = f"{f.title} {f.description}".lower()
        if "outdated" in blob or "old" in blob or "deprecated" in blob or "eol" in blob:
            return True
    blob = f"{f.finding_type} {f.title} {f.description}".lower()
    return "outdated" in blob or "deprecated" in blob or "end of life" in blob or "eol" in blob


def _cond_known_cve(f: Finding) -> bool:
    if "cve" in f.finding_type.lower() or "cve" in f.title.lower():
        return True
    blob = f"{f.title} {f.description}".lower()
    return "cve-" in blob


def _cond_debug_mode(f: Finding) -> bool:
    if "debug" in f.finding_type.lower():
        return True
    blob = f"{f.finding_type} {f.title} {f.description} {f.url}".lower()
    return "debug" in blob or "stack trace" in blob or "actuator" in blob


# Registry of condition → matcher function.
_CONDITION_MATCHERS = {
    "ssrf": _cond_ssrf,
    "secret": _cond_secret,
    "git_exposed": _cond_git_exposed,
    "open_redirect": _cond_open_redirect,
    "xss": _cond_xss,
    "admin_endpoint": _cond_admin_endpoint,
    "graphql_introspection": _cond_graphql_introspection,
    "api_route": _cond_api_route,
    "swagger": _cond_swagger,
    "endpoint": _cond_endpoint,
    "sqli": _cond_sqli,
    "admin_panel": _cond_admin_panel,
    "login_page": _cond_login_page,
    "csrf_weak": _cond_csrf_weak,
    "cors_misconfig": _cond_cors_misconfig,
    "auth_cookie": _cond_auth_cookie,
    "jwt_exposed": _cond_jwt_exposed,
    "cloud_metadata": _cond_cloud_metadata,
    "subdomain_takeover": _cond_subdomain_takeover,
    "backup_file": _cond_backup_file,
    "source_map": _cond_source_map,
    "weak_csp": _cond_weak_csp,
    "missing_hsts": _cond_missing_hsts,
    "ssl_mitm": _cond_ssl_mitm,
    "put_method": _cond_put_method,
    "trace_method": _cond_trace_method,
    "mass_assignment": _cond_mass_assignment,
    "idor": _cond_idor,
    "param_reflection": _cond_param_reflection,
    "old_tech": _cond_old_tech,
    "known_cve": _cond_known_cve,
    "debug_mode": _cond_debug_mode,
}


def _match_condition(condition: str, f: Finding) -> bool:
    """Return True if finding `f` satisfies the named condition."""
    matcher = _CONDITION_MATCHERS.get(condition)
    if matcher is None:
        log.debug(f"Unknown correlation condition: {condition}")
        return False
    try:
        return bool(matcher(f))
    except Exception as e:  # never let a matcher crash the whole run
        log.debug(f"Matcher '{condition}' raised on finding {f.title!r}: {e}")
        return False


def enhanced_correlate(
    findings: list,
    chains: list,
    target: str,
) -> tuple[list, list]:
    """
    Apply the enhanced 25+ attack-chain pattern library to existing findings.

    Takes the findings and chains already produced by the basic correlate()
    pass (or any prior pass), applies every pattern in ATTACK_CHAINS, appends
    any newly detected chains, and tags the findings that participate in chains.

    Returns (updated_findings, updated_chains). The input findings list is
    mutated in place (matching the basic correlate() contract) and also
    returned for convenience; new chains are appended to the input chains list.
    """
    from collections import defaultdict

    # Group findings by asset so chains stay scoped to a single host.
    by_asset: dict = defaultdict(list)
    for f in findings:
        asset = getattr(f, "asset", None) or target
        by_asset[asset].append(f)

    # Track which findings already belong to a chain so we can tag them.
    chain_member_ids: set = set()
    for c in chains:
        for f in getattr(c, "findings", []) or []:
            chain_member_ids.add(id(f))

    new_chains: List[AttackChain] = []

    for asset, asset_findings in by_asset.items():
        # Pre-bucket findings by condition to avoid O(patterns * findings^2)
        # recomputation. A single finding can satisfy several conditions.
        cond_buckets: dict = defaultdict(list)
        for f in asset_findings:
            for cond_name in _CONDITION_MATCHERS:
                if _match_condition(cond_name, f):
                    cond_buckets[cond_name].append(f)

        for cond_a, cond_b, title, confidence, description in ATTACK_CHAINS:
            a_findings = cond_buckets.get(cond_a, [])
            b_findings = cond_buckets.get(cond_b, [])

            # Need at least one finding for each side. They must be distinct
            # findings so a single finding doesn't form a "chain" with itself.
            participants_a = list(a_findings)
            participants_b = [f for f in b_findings if id(f) not in {id(x) for x in participants_a}]
            # If cond_a and cond_b are the same, we still need two distinct findings.
            if cond_a == cond_b:
                if len(a_findings) < 2:
                    continue
                participants_a = a_findings[:1]
                participants_b = a_findings[1:2]
            elif not participants_a or not participants_b:
                continue

            # Avoid duplicate chains: skip if an existing chain (basic or
            # already-added enhanced) on this asset already has this title.
            if any(c.title == title for c in chains if asset in c.assets):
                continue
            if any(c.title == title for c in new_chains if asset in c.assets):
                continue

            chain_findings = participants_a + participants_b
            new_chains.append(AttackChain(
                title=title,
                assets=[asset],
                findings=chain_findings,
                confidence=float(confidence),
                description=description,
            ))
            for f in chain_findings:
                chain_member_ids.add(id(f))

    # Tag findings that participate in any chain (basic or enhanced).
    for f in findings:
        if id(f) in chain_member_ids:
            existing = f.extra.get("chains", [])
            if not isinstance(existing, list):
                existing = [existing] if existing else []
            f.extra["in_chain"] = True
        else:
            f.extra.setdefault("in_chain", False)

    chains.extend(new_chains)

    if new_chains:
        log.info(f"enhanced_correlate: detected {len(new_chains)} additional attack chain(s) "
                 f"across {len(findings)} finding(s) for {target}")

    return findings, chains
