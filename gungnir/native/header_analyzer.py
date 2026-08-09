"""
Security header analyzer — audits HTTP response headers for missing or
misconfigured security controls, and inspects cookie flags.
No external tool dependency — pure Python.
"""
from __future__ import annotations
import ssl
import urllib.request
import urllib.error
from typing import List
from ..utils.logger import get_logger

log = get_logger()

# Headers that should be present on any modern HTTPS site.
EXPECTED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Minimum acceptable HSTS max-age in seconds (1 year = 31536000).
MIN_HSTS_MAX_AGE = 31536000


def analyze_headers(url: str) -> List[dict]:
    """
    Fetch the response headers for `url` and audit them for missing or
    weak security controls. Also inspects Set-Cookie flags.

    Returns a list of finding dicts with the common shape:
      {"type": "security_header", "severity": "...", "description": "...",
       "url": "...", "source": "header_analyzer"}
    """
    findings: List[dict] = []
    url = _normalize(url)

    try:
        headers, status = _fetch_headers(url)
    except Exception as e:
        log.debug(f"header_analyzer: failed to fetch {url}: {e}")
        return findings

    if headers is None:
        # Connection-level failure (no response at all).
        findings.append({
            "type": "security_header",
            "severity": "info",
            "description": f"Unable to fetch headers from {url}",
            "url": url,
            "source": "header_analyzer",
        })
        return findings

    # Lower-cased header dict for case-insensitive lookups.
    norm = {k.lower(): v for k, v in headers.items()}

    # 1. Missing headers --------------------------------------------------
    present_lower = set(norm.keys())
    for header in EXPECTED_SECURITY_HEADERS:
        if header not in present_lower:
            findings.append({
                "type": "security_header",
                "severity": _severity_for_missing(header),
                "description": f"Missing security header: {header}",
                "url": url,
                "source": "header_analyzer",
                "header": header,
                "status": "missing",
            })

    # 2. HSTS analysis ----------------------------------------------------
    _check_hsts(norm, url, findings)

    # 3. CSP analysis ------------------------------------------------------
    _check_csp(norm, url, findings)

    # 4. X-Frame-Options analysis -----------------------------------------
    _check_x_frame_options(norm, url, findings)

    # 5. X-Content-Type-Options -------------------------------------------
    _check_x_content_type(norm, url, findings)

    # 6. Referrer-Policy --------------------------------------------------
    _check_referrer_policy(norm, url, findings)

    # 7. Permissions-Policy ----------------------------------------------
    _check_permissions_policy(norm, url, findings)

    # 8. Cookie security audit -------------------------------------------
    _check_cookies(headers, url, findings)

    return findings


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_hsts(norm: dict, url: str, findings: List[dict]) -> None:
    hsts = norm.get("strict-transport-security")
    if not hsts:
        return  # reported as missing above
    max_age = _parse_max_age(hsts)
    if max_age is not None and max_age < MIN_HSTS_MAX_AGE:
        findings.append({
            "type": "security_header",
            "severity": "medium",
            "description": (
                f"HSTS max-age is too short ({max_age}s < {MIN_HSTS_MAX_AGE}s "
                "recommended)"
            ),
            "url": url,
            "source": "header_analyzer",
            "header": "strict-transport-security",
            "value": hsts,
            "status": "weak",
        })
    if "preload" not in hsts.lower():
        findings.append({
            "type": "security_header",
            "severity": "low",
            "description": "HSTS header missing 'preload' directive",
            "url": url,
            "source": "header_analyzer",
            "header": "strict-transport-security",
            "status": "weak",
        })
    if "includesubdomains" not in hsts.lower():
        findings.append({
            "type": "security_header",
            "severity": "low",
            "description": "HSTS header missing 'includeSubDomains' directive",
            "url": url,
            "source": "header_analyzer",
            "header": "strict-transport-security",
            "status": "weak",
        })


def _check_csp(norm: dict, url: str, findings: List[dict]) -> None:
    csp = norm.get("content-security-policy")
    if not csp:
        return  # reported as missing above
    csp_low = csp.lower()
    issues = []
    if "unsafe-inline" in csp_low:
        issues.append("'unsafe-inline' allows inline scripts/styles")
    if "unsafe-eval" in csp_low:
        issues.append("'unsafe-eval' allows eval()")
    for directive in ("script-src", "style-src", "default-src", "img-src"):
        # crude: look for '* <host>' sources in the directive
        if f"{directive} *" in csp_low or f"{directive} *;" in csp_low:
            issues.append(f"'*' wildcard in {directive} allows any source")
    # Also catch a bare "* " in default-src
    if "default-src *" in csp_low:
        issues.append("'*' wildcard in default-src allows any source")
    if "report-uri" not in csp_low and "report-to" not in csp_low:
        issues.append("no report-uri/report-to directive")
    for issue in issues:
        findings.append({
            "type": "security_header",
            "severity": "high" if "unsafe" in issue else "medium",
            "description": f"Weak Content-Security-Policy: {issue}",
            "url": url,
            "source": "header_analyzer",
            "header": "content-security-policy",
            "value": csp,
            "status": "weak",
        })


def _check_x_frame_options(norm: dict, url: str, findings: List[dict]) -> None:
    xfo = norm.get("x-frame-options")
    if not xfo:
        return  # reported as missing above
    xfo_low = xfo.lower().strip()
    if xfo_low.startswith("allow-from"):
        findings.append({
            "type": "security_header",
            "severity": "medium",
            "description": (
                "X-Frame-Options uses deprecated 'ALLOW-FROM' directive — "
                "use Content-Security-Policy frame-ancestors instead"
            ),
            "url": url,
            "source": "header_analyzer",
            "header": "x-frame-options",
            "value": xfo,
            "status": "weak",
        })


def _check_x_content_type(norm: dict, url: str, findings: List[dict]) -> None:
    xcto = norm.get("x-content-type-options")
    if not xcto:
        return  # reported as missing above
    if xcto.strip().lower() != "nosniff":
        findings.append({
            "type": "security_header",
            "severity": "medium",
            "description": (
                f"X-Content-Type-Options has unexpected value '{xcto}' — "
                "should be 'nosniff'"
            ),
            "url": url,
            "source": "header_analyzer",
            "header": "x-content-type-options",
            "value": xcto,
            "status": "weak",
        })


def _check_referrer_policy(norm: dict, url: str, findings: List[dict]) -> None:
    rp = norm.get("referrer-policy")
    if not rp:
        return  # reported as missing above
    rp_low = rp.strip().lower()
    weak_values = {"", "unsafe-url", "no-referrer-when-downgrade"}
    if rp_low in weak_values:
        findings.append({
            "type": "security_header",
            "severity": "medium",
            "description": (
                f"Weak Referrer-Policy '{rp}' leaks referrer to third parties"
            ),
            "url": url,
            "source": "header_analyzer",
            "header": "referrer-policy",
            "value": rp,
            "status": "weak",
        })


def _check_permissions_policy(norm: dict, url: str, findings: List[dict]) -> None:
    pp = norm.get("permissions-policy")
    if not pp:
        return  # reported as missing above
    # If permissions-policy is present but empty, that's a weak config.
    if not pp.strip():
        findings.append({
            "type": "security_header",
            "severity": "low",
            "description": "Permissions-Policy header is empty",
            "url": url,
            "source": "header_analyzer",
            "header": "permissions-policy",
            "status": "weak",
        })


def _check_cookies(raw_headers, url: str, findings: List[dict]) -> None:
    """Inspect Set-Cookie headers (which may be multiple)."""
    # urllib normalizes duplicate headers into a list for some accessors,
    # but http.client.HTTPMessage.get_all returns them all reliably.
    if hasattr(raw_headers, "get_all"):
        set_cookies = raw_headers.get_all("Set-Cookie") or []
    else:
        # Fall back to scanning the dict-like object.
        set_cookies = [v for k, v in raw_headers.items() if k.lower() == "set-cookie"]

    if not set_cookies:
        return

    for cookie in set_cookies:
        cookie_low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        missing = []
        if "secure" not in cookie_low:
            missing.append("Secure")
        if "httponly" not in cookie_low:
            missing.append("HttpOnly")
        # SameSite can be Strict, Lax, or None (with Secure). Missing is risky.
        if "samesite" not in cookie_low:
            missing.append("SameSite")
        if missing:
            findings.append({
                "type": "security_header",
                "severity": "high" if "Secure" in missing and url.lower().startswith("https") else "medium",
                "description": (
                    f"Cookie '{name}' missing security flags: {', '.join(missing)}"
                ),
                "url": url,
                "source": "header_analyzer",
                "header": "set-cookie",
                "cookie": name,
                "missing_flags": missing,
                "status": "weak",
            })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_for_missing(header: str) -> str:
    severities = {
        "strict-transport-security": "medium",
        "content-security-policy": "high",
        "x-frame-options": "medium",
        "x-content-type-options": "medium",
        "referrer-policy": "low",
        "permissions-policy": "low",
    }
    return severities.get(header, "low")


def _parse_max_age(hsts: str):
    """Extract the max-age value from an HSTS header."""
    import re
    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def _fetch_headers(url: str, timeout: int = 10):
    """Return (headers, status) for the URL. headers is an HTTPMessage-like obj."""
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "Chrome/120.0 Safari/537.36",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.headers, resp.status
    except urllib.error.HTTPError as e:
        # Even error responses carry headers worth auditing.
        if e.headers is not None:
            return e.headers, e.code
        raise


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target
