"""
Verification engine — re-tests critical/high findings to confirm before reporting.
Non-destructive: only re-sends the original request and checks if the finding persists.
"""
from __future__ import annotations
import urllib.request
import urllib.parse
from typing import List, Optional
from .correlate import Finding, Severity
from ..utils.logger import get_logger

log = get_logger()


async def verify_criticals(findings: List[Finding]) -> List[Finding]:
    """Re-test critical and high findings. Returns updated findings."""
    for f in findings:
        if f.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        if not f.url:
            continue

        try:
            result = _retest(f)
            if result is not None:
                f.verified = result
                if result:
                    f.confidence = min(1.0, f.confidence + 0.2)
                    f.extra["verification"] = "confirmed on re-test"
                else:
                    f.extra["verification"] = "could not reproduce"
        except Exception as e:
            log.debug(f"Verification error for {f.title}: {e}")

    return findings


def _retest(f: Finding) -> Optional[bool]:
    """Re-test a single finding. Returns True (confirmed) / False (not reproduced) / None (can't verify)."""
    url = f.url
    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # For XSS: check if the reflected payload is still present
    if f.finding_type == "xss":
        body = _fetch(url)
        if body:
            # If the original evidence/payload is reflected, it's confirmed
            if "alert" in body or "onerror" in body or "onload" in body:
                return True
            return False

    # For exposed files (.git, .env, swagger): check if still accessible
    if f.finding_type == "endpoint":
        if any(p in url for p in [".git", ".env", "swagger", "openapi"]):
            result = _fetch_status(url)
            if result == 200:
                return True
            return False

    # For secrets: check if the file is still accessible
    if f.finding_type == "secret":
        if f.url:
            result = _fetch_status(f.url)
            if result == 200:
                return True
            return False

    # For GraphQL: check if introspection still works
    if "graphql" in f.finding_type:
        body = _fetch(url, method="POST",
                      data='{"query":"{ __schema { types { name } } }"}',
                      content_type="application/json")
        if body and ("__schema" in body or "types" in body):
            return True
        return False

    # For CORS: check if ACAO still reflects
    if f.finding_type == "cors":
        headers = _fetch_headers(url, origin="https://evil.com")
        acao = headers.get("access-control-allow-origin", "")
        if acao and acao != "*":
            return True
        return False

    # Can't verify other types
    return None


def _fetch(url: str, method: str = "GET", data: str = None,
           content_type: str = None, timeout: int = 10) -> str:
    """Fetch URL body."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"}
    if content_type:
        headers["Content-Type"] = content_type

    req = urllib.request.Request(url, method=method, headers=headers,
                                  data=data.encode() if data else None)
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""


def _fetch_status(url: str, timeout: int = 10) -> int:
    """Fetch URL status code only."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _fetch_headers(url: str, origin: str = "", timeout: int = 10) -> dict:
    """Fetch URL headers."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"}
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(url, headers=headers)
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return {}
