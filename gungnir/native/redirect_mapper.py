"""
Redirect chain mapper — follows a URL's redirect chain (up to 20 hops),
records every hop, and tests for open-redirect and redirect-based SSRF
vulnerabilities via injected redirect parameters.

No external tool dependency — pure Python (urllib only).
"""
from __future__ import annotations
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Optional, Tuple
from ..utils.logger import get_logger

log = get_logger()

MAX_HOPS = 20

# Parameter names commonly used to carry redirect targets.
REDIRECT_PARAMS = [
    "redirect", "redirectUrl", "redirect_url", "returnUrl", "return_url",
    "next", "url", "uri", "path", "dest", "destination", "go", "target",
    "rurl", "redir", "returnTo", "callback", "continue", "image",
    "img", "src", "source", "fetch", "proxy", "to", "from",
]

# Probe payloads for open-redirect / SSRF testing.
OPEN_REDIRECT_PAYLOADS = [
    ("external_url", "https://example.com/"),
    ("protocol_relative", "//example.com/"),
    ("data_uri", "data:text/html,<h1>redirect</h1>"),
    ("javascript_uri", "javascript:alert(1)"),
    ("crlf_injection", "https://example.com/\r\nX-Injected: yes"),
    ("ssrf_internal", "http://127.0.0.1:80/"),
    ("ssrf_metadata", "http://169.254.169.254/latest/meta-data/"),
    ("ssrf_localhost_name", "http://localhost/"),
    ("double_scheme", "https://example.com/?next=https://evil.com"),
]


def map_redirects(url: str) -> List[dict]:
    """
    Follow the redirect chain for `url` and test for open-redirect / SSRF.

    Returns a list of finding dicts. The first finding always describes the
    observed redirect chain; subsequent findings report vulnerabilities.
    """
    findings: List[dict] = []
    url = _normalize(url)

    # 1. Map the redirect chain for the base URL.
    chain, final_status = _follow_chain(url)
    if len(chain) > 1:
        findings.append({
            "type": "redirect_chain",
            "severity": "info",
            "description": (
                f"Redirect chain of {len(chain)} hops: "
                + " → ".join(chain)
            ),
            "url": url,
            "source": "redirect_mapper",
            "chain": chain,
            "final_status": final_status,
            "indicator": "redirect_chain_mapped",
        })
        # Flag suspicious external jumps mid-chain.
        base_host = urllib.parse.urlparse(url).hostname or ""
        for i, hop in enumerate(chain[1:], start=1):
            hop_host = urllib.parse.urlparse(hop).hostname or ""
            if hop_host and base_host and not _same_registrable(base_host, hop_host):
                findings.append({
                    "type": "redirect",
                    "severity": "medium",
                    "description": (
                        f"Redirect hop {i} crosses registrable domain: "
                        f"{chain[i-1]} → {hop}"
                    ),
                    "url": chain[i-1],
                    "source": "redirect_mapper",
                    "to": hop,
                    "indicator": "cross_domain_redirect",
                })
    else:
        findings.append({
            "type": "redirect_chain",
            "severity": "info",
            "description": "No redirects — single response",
            "url": url,
            "source": "redirect_mapper",
            "chain": chain,
            "final_status": final_status,
            "indicator": "no_redirect",
        })

    # 2. Test open-redirect / SSRF via injected parameters.
    #
    # We compare the redirect Location against the injected payload (not just
    # against "any external host") so we don't false-positive on a target that
    # already redirects for unrelated reasons. We also capture a baseline
    # redirect (with no injected value) and only flag params whose redirect
    # differs from that baseline.
    base_url = url.split("?")[0]
    existing_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))

    # Baseline: inject a benign, *same-origin* value into each candidate param
    # so we can distinguish "server redirects to a fixed URL regardless of
    # input" (not vulnerable) from "server redirects to whatever we put in
    # the param" (vulnerable).
    baseline_locations: dict = {}
    for param in REDIRECT_PARAMS:
        benign = _benign_sameorigin(url, param)
        _, loc, _ = _probe_redirect(
            _inject_param(base_url, existing_params, param, benign["value"]))
        baseline_locations[param] = loc or ""

    for param in REDIRECT_PARAMS:
        for payload_name, payload in OPEN_REDIRECT_PAYLOADS:
            injected = _inject_param(base_url, existing_params, param, payload)
            target_url, location, status = _probe_redirect(injected)
            if not location:
                continue
            # The redirect must reflect OUR payload to count — otherwise the
            # server is just redirecting to a fixed target regardless of input.
            if not _reflects_payload(location, payload, baseline_locations.get(param)):
                continue
            if _is_external_redirect(location, url):
                sev = "high"
                if payload_name == "ssrf_internal" or "ssrf" in payload_name:
                    sev = "critical"
                findings.append({
                    "type": "redirect",
                    "severity": sev,
                    "description": (
                        f"Open redirect via '{param}' param with "
                        f"{payload_name} payload — redirects to {location}"
                    ),
                    "url": target_url,
                    "source": "redirect_mapper",
                    "parameter": param,
                    "payload": payload,
                    "payload_type": payload_name,
                    "location": location,
                    "status": status,
                    "indicator": "open_redirect_confirmed"
                    if "ssrf" not in payload_name else "ssrf_via_redirect",
                })

    return findings


# ---------------------------------------------------------------------------
# Chain following
# ---------------------------------------------------------------------------

def _follow_chain(url: str) -> Tuple[List[str], Optional[int]]:
    """
    Manually follow redirects up to MAX_HOPS, recording each URL.
    Returns (chain, final_status).
    """
    chain: List[str] = [url]
    current = url
    status: Optional[int] = None
    for _ in range(MAX_HOPS):
        status, location = _fetch_status_and_location(current)
        if not location:
            break
        next_url = _resolve_redirect(current, location)
        if next_url in chain:
            # Redirect loop detected.
            chain.append(next_url)
            break
        chain.append(next_url)
        current = next_url
    return chain, status


def _fetch_status_and_location(url: str, timeout: int = 10):
    """Fetch a URL without following redirects; return (status, location)."""
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "Chrome/120.0 Safari/537.36",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Use a no-redirect opener so we can inspect 3xx manually.
        opener = urllib.request.build_opener(NoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx))
        try:
            with opener.open(req, timeout=timeout) as resp:
                location = resp.headers.get("Location") or resp.headers.get("location")
                return resp.status, location
        except urllib.error.HTTPError as e:
            location = None
            if e.headers:
                location = e.headers.get("Location") or e.headers.get("location")
            return e.code, location
    except Exception:
        return None, None


def _probe_redirect(url: str, timeout: int = 10):
    """Probe an injected URL; return (url, location_header, status)."""
    status, location = _fetch_status_and_location(url, timeout)
    return url, location, status


# ---------------------------------------------------------------------------
# Open-redirect analysis helpers
# ---------------------------------------------------------------------------

def _inject_param(base_url: str, existing: dict, param: str, value: str) -> str:
    params = dict(existing)
    params[param] = value
    qs = urllib.parse.urlencode(params)
    return f"{base_url}?{qs}"


def _benign_sameorigin(url: str, param: str) -> dict:
    """Build a benign, same-origin value to use as the baseline for `param`.

    We use a unique path on the target's own host so that a redirect to it is
    clearly 'reflecting whatever we put here' rather than a server default.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    port = parsed.port
    netloc = host
    if port and not ((scheme == "https" and port == 443) or
                     (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    value = f"{scheme}://{netloc}/gungnir_baseline_{param}"
    return {"value": value, "host": netloc}


def _reflects_payload(location: str, payload: str, baseline: str) -> bool:
    """Decide whether `location` actually reflects the injected `payload`.

    We accept any of:
      - the location's host equals the payload's host (for http(s) payloads)
      - the location literally contains the payload string
      - for scheme-only payloads (javascript:, data:), the location starts
        with the payload scheme.
    A redirect that matches the baseline (i.e. the server redirects to a
    fixed target regardless of input) is treated as NOT reflecting.
    """
    if not location:
        return False
    loc_low = location.lower()

    # Same as baseline => server ignores the param value; not our redirect.
    if baseline and _normalize_loc(location) == _normalize_loc(baseline):
        return False

    payload_low = payload.lower()

    # Scheme-only payloads.
    for scheme in ("javascript:", "data:", "vbscript:"):
        if payload_low.startswith(scheme) and loc_low.startswith(scheme):
            return True

    # Literal containment (catches CRLF / path-rewrite cases).
    if payload in location:
        return True

    # Host comparison for http(s) and protocol-relative payloads.
    payload_for_parse = payload
    if payload.startswith("//"):
        payload_for_parse = "http:" + payload
    loc_for_parse = location if location.startswith(("http://", "https://")) \
        else ("http:" + location if location.startswith("//") else location)
    try:
        p_host = urllib.parse.urlparse(payload_for_parse).hostname or ""
        l_host = urllib.parse.urlparse(loc_for_parse).hostname or ""
    except Exception:
        return False
    if p_host and l_host and p_host.lower() == l_host.lower():
        return True
    return False


def _normalize_loc(loc: str) -> str:
    """Normalize a Location value for stable baseline comparison."""
    if not loc:
        return ""
    return loc.strip().lower().rstrip("/")


def _is_external_redirect(location: str, original_url: str) -> bool:
    """A redirect to a different host (or scheme) than the original is external."""
    if not location:
        return False
    # Scheme-only redirects (javascript:, data:) are always external/dangerous.
    if location.lower().startswith(("javascript:", "data:", "vbscript:")):
        return True
    # Protocol-relative URLs are external if the host differs.
    if location.startswith("//"):
        loc_host = urllib.parse.urlparse("http:" + location).hostname or ""
    else:
        loc_host = urllib.parse.urlparse(location).hostname or ""
    orig_host = urllib.parse.urlparse(original_url).hostname or ""
    if not loc_host:
        return False
    if not orig_host:
        return False
    return not _same_registrable(orig_host, loc_host)


def _same_registrable(host_a: str, host_b: str) -> bool:
    """Cheap registrable-domain check (last two labels)."""
    a = host_a.lower().split(".")[-2:]
    b = host_b.lower().split(".")[-2:]
    return a == b


def _resolve_redirect(base: str, location: str) -> str:
    if not location:
        return base
    if location.startswith(("http://", "https://")):
        return location
    if location.startswith("//"):
        scheme = urllib.parse.urlparse(base).scheme or "https"
        return f"{scheme}:{location}"
    parsed = urllib.parse.urlparse(base)
    if location.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    return urllib.parse.urljoin(base, location)


# ---------------------------------------------------------------------------
# No-redirect handler
# ---------------------------------------------------------------------------

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from auto-following 3xx so we can map the chain."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not follow — let the caller inspect the Location header.
        return None


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target
