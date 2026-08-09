"""
JavaScript analyzer — downloads and analyzes JS files from a target.
Extracts API routes, parameters, secrets, and source maps.
No external tool dependency — pure Python.
"""
from __future__ import annotations
import re
import json
import urllib.request
import urllib.parse
from typing import List
from ..utils.logger import get_logger

log = get_logger()

# Patterns for extracting interesting things from JS
API_ROUTE_PATTERNS = [
    r'''["'`](/api/[a-zA-Z0-9/_\-{}]+)["'`]''',
    r'''["'`](/v[0-9]+/[a-zA-Z0-9/_\-{}]+)["'`]''',
    r'''fetch\(["'`]([^"'`]+)["'`]''',
    r'''axios\.[a-z]+\(["'`]([^"'`]+)["'`]''',
    r'''\$\.ajax\(\{[^}]*url:\s*["'`]([^"'`]+)["'`]''',
    r'''XMLHttpRequest[^}]*open\(["'`][^"'`]+["'`],\s*["'`]([^"'`]+)["'`]''',
]

PARAM_PATTERNS = [
    r'''["'`](\w+)=["'`]''',  # query params in strings
    r'''params:\s*\{([^}]+)\}''',  # params object
]

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "aws_key"),
    (r'ghp_' + r'[0-9A-Za-z]{36}', "github_token"),
    (r'AIza[0-9A-Za-z_\-]{35}', "google_api_key"),
    (r'sk_live_[0-9A-Za-z]{24,}', "stripe_key"),
    (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "jwt"),
    (r'["\'](?:api[_-]?key|secret|token|password)["\']\s*[:=]\s*["\']([^"\']{16,})["\']', "generic_secret"),
]


def analyze_js(target: str) -> List[dict]:
    """
    Download the target's HTML, find JS files, download and analyze them.
    Returns list of findings.
    """
    findings = []
    target = normalize_url(target)

    try:
        html = _fetch(target)
        if not html:
            return findings
    except Exception as e:
        log.debug(f"JS analyzer: failed to fetch {target}: {e}")
        return findings

    # Find JS file references in HTML
    js_urls = _extract_js_urls(html, target)
    findings.append({
        "type": "js_files_found",
        "count": len(js_urls),
        "urls": js_urls[:20],
        "source": "js_analyzer",
        "target": target,
    })

    # Download and analyze each JS file
    for js_url in js_urls[:15]:  # limit to 15 files
        try:
            js_content = _fetch(js_url)
            if not js_content:
                continue

            # Extract API routes
            routes = _extract_patterns(js_content, API_ROUTE_PATTERNS)
            for route in routes:
                findings.append({
                    "type": "api_route",
                    "route": route,
                    "source": "js_analyzer",
                    "file": js_url,
                    "target": target,
                })

            # Extract parameters
            params = _extract_patterns(js_content, PARAM_PATTERNS)
            for param in params:
                findings.append({
                    "type": "js_parameter",
                    "parameter": param,
                    "source": "js_analyzer",
                    "file": js_url,
                    "target": target,
                })

            # Extract secrets
            for pattern, secret_type in SECRET_PATTERNS:
                matches = re.findall(pattern, js_content)
                for m in (matches if isinstance(matches, list) else [matches]):
                    if m and len(str(m)) > 10:
                        findings.append({
                            "type": "secret",
                            "secret_type": secret_type,
                            "value": str(m)[:20] + "...",
                            "file": js_url,
                            "source": "js_analyzer",
                            "target": target,
                        })

            # Check for source maps
            if ".map" in js_content or "sourceMappingURL" in js_content:
                findings.append({
                    "type": "source_map_exposed",
                    "file": js_url,
                    "source": "js_analyzer",
                    "target": target,
                })

        except Exception as e:
            log.debug(f"JS analyzer: failed to analyze {js_url}: {e}")

    return findings


def _fetch(url: str, timeout: int = 15) -> str:
    """Fetch URL content."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _extract_js_urls(html: str, base_url: str) -> List[str]:
    """Extract JS file URLs from HTML."""
    urls = []
    # <script src="...">
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        urls.append(_resolve_url(src, base_url))
    # Also look for inline references to .js files
    for m in re.finditer(r'["\']([^"\']+\.js)["\']', html):
        src = m.group(1)
        if not src.startswith("http"):
            urls.append(_resolve_url(src, base_url))
    return list(set(urls))


def _resolve_url(src: str, base_url: str) -> str:
    """Resolve a relative URL against a base."""
    if src.startswith(("http://", "https://")):
        return src
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("/"):
        parsed = urllib.parse.urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{src}"
    return urllib.parse.urljoin(base_url, src)


def _extract_patterns(content: str, patterns: List[str]) -> List[str]:
    """Extract all matches from content using a list of regex patterns."""
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0] if m else ""
            if m and len(m) > 1 and m not in results:
                results.append(m)
    return results
