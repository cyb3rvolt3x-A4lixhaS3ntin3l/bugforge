"""
Technology fingerprinting.

Infers the technology stack (framework, CMS, server, CDN, etc.) from HTTP
headers, cookies, and response-body markers. No external deps.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..utils.http import HttpClient


# Header/value -> technology
HEADER_SIGNS = [
    ("server", r"nginx", "Nginx"),
    ("server", r"apache", "Apache HTTP Server"),
    ("server", r"Microsoft-IIS", "Microsoft IIS"),
    ("server", r"cloudflare", "Cloudflare"),
    ("x-powered-by", r"Express", "Express.js"),
    ("x-powered-by", r"PHP", "PHP"),
    ("x-powered-by", r"ASP\\.NET", "ASP.NET"),
    ("x-powered-by", r"Next\\.js", "Next.js"),
    ("x-aspnet-version", r".+", "ASP.NET"),
    ("x-generator", r"Drupal", "Drupal"),
    ("x-generator", r"WordPress", "WordPress"),
    ("x-amz-cf-id", r".+", "AWS CloudFront"),
    ("x-served-by", r"cache-", "Fastly"),
    ("set-cookie", r"sessionid", "Django (sessionid)"),
    ("set-cookie", r"laravel_session", "Laravel"),
    ("set-cookie", r"connect\\.sid", "Express.js (connect.sid)"),
    ("set-cookie", r"wp-settings", "WordPress"),
    ("set-cookie", r"JSESSIONID", "Java Servlet"),
    ("set-cookie", r"ASP\\.NET_SessionId", "ASP.NET"),
]

# Body regex -> technology
BODY_SIGNS = [
    (r"<meta name=\"generator\" content=\"WordPress ([0-9.]+)", "WordPress"),
    (r"<meta name=\"generator\" content=\"Drupal ([0-9.]+)", "Drupal"),
    (r"wp-content/", "WordPress"),
    (r"__next_data__", "Next.js"),
    (r"data-reactroot", "React"),
    (r"ng-version=\"([0-9.]+)\"", "Angular"),
    (r"vue\\.js", "Vue.js"),
    (r"/static/django", "Django"),
    (r"laravel", "Laravel"),
    (r"<title>Index of /", "Apache directory listing"),
    (r"cdn\\.jsdelivr\\.net", "jsDelivr CDN"),
    (r"cloudflare", "Cloudflare"),
]


@dataclass
class TechMatch:
    technology: str
    evidence: str
    source: str  # 'header' | 'body' | 'cookie'


@dataclass
class FingerprintResult:
    url: str
    status: Optional[int]
    technologies: List[TechMatch] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


class TechFingerprinter:
    def __init__(self, client: Optional[HttpClient] = None):
        self.client = client or HttpClient()
        self._header_sigs = [(h, re.compile(p, re.I), t) for h, p, t in HEADER_SIGNS]
        self._body_sigs = [(re.compile(p, re.I), t) for p, t in BODY_SIGNS]

    def fingerprint(self, url: str) -> FingerprintResult:
        r = self.client.get(url)
        result = FingerprintResult(url=url, status=r.status, headers=r.headers)
        seen = set()

        for h, pat, tech in self._header_sigs:
            val = r.header(h)
            if val and pat.search(val):
                key = (tech, h)
                if key not in seen:
                    seen.add(key)
                    result.technologies.append(
                        TechMatch(tech, f"{h}: {val[:80]}", "header"))

        if r.text:
            for pat, tech in self._body_sigs:
                m = pat.search(r.text)
                if m:
                    key = (tech, "body")
                    if key not in seen:
                        seen.add(key)
                        result.technologies.append(
                            TechMatch(tech, f"body: {m.group(0)[:80]}", "body"))

        # security headers audit
        result.headers = r.headers
        return result

    def missing_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """Return security headers that are absent (quick audit)."""
        recommended = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        low = {k.lower() for k in headers}
        return [h for h in recommended if h.lower() not in low]
