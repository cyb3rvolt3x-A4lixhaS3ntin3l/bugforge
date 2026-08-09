"""
Content & endpoint discovery.

Wordlist-based path discovery with concurrency, status filtering, and
interesting-status highlighting. Ships with a built-in wordlist; accepts an
external wordlist too.
"""
from __future__ import annotations
import concurrent.futures
from dataclasses import dataclass
from typing import List, Optional

from ..utils.http import HttpClient


# A small built-in wordlist so the tool is usable with zero setup.
BUILTIN_WORDLIST = [
    "admin", "login", "api", "config", "backup", "test", "debug", "dev",
    "staging", "old", "new", "tmp", "internal", "secret", "private",
    "dashboard", "panel", "console", "graphql", "rest", "v1", "v2",
    ".git/config", ".env", "robots.txt", "sitemap.xml", ".well-known/",
    "swagger.json", "swagger-ui", "api-docs", "health", "status",
    "webhook", "upload", "download", "files", "static", "assets",
    "user", "users", "account", "profile", "settings", "wp-admin",
    "phpinfo.php", "info.php", "server-status", "metrics", "actuator",
]


@dataclass
class ContentResult:
    url: str
    status: Optional[int]
    length: int
    location: Optional[str] = None


class ContentDiscovery:
    def __init__(self, client: Optional[HttpClient] = None, threads: int = 10):
        self.client = client or HttpClient()
        self.threads = threads

    def discover(self, base_url: str, wordlist: Optional[List[str]] = None,
                 extensions: Optional[List[str]] = None,
                 status_filter: Optional[List[int]] = None) -> List[ContentResult]:
        words = wordlist or BUILTIN_WORDLIST
        exts = extensions or [""]
        base = base_url.rstrip("/")
        urls = [f"{base}/{w.lstrip('/')}{e}" for w in words for e in exts]

        results: List[ContentResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._probe, u): u for u in urls}
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res is None:
                    continue
                if status_filter and res.status not in status_filter:
                    continue
                results.append(res)
        results.sort(key=lambda r: r.url)
        return results

    def interesting(self, results: List[ContentResult]) -> List[ContentResult]:
        """Return likely-interesting results (non-404, redirects, auth walls)."""
        interesting_codes = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}
        return [r for r in results if r.status in interesting_codes]

    def _probe(self, url: str) -> Optional[ContentResult]:
        r = self.client.get(url, headers={"Accept": "*/*"})
        if r.status is None and r.error:
            return None
        return ContentResult(url, r.status, len(r.body),
                              r.header("Location"))
