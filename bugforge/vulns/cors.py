"""
CORS misconfiguration checker.

Detects common CORS flaws:
  - Reflection of arbitrary Origin with ACAO (Access-Control-Allow-Origin) set
  - ACAO: null allowed (often exploitable via sandboxed iframes)
  - ACAC (Allow-Credentials) true with a wildcard or reflected origin
  - Wildcard with credentials (browser-blocked, but signals misconfig)

You supply the target URL; the checker probes with several Origins.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

from ..utils.http import HttpClient


PROBE_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "https://sub.target.evil.com",   # suffix match test
    "null",
    "https://target.com.evil.com",   # prefix confusion
]


@dataclass
class CorsResult:
    origin: str
    acao: Optional[str]
    acac: Optional[str]
    vulnerable: bool
    reason: str = ""


class CorsChecker:
    def __init__(self, client: Optional[HttpClient] = None):
        self.client = client or HttpClient()

    def check(self, url: str, origins: List[str] | None = None) -> List[CorsResult]:
        origins = origins or PROBE_ORIGINS
        results: List[CorsResult] = []
        for origin in origins:
            resp = self.client.get(url, headers={"Origin": origin})
            acao = resp.header("Access-Control-Allow-Origin")
            acac = resp.header("Access-Control-Allow-Credentials")
            vulnerable, reason = self._assess(origin, acao, acac)
            results.append(CorsResult(origin, acao, acac, vulnerable, reason))
        return results

    @staticmethod
    def _assess(origin: str, acao: Optional[str], acac: Optional[str]) -> tuple[bool, str]:
        if acao is None:
            return False, "no ACAO header returned"
        if acao == "*":
            if acac and acac.lower() == "true":
                return False, "wildcard + credentials (browser blocks; misconfig but unexploitable)"
            return False, "wildcard ACAO (credentials not allowed)"
        # Reflection of arbitrary origin
        if acao == origin and origin not in ("null",):
            if acac and acac.lower() == "true":
                return True, "arbitrary origin reflected with credentials — exploitable CORS"
            return True, "arbitrary origin reflected (no creds) — limited CORS issue"
        if acao == "null":
            if acac and acac.lower() == "true":
                return True, "null origin allowed with credentials — exploitable via sandbox iframe"
            return True, "null origin allowed — exploitable from sandboxed iframe"
        # Suffix/prefix confusion
        if origin == "null":
            return False, "null probe ignored"
        return False, f"ACAO '{acao}' does not reflect probe origin"
