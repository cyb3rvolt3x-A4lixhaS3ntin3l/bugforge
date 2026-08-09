"""
IDOR / Broken Access Control checker.

Helps test Insecure Direct Object Reference vulnerabilities by:
  - Taking a list of object IDs (numeric ranges, UUIDs, etc.)
  - Replaying authenticated requests while swapping the ID
  - Comparing responses across two authorization contexts to detect
    authorization failures (same body returned for a different user)

You supply the authenticated HttpClient(s). This module coordinates requests
and reports differences — it never authenticates for you.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from .secrets import SecretScanner

from ..utils.http import HttpClient


@dataclass
class IdorResult:
    object_id: str
    user_a_status: Optional[int]
    user_b_status: Optional[int]
    same_body: bool
    user_a_len: int
    user_b_len: int
    note: str = ""


def numeric_ids(start: int, end: int, step: int = 1) -> List[str]:
    """Generate a numeric ID range."""
    return [str(i) for i in range(start, end + 1, step)]


def uuid_ids(count: int) -> List[str]:
    """Generate random UUIDv4 strings for ID fuzzing."""
    import uuid
    return [str(uuid.uuid4()) for _ in range(count)]


class IdorChecker:
    """
    Replay a request template across object IDs and two auth contexts.

    Usage:
        checker = IdorChecker(client_user_a, client_user_b)
        results = checker.check(
            build_url=lambda oid: f"https://target/api/users/{oid}",
            object_ids=numeric_ids(1, 50),
        )
    """

    def __init__(self, client_a: HttpClient, client_b: Optional[HttpClient] = None,
                 secret_scanner: Optional[SecretScanner] = None):
        self.client_a = client_a
        # If no second client, we compare against unauthenticated access
        self.client_b = client_b or HttpClient()
        self.scanner = secret_scanner or SecretScanner()

    def check(self, build_url: Callable[[str], str], object_ids: List[str],
              method: str = "GET", max_ids: int = 0) -> List[IdorResult]:
        results: List[IdorResult] = []
        ids = object_ids[:max_ids] if max_ids else object_ids
        for oid in ids:
            url = build_url(oid)
            ra = self.client_a.request(method, url)
            rb = self.client_b.request(method, url)
            same = (ra.body == rb.body) and ra.status == rb.status and ra.status == 200
            note = ""
            if same:
                note = "same 200 response across auth contexts — possible IDOR"
            elif rb.status == 200 and ra.status == 200:
                # both 200 but different bodies — check for sensitive data leak in B
                if self.scanner.has_secret(rb.text):
                    note = "user_b 200 response contains leaked secret — investigate"
            elif rb.status == 200 and ra.status in (401, 403):
                note = "user_b got 200 while user_a got 401/403 — possible IDOR"
            results.append(IdorResult(oid, ra.status, rb.status, same,
                                       len(ra.body), len(rb.body), note))
        return results

    def filter_suspicious(self, results: List[IdorResult]) -> List[IdorResult]:
        """Return only results flagged as potentially vulnerable."""
        return [r for r in results if r.note]
