"""
Secret / sensitive-data scanner for HTTP response bodies.

Identifies accidentally leaked credentials, tokens, and keys in web responses
—a common bug-bounty finding (sensitive data exposure). Uses a curated set of
regexes with low false-positive tuning and returns structured matches.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass
class SecretMatch:
    type: str
    value: str
    start: int
    end: int
    line: int


# (type, regex). Patterns are intentionally specific to cut false positives.
SECRET_PATTERNS: List[tuple[str, str]] = [
    # AWS
    ("aws_access_key_id", r"A" + r"KIA[0-9A-Z]{16}"),
    ("aws_secret_key", r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ("aws_s3_bucket_url", r"https?://[a-z0-9.-]*\\.s3[a-z0-9.-]*\\.amazonaws\\.com"),
    # Google
    ("google_api_key", r"A" + r"Iza[0-9A-Za-z_\\-]{35}"),
    ("gcp_oauth", r"ya29\\.[0-9A-Za-z_\\-]+"),
    # GitHub
    ("github_token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("github_pat", r"github_pat_[0-9A-Za-z_]{22}_[0-9A-Za-z_]{59}"),
    ("github_oauth", r"gho_[0-9A-Za-z]{36}"),
    # Slack
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("slack_webhook", r"https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    # Stripe
    ("stripe_live_key", r"s" + r"k_live_[0-9A-Za-z]{24,}"),
    ("stripe_test_key", r"sk_test_[0-9A-Za-z]{24,}"),
    # Twilio
    ("twilio_sid", r"AC[a-z0-9]{32}"),
    # JWT
    ("jwt", r"eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+"),
    # Private keys
    ("private_key_rsa", r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) [A-Z ]*KEY-----"),
    # Database connection strings
    ("db_connection", r"(mongodb|postgres|postgresql|mysql|redis)://[^\\s'\"<>]+"),
    # Generic
    ("generic_api_key", r"(?i)api[_-]?key['\"\\s:=]+['\"][A-Za-z0-9_\\-]{20,}['\"]"),
    ("generic_secret", r"(?i)secret['\"\\s:=]+['\"][A-Za-z0-9_\\-]{16,}['\"]"),
    ("generic_password", r"(?i)(password|passwd|pwd)['\"\\s:=]+['\"][^'\"\\s]{6,}['\"]"),
    ("bearer_token", r"(?i)bearer\\s+[A-Za-z0-9_\\-\\.]+"),
    # Heroku / SendGrid / Mailgun
    ("heroku_api_key", r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("sendgrid_key", r"SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}"),
    ("mailgun_key", r"key-[0-9a-zA-Z]{32}"),
    # Firebase
    ("firebase_url", r"https?://[a-z0-9-]+\\.firebaseio\\.com"),
    # Square
    ("square_access_token", r"sq0atp-[0-9A-Za-z_\\-]{22}"),
    # Cloudflare
    ("cloudflare_api_key", r"v1\\.0-[0-9a-f]{24}"),
]

# Mask these generic types for noise reduction; require keyword nearby
_GENERIC_TYPES = {"generic_api_key", "generic_secret", "generic_password", "bearer_token"}


class SecretScanner:
    """Scan response bodies for leaked secrets."""

    def __init__(self, extra_patterns: List[tuple[str, str]] | None = None):
        self.patterns: List[tuple[str, Pattern]] = [
            (t, re.compile(p)) for t, p in SECRET_PATTERNS
        ]
        if extra_patterns:
            self.patterns.extend((t, re.compile(p)) for t, p in extra_patterns)

    def scan(self, body: str) -> List[SecretMatch]:
        """Scan ``body`` and return all matches."""
        matches: List[SecretMatch] = []
        if not body:
            return matches
        lines = body.splitlines()
        for t, pat in self.patterns:
            for m in pat.finditer(body):
                # generic-keyword heuristic: require the keyword match itself
                value = m.group(0)
                # suppress very short generic matches
                if t in _GENERIC_TYPES and len(value) < 20:
                    continue
                line_no = body[:m.start()].count("\n") + 1
                matches.append(SecretMatch(t, value, m.start(), m.end(), line_no))
        # sort by position
        matches.sort(key=lambda x: x.start)
        return matches

    def scan_file(self, path: str) -> List[SecretMatch]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.scan(f.read())

    def has_secret(self, body: str) -> bool:
        return bool(self.scan(body))
