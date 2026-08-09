"""
Parameter miner — discovers hidden parameters on endpoints.
Tests common parameter names and checks for interesting responses.
No external tool dependency — pure Python.
"""
from __future__ import annotations
import re
import urllib.request
import urllib.parse
from typing import List
from ..utils.logger import get_logger

log = get_logger()

# High-value parameter names ranked by bug bounty potential
PARAM_NAMES = [
    # Injection-prone
    "id", "user", "userId", "uid", "account", "item", "file", "page",
    "query", "search", "q", "keyword", "name", "title", "description",
    # Redirect/SSRF-prone
    "url", "redirect", "redirectUrl", "redirect_url", "returnUrl", "return_url",
    "next", "callback", "continue", "dest", "destination", "go", "target",
    "rurl", "image", "img", "src", "source", "fetch", "proxy",
    # Debug/admin
    "debug", "test", "dev", "admin", "internal", "secret", "key",
    "token", "auth", "session", "csrf", "xss", "cmd", "exec", "command",
    "shell", "system", "path", "dir", "folder", "document", "root",
    # File operations
    "download", "upload", "filename", "filepath", "fileUrl", "file_url",
    # IDOR-prone
    "orderId", "order", "invoiceId", "invoice", "transactionId",
    "messageId", "message", "commentId", "comment", "postId", "post",
    "productId", "product", "customerId", "customer", "memberId",
    # Config
    "config", "settings", "options", "properties", "env", "environment",
]


def mine_parameters(url: str) -> List[dict]:
    """
    Test common parameter names against a URL.
    Detects reflection (XSS), error messages (SQLi), and response changes (IDOR).
    """
    findings = []
    base_url = url.split("?")[0]

    # Get baseline response
    baseline = _fetch_url(base_url)
    if not baseline:
        return findings

    baseline_len = len(baseline["body"])
    baseline_status = baseline["status"]

    for param in PARAM_NAMES:
        test_url = f"{base_url}?{param}=bugforge_test_123"
        result = _fetch_url(test_url)
        if not result:
            continue

        # Check for reflection (potential XSS)
        if "bugforge_test_123" in result["body"]:
            findings.append({
                "type": "parameter_reflected",
                "parameter": param,
                "url": base_url,
                "source": "param_miner",
                "note": "parameter value reflected in response — XSS candidate",
            })

        # Check for error messages (potential SQLi)
        if any(err in result["body"].lower() for err in [
            "sql", "syntax", "mysql", "postgresql", "oracle", "sqlite",
            "odbc", "jdbc", "error in your sql", "unclosed quotation",
        ]):
            findings.append({
                "type": "parameter_sqli_indicator",
                "parameter": param,
                "url": base_url,
                "source": "param_miner",
                "note": "parameter triggers SQL error — SQLi candidate",
            })

        # Check for response length change (potential IDOR)
        if result["status"] == 200 and abs(len(result["body"]) - baseline_len) > 100:
            findings.append({
                "type": "parameter_changes_response",
                "parameter": param,
                "url": base_url,
                "source": "param_miner",
                "note": f"parameter changes response by {abs(len(result['body']) - baseline_len)} bytes — investigate",
                "baseline_len": baseline_len,
                "response_len": len(result["body"]),
            })

        # Check for different status code
        if result["status"] != baseline_status and result["status"] in (200, 301, 302, 401, 403):
            findings.append({
                "type": "parameter_status_change",
                "parameter": param,
                "url": base_url,
                "source": "param_miner",
                "note": f"parameter changes status from {baseline_status} to {result['status']}",
            })

    return findings


def _fetch_url(url: str, timeout: int = 10) -> dict:
    """Fetch a URL and return status + body."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    })
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "body": body}
    except Exception:
        return {"status": 0, "body": ""}
