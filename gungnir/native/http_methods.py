"""
HTTP method tester — probes a target for allowed HTTP methods and tests
dangerous ones (PUT write, DELETE remove, TRACE reflection, PROPFIND WebDAV).

No external tool dependency — pure Python (urllib only).
"""
from __future__ import annotations
import ssl
import urllib.request
import urllib.error
from typing import List, Optional
from ..utils.logger import get_logger

log = get_logger()

# All methods to probe.
ALL_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
    "PROPFIND", "MKCOL",
]

# Methods considered dangerous if allowed.
DANGEROUS_METHODS = {
    "PUT": "allows writing resources",
    "DELETE": "allows removing resources",
    "TRACE": "enables Cross-Site Tracing (XST)",
    "CONNECT": "allows proxying (potential SSRF/tunneling)",
    "MKCOL": "allows creating WebDAV collections",
    "PROPFIND": "exposes WebDAV metadata",
}

# Marker text used to test PUT uploads safely.
PUT_MARKER = "gungnir-method-test"


def test_methods(url: str) -> List[dict]:
    """
    Test which HTTP methods are accepted by `url` and probe dangerous ones.

    Returns a list of finding dicts.
    """
    findings: List[dict] = []
    url = _normalize(url)

    # 1. Detect allowed methods via OPTIONS / Allow header.
    allowed = _detect_allowed_methods(url)
    if allowed:
        findings.append({
            "type": "http_method",
            "severity": "info",
            "description": (
                f"Server advertises allowed methods: {', '.join(sorted(allowed))}"
            ),
            "url": url,
            "source": "http_methods",
            "methods": sorted(allowed),
            "indicator": "options_allow_header",
        })
        for method in allowed:
            if method in DANGEROUS_METHODS:
                findings.append({
                    "type": "http_method",
                    "severity": "high",
                    "description": (
                        f"Dangerous method {method} is allowed — "
                        f"{DANGEROUS_METHODS[method]}"
                    ),
                    "url": url,
                    "source": "http_methods",
                    "method": method,
                    "indicator": "dangerous_method_advertised",
                })

    # 2. Probe each method directly to see what actually responds (200/2xx or
    # 405 vs. 501 vs. other). Servers sometimes lie in OPTIONS/Allow.
    responded = []
    for method in ALL_METHODS:
        status = _probe_method(url, method)
        if status and 200 <= status < 500 and status not in (405,):
            responded.append((method, status))
    for method, status in responded:
        if method in DANGEROUS_METHODS:
            findings.append({
                "type": "http_method",
                "severity": "high",
                "description": (
                    f"Dangerous method {method} returned status {status} — "
                    f"{DANGEROUS_METHODS[method]}"
                ),
                "url": url,
                "source": "http_methods",
                "method": method,
                "status": status,
                "indicator": "dangerous_method_responds",
            })

    # 3. Active tests -----------------------------------------------------
    _test_put_write(url, findings)
    _test_delete(url, findings)
    _test_trace(url, findings)
    _test_propfind(url, findings)

    return findings


# ---------------------------------------------------------------------------
# Active tests
# ---------------------------------------------------------------------------

def _test_put_write(url: str, findings: List[dict]) -> None:
    """Attempt a PUT upload with a benign marker file."""
    test_url = url.rstrip("/") + "/gungnir_test_put.txt"
    body = PUT_MARKER.encode()
    status, resp_headers = _send(test_url, "PUT", data=body)
    if status in (200, 201, 204):
        # Confirm the file landed by reading it back.
        read_status, read_body = _read(test_url)
        if read_status == 200 and PUT_MARKER in (read_body or ""):
            findings.append({
                "type": "http_method",
                "severity": "critical",
                "description": (
                    "PUT method enabled and writable — uploaded file is "
                    "retrievable (server allows arbitrary file writes)"
                ),
                "url": test_url,
                "source": "http_methods",
                "method": "PUT",
                "status": status,
                "indicator": "put_writable_confirmed",
            })
            # Clean up our test file.
            _send(test_url, "DELETE")
        else:
            findings.append({
                "type": "http_method",
                "severity": "medium",
                "description": (
                    f"PUT returned success status {status} but uploaded file "
                    "was not retrievable — investigate write access"
                ),
                "url": test_url,
                "source": "http_methods",
                "method": "PUT",
                "status": status,
                "indicator": "put_success_no_confirm",
            })


def _test_delete(url: str, findings: List[dict]) -> None:
    """Attempt a DELETE against a non-existent path; 2xx is suspicious."""
    test_url = url.rstrip("/") + "/gungnir_nonexistent_file"
    status, _ = _send(test_url, "DELETE")
    if status in (200, 202, 204):
        findings.append({
            "type": "http_method",
            "severity": "high",
            "description": (
                f"DELETE returned success status {status} for a non-existent "
                "resource — server may allow arbitrary deletes"
            ),
            "url": test_url,
            "source": "http_methods",
            "method": "DELETE",
            "status": status,
            "indicator": "delete_succeeds",
        })


def _test_trace(url: str, findings: List[dict]) -> None:
    """TRACE should reflect the request — if so, XST is possible."""
    marker_header = "X-Gungnir-Trace-Marker: present\r\n"
    status, body, resp_headers = _send_raw_trace(url, marker_header)
    if status == 200 and body and "x-gungnir-trace-marker" in body.lower():
        findings.append({
            "type": "http_method",
            "severity": "high",
            "description": (
                "TRACE method is enabled and reflects request headers — "
                "Cross-Site Tracing (XST) may be exploitable to steal "
                "HttpOnly cookies"
            ),
            "url": url,
            "source": "http_methods",
            "method": "TRACE",
            "status": status,
            "indicator": "trace_reflection_confirmed",
        })
    elif status and status < 500 and status != 405:
        findings.append({
            "type": "http_method",
            "severity": "low",
            "description": (
                f"TRACE method returned status {status} — verify whether "
                "reflection is possible"
            ),
            "url": url,
            "source": "http_methods",
            "method": "TRACE",
            "status": status,
            "indicator": "trace_responds",
        })


def _test_propfind(url: str, findings: List[dict]) -> None:
    """PROPFIND may expose WebDAV directory listings / metadata."""
    status, body = _send_propfind(url)
    if status in (207, 200) and body:
        findings.append({
            "type": "http_method",
            "severity": "medium",
            "description": (
                "PROPFIND method is enabled and returns WebDAV metadata — "
                "directory structure may be exposed"
            ),
            "url": url,
            "source": "http_methods",
            "method": "PROPFIND",
            "status": status,
            "indicator": "propfind_metadata_exposed",
        })
    elif status == 207:
        findings.append({
            "type": "http_method",
            "severity": "low",
            "description": (
                "PROPFIND returns 207 (Multi-Status) — WebDAV is enabled, "
                "investigate"
            ),
            "url": url,
            "source": "http_methods",
            "method": "PROPFIND",
            "status": status,
            "indicator": "webdav_enabled",
        })


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _detect_allowed_methods(url: str) -> List[str]:
    """Use OPTIONS to read the Allow header; fall back to empty list."""
    status, resp_headers = _send(url, "OPTIONS")
    allow = None
    if resp_headers:
        for k, v in resp_headers.items():
            if k.lower() == "allow":
                allow = v
                break
    if not allow:
        return []
    return [m.strip().upper() for m in allow.split(",") if m.strip()]


def _probe_method(url: str, method: str) -> Optional[int]:
    """Return the status code for a single method probe."""
    status, _ = _send(url, method)
    return status


def _send(url: str, method: str, data: Optional[bytes] = None,
          extra_headers: Optional[dict] = None, timeout: int = 10):
    """Send a request and return (status, headers_dict)."""
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "Chrome/120.0 Safari/537.36",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        hdrs = dict(e.headers.items()) if e.headers else {}
        return e.code, hdrs
    except Exception:
        return None, None


def _read(url: str, timeout: int = 10):
    """GET a URL, return (status, body_text)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "Chrome/120.0 Safari/537.36",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return None, ""


def _send_raw_trace(url: str, extra_raw_headers: str, timeout: int = 10):
    """
    Send a TRACE request via a raw socket so we can inject custom request
    headers (urllib.request.Request sanitizes some headers).

    Returns (status, body_text, headers_dict).
    """
    import socket
    import urllib.parse as up
    p = up.urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"

    request_line = (
        f"TRACE {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: gungnir/1.0\r\n"
        f"Connection: close\r\n"
        f"{extra_raw_headers}\r\n"
    ).encode()

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request_line)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        raw = b"".join(chunks).decode("utf-8", errors="replace")
        # Split status line / headers / body.
        status = None
        body = raw
        if "\r\n\r\n" in raw:
            head, _, body = raw.partition("\r\n\r\n")
            first_line = head.split("\r\n", 1)[0]
            try:
                status = int(first_line.split(" ")[1])
            except (IndexError, ValueError):
                status = None
        return status, body, {}
    except Exception as e:
        log.debug(f"http_methods: raw TRACE failed for {url}: {e}")
        return None, "", None


def _send_propfind(url: str, timeout: int = 10):
    """Send a PROPFIND with the required Depth header and XML body."""
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<propfind xmlns="DAV:">'
        '<prop><displayname/></prop>'
        '</propfind>'
    ).encode()
    status, _ = _send(url, "PROPFIND", data=body,
                      extra_headers={"Depth": "0",
                                      "Content-Type": "application/xml"})
    if status is None:
        return None, ""
    body_text = ""
    # Re-read the body via a second PROPFIND (urllib discards bodies on errors).
    try:
        req = urllib.request.Request(url, data=body, method="PROPFIND", headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "Chrome/120.0 Safari/537.36",
            "Depth": "0",
            "Content-Type": "application/xml",
        })
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body_text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception:
        pass
    return status, body_text


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target
