"""
Thin HTTP client wrapper around urllib with a few bug-hunting niceties:
  - configurable timeout & retries
  - random User-Agent rotation
  - optional custom headers / proxies
  - returns response objects with .status, .headers, .body (bytes), .text

Keeps the dependency footprint tiny (stdlib only) so the toolkit runs anywhere.
"""
import random
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


@dataclass
class HttpResponse:
    url: str
    status: Optional[int]
    headers: Dict[str, str]
    body: bytes = b""
    error: Optional[str] = None
    elapsed: float = 0.0

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def header(self, name: str) -> Optional[str]:
        # case-insensitive header lookup
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


@dataclass
class HttpClient:
    timeout: float = 10.0
    retries: int = 1
    backoff: float = 0.5
    user_agent: Optional[str] = None  # None => rotate
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    verify_tls: bool = True

    def _build_request(self, url: str, method: str, data: Optional[bytes],
                       extra_headers: Dict[str, str]) -> urllib.request.Request:
        ua = self.user_agent or random.choice(USER_AGENTS)
        h = {"User-Agent": ua, "Accept": "*/*"}
        h.update(self.headers)
        h.update(extra_headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        return req

    def request(self, method: str, url: str, *, params: Optional[Dict[str, Any]] = None,
                 data: Optional[Any] = None, headers: Optional[Dict[str, str]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> HttpResponse:
        if params:
            qs = urllib.parse.urlencode(params)
            url = f"{url}{'&' if '?' in url else '?'}{qs}"

        body: Optional[bytes] = None
        extra = headers or {}
        if data is not None:
            body = data.encode() if isinstance(data, str) else data
        elif json_body is not None:
            import json
            body = json.dumps(json_body).encode()
            extra.setdefault("Content-Type", "application/json")

        req = self._build_request(url, method, body, extra)
        if self.proxy:
            req.set_proxy(self.proxy, "http")

        last_err: Optional[str] = None
        for attempt in range(self.retries + 1):
            start = time.time()
            try:
                import ssl
                ctx = ssl.create_default_context()
                if not self.verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    raw = resp.read()
                    hdrs = {k: v for k, v in resp.headers.items()}
                    return HttpResponse(url=url, status=resp.status, headers=hdrs,
                                         body=raw, elapsed=time.time() - start)
            except urllib.error.HTTPError as e:
                raw = e.read() if hasattr(e, "read") else b""
                hdrs = {k: v for k, v in (e.headers.items() if e.headers else [])}
                return HttpResponse(url=url, status=e.code, headers=hdrs, body=raw,
                                     elapsed=time.time() - start)
            except urllib.error.URLError as e:
                last_err = str(e.reason)
            except Exception as e:
                last_err = str(e)
            if attempt < self.retries:
                time.sleep(self.backoff * (attempt + 1))
        return HttpResponse(url=url, status=None, headers={}, error=last_err,
                            elapsed=0.0)

    def get(self, url: str, **kw) -> HttpResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> HttpResponse:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw) -> HttpResponse:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> HttpResponse:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw) -> HttpResponse:
        return self.request("HEAD", url, **kw)
