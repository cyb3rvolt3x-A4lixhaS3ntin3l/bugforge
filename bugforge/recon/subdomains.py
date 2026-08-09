"""
Subdomain enumeration (passive, no active bruteforce by default).

Sources (stdlib-only, no API keys required):
  - crt.sh (certificate transparency)
  - HackerTarget API
  - RapidDNS
  - Wayback Machine CDX (via web.archive.org)

Optionally resolve discovered hosts to live IPs. Respects scope via the
scope validator — only subdomains of an in-scope apex are returned when a
Scope is provided.
"""
from __future__ import annotations
import json
import re
import socket
from dataclasses import dataclass
from typing import List, Optional, Set

from ..utils.http import HttpClient
from ..scope.validator import Scope


@dataclass
class Subdomain:
    name: str
    source: str
    ip: Optional[str] = None


class SubdomainEnum:
    def __init__(self, client: Optional[HttpClient] = None, timeout: float = 15.0):
        self.client = client or HttpClient(timeout=timeout)

    def enumerate(self, domain: str, resolve: bool = False,
                  scope: Optional[Scope] = None) -> List[Subdomain]:
        domain = domain.lower().strip()
        results: List[Subdomain] = []
        seen: Set[str] = set()
        fetchers = [self._crt_sh, self._hackertarget, self._rapiddns, self._wayback]
        for fetch in fetchers:
            try:
                names = fetch(domain)
            except Exception:
                continue
            for n in names:
                n = n.lower().strip()
                if not n or n in seen:
                    continue
                if scope is not None and not scope.is_in_scope(f"https://{n}/")[0]:
                    continue
                ip = None
                if resolve:
                    ip = self._resolve(n)
                    if ip is None:
                        continue  # skip unresolvable when resolving
                seen.add(n)
                results.append(Subdomain(name=n, source=fetch.__name__, ip=ip))
        return results

    # ---- sources ----
    def _crt_sh(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = self.client.get(url)
        if not r.text:
            return []
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            return []
        out: List[str] = []
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lstrip("*.")
                if line and domain in line:
                    out.append(line)
        return out

    def _hackertarget(self, domain: str) -> List[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = self.client.get(url)
        if not r.text or "error" in r.text.lower() or "API count exceeded" in r.text:
            return []
        out: List[str] = []
        for line in r.text.splitlines():
            if "," in line:
                out.append(line.split(",")[0].strip())
        return out

    def _rapiddns(self, domain: str) -> List[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
        r = self.client.get(url)
        if not r.text:
            return []
        # crude: grab <a> text that looks like subdomains
        return re.findall(r"[a-zA-Z0-9_.-]+\." + re.escape(domain), r.text)

    def _wayback(self, domain: str) -> List[str]:
        url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
               f"&output=json&fl=original&collapse=urlkey&limit=10000")
        r = self.client.get(url)
        if not r.text:
            return []
        try:
            data = json.loads(r.text)
        except json.JSONDecodeError:
            return []
        out: List[str] = []
        for row in data[1:]:  # first row is the header
            if row:
                from urllib.parse import urlparse
                host = urlparse(row[0]).hostname
                if host:
                    out.append(host)
        return out

    @staticmethod
    def _resolve(host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None
