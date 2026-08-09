"""
Program-brief parser & in-scope target validator.

Bug bounty programs publish a *brief* listing in-scope and out-of-scope assets,
usually as wildcard domains (*.example.com), specific hosts, or IP ranges.
Testing anything outside scope violates the program rules (and the law).
This module parses a brief into structured scope rules and validates a target
URL/host against them before any tool touches it.

Brief format (simple, human-editable YAML-ish / JSON / plain list):

    in_scope:
      - "*.example.com"
      - "api.example.com"
      - "10.0.0.0/24"
    out_of_scope:
      - "*.staging.example.com"
      - "support.example.com"

Works with JSON, the YAML-like text above, or a plain newline list prefixed
with ``in_scope:`` / ``out_of_scope:`` sections.
"""
from __future__ import annotations
import fnmatch
import ipaddress
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ScopeRule:
    """A single scope rule (a wildcard host, a host, or an IP/CIDR)."""
    raw: str
    kind: str  # 'wildcard' | 'host' | 'ip' | 'cidr'
    network: Optional[ipaddress._BaseNetwork] = None
    pattern: str = ""


@dataclass
class Scope:
    in_scope: List[ScopeRule] = field(default_factory=list)
    out_of_scope: List[ScopeRule] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Validate ``target`` (URL or host or IP) against the scope."""
        host, port = _extract_host(target)
        if not host:
            return False, f"could not parse a host from {target!r}"

        # Out-of-scope takes precedence
        for rule in self.out_of_scope:
            if _matches(host, rule):
                return False, f"matches out-of-scope rule {rule.raw!r}"

        for rule in self.in_scope:
            if _matches(host, rule):
                return True, f"matches in-scope rule {rule.raw!r}"

        return False, "no in-scope rule matched"


def _extract_host(target: str) -> Tuple[Optional[str], Optional[int]]:
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname
        port = parsed.port
    else:
        host = target.split(":")[0]
        port = None
        # strip brackets from ipv6
        if host and host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
    return host, port


def _parse_rule(raw: str) -> ScopeRule:
    raw = raw.strip()
    # IP / CIDR
    try:
        net = ipaddress.ip_network(raw, strict=False)
        kind = "cidr" if "/" in raw else "ip"
        return ScopeRule(raw=raw, kind=kind, network=net)
    except ValueError:
        pass
    # Wildcard host
    if raw.startswith("*."):
        return ScopeRule(raw=raw, kind="wildcard", pattern=raw)
    if "*" in raw or "?" in raw:
        return ScopeRule(raw=raw, kind="wildcard", pattern=raw)
    # Plain host
    return ScopeRule(raw=raw, kind="host", pattern=raw)


def _matches(host: str, rule: ScopeRule) -> bool:
    if rule.kind in ("ip", "cidr"):
        try:
            ip = ipaddress.ip_address(host)
            return ip in rule.network
        except ValueError:
            return False
    if rule.kind == "wildcard":
        # *.example.com matches sub.example.com but not example.com
        pat = rule.pattern
        if pat.startswith("*."):
            base = pat[2:]
            return host == base or host.endswith("." + base)
        return fnmatch.fnmatch(host, pat)
    if rule.kind == "host":
        return host == rule.pattern
    return False


class ScopeValidator:
    """Convenience wrapper holding a Scope and validating many targets."""

    def __init__(self, scope: Scope):
        self.scope = scope

    def check(self, target: str) -> Tuple[bool, str]:
        return self.scope.is_in_scope(target)

    def check_many(self, targets: List[str]) -> List[Tuple[str, bool, str]]:
        return [(t, *self.scope.is_in_scope(t)) for t in targets]

    def filter_in_scope(self, targets: List[str]) -> List[str]:
        return [t for t in targets if self.scope.is_in_scope(t)[0]]


def _build_scope(in_list: List[str], out_list: List[str]) -> Scope:
    return Scope(
        in_scope=[_parse_rule(r) for r in in_list if r.strip()],
        out_of_scope=[_parse_rule(r) for r in out_list if r.strip()],
        raw={"in_scope": in_list, "out_of_scope": out_list},
    )


_SECTION_RE = re.compile(r"^(in_scope|out_of_scope)\\s*:\\s*$", re.IGNORECASE)


def parse_brief(text: str) -> Scope:
    """
    Parse a brief from text. Accepts:
      - JSON object with in_scope / out_of_scope keys
      - Sectioned plain text:
            in_scope:
              - *.example.com
              - api.example.com
            out_of_scope:
              - support.example.com
    """
    text = text.strip()
    if not text:
        return Scope()

    # JSON?
    if text.startswith("{"):
        try:
            data = json.loads(text)
            return _build_scope(data.get("in_scope", []), data.get("out_of_scope", []))
        except json.JSONDecodeError:
            pass

    # Sectioned plain text
    current = None
    in_list: List[str] = []
    out_list: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SECTION_RE.match(line)
        if m:
            current = m.group(1).lower()
            continue
        # strip leading "- " bullet
        item = re.sub(r"^-\\s*", "", line)
        if current == "in_scope":
            in_list.append(item)
        elif current == "out_of_scope":
            out_list.append(item)
    return _build_scope(in_list, out_list)


def load_brief_file(path: str) -> Scope:
    """Load and parse a brief from a file path."""
    with open(path, "r", encoding="utf-8") as f:
        return parse_brief(f.read())
