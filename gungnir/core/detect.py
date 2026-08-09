"""
Target auto-detection — figures out what kind of target we're dealing with
and selects the right tool combinations.
"""
from __future__ import annotations
import ipaddress
import re
import socket
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    UNKNOWN = "unknown"


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_cidr(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def is_url(target: str) -> bool:
    return target.startswith(("http://", "https://"))

def is_domain(target: str) -> bool:
    """Check if target looks like a domain name."""
    if is_ip(target) or is_cidr(target) or is_url(target):
        return False
    # Domain regex: labels separated by dots, TLD must be alpha
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, target))

def resolves(target: str) -> bool:
    """Check if target resolves via DNS."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def detect_target_type(target: str) -> TargetType:
    """Auto-detect the type of target."""
    target = target.strip()

    if is_url(target):
        return TargetType.URL
    if is_ip(target):
        return TargetType.IP
    if is_cidr(target):
        return TargetType.CIDR
    if is_domain(target):
        return TargetType.DOMAIN
    if "/" in target and not is_url(target):
        # Could be a path on a domain
        parts = target.split("/")[0]
        if is_domain(parts) or is_ip(parts):
            return TargetType.URL
    if resolves(target):
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


def normalize_target(target: str, target_type: Optional[TargetType] = None) -> str:
    """Normalize a target to a clean form."""
    target = target.strip()
    if target_type is None:
        target_type = detect_target_type(target)

    if target_type == TargetType.URL and not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def get_domain_from_url(url: str) -> str:
    """Extract the domain from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def get_cidr_hosts(cidr: str) -> list[str]:
    """Expand a CIDR to a list of IP strings."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # Limit to /24 for safety
        if net.prefixlen < 24:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()][:256]
    except ValueError:
        return []
