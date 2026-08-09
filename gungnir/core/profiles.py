"""
Tool profiles — Gungnir's modified, optimized configurations for each tool.
This is what makes Gungnir different from just running tools with defaults.

Each profile specifies:
  - Modified command-line flags (not defaults)
  - Custom resource files (templates, wordlists, payloads)
  - Output format
  - How to parse results into normalized findings
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
from enum import Enum


class Wave(int, Enum):
    DISCOVERY = 1
    DEEP_SCAN = 2


@dataclass
class ToolProfile:
    name: str
    wave: Wave
    binary: str
    description: str
    applies_to: List[str]  # target types this tool is relevant for
    command_builder: Callable[[str, Dict], List[str]]
    parser: Callable[[str], List[dict]]
    timeout: int = 300
    requires_web: bool = True  # only run on web assets


# ─── Profile implementations ───

def _subfinder_cmd(target, opts):
    return ["subfinder", "-d", target, "-silent", "-json", "-o", "-"]

def _subfinder_parse(stdout):
    import json
    out = []
    for line in stdout.strip().splitlines():
        try:
            d = json.loads(line)
            if d.get("host"):
                out.append({"type": "subdomain", "value": d["host"], "source": d.get("source", "subfinder")})
        except json.JSONDecodeError:
            continue
    return out

def _assetfinder_cmd(target, opts):
    return ["assetfinder", "--subs-only", target]

def _assetfinder_parse(stdout):
    return [{"type": "subdomain", "value": line.strip(), "source": "assetfinder"}
            for line in stdout.strip().splitlines() if line.strip()]

def _httpx_cmd(target, opts):
    input_file = opts.get("input_file", "")
    if input_file:
        return ["httpx", "-l", input_file, "-silent", "-json", "-title", "-tech-detect",
                "-status-code", "-follow-redirects", "-threads", "50"]
    return ["httpx", "-u", target, "-silent", "-json", "-title", "-tech-detect",
            "-status-code", "-follow-redirects"]

def _httpx_parse(stdout):
    import json
    out = []
    for line in stdout.strip().splitlines():
        try:
            d = json.loads(line)
            out.append({
                "type": "http_probe",
                "url": d.get("url", ""),
                "status": d.get("status_code", 0),
                "title": d.get("title", ""),
                "tech": d.get("tech", []),
                "webserver": d.get("webserver", ""),
                "content_length": d.get("content_length", 0),
            })
        except json.JSONDecodeError:
            continue
    return out

def _ffuf_cmd(target, opts):
    wordlist = opts.get("wordlist", "/dev/null")
    # Use built-in mini wordlist if no custom one
    return [
        "ffuf", "-u", f"{target.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403,405,500",
        "-ac", "-t", "40", "-json",
    ]

def _ffuf_parse(stdout):
    import json
    out = []
    for line in stdout.strip().splitlines():
        try:
            d = json.loads(line)
            if d.get("status"):
                inp = d.get("input", {}).get("FUZZ", "")
                out.append({
                    "type": "endpoint",
                    "url": d.get("url", ""),
                    "path": f"/{inp}",
                    "status": d.get("status", 0),
                    "length": d.get("length", 0),
                    "words": d.get("words", 0),
                })
        except json.JSONDecodeError:
            continue
    return out

def _nuclei_cmd(target, opts):
    template_dir = opts.get("templates", "")
    cmd = ["nuclei", "-u", target, "-json", "-silent",
           "-severity", "low,medium,high,critical",
           "-rate-limit", "150", "-nc"]
    if template_dir:
        cmd.extend(["-t", template_dir])
    return cmd

def _nuclei_parse(stdout):
    import json
    out = []
    for line in stdout.strip().splitlines():
        try:
            d = json.loads(line)
            if d.get("template-id"):
                out.append({
                    "type": "vulnerability",
                    "template": d.get("template-id", ""),
                    "name": d.get("info", {}).get("name", ""),
                    "severity": d.get("info", {}).get("severity", "info"),
                    "url": d.get("matched-at", d.get("host", "")),
                    "description": d.get("info", {}).get("description", "")[:500],
                    "references": d.get("info", {}).get("reference", []),
                    "curl": d.get("curl-command", ""),
                    "source": "nuclei",
                })
        except json.JSONDecodeError:
            continue
    return out

def _dalfox_cmd(target, opts):
    return ["dalfox", "url", target, "--silence", "--no-color",
            "--only-poc", "r", "--timeout", "10"]

def _dalfox_parse(stdout):
    out = []
    for line in stdout.strip().splitlines():
        if line.strip().startswith("http"):
            out.append({"type": "xss", "url": line.strip(), "source": "dalfox"})
    return out

def _gitleaks_cmd(target, opts):
    return ["gitleaks", "detect", "--source", target,
            "--report-format", "json", "--report-path", "-", "--no-banner"]

def _gitleaks_parse(stdout):
    import json
    try:
        data = json.loads(stdout) if stdout.strip() else []
        return [{"type": "secret", "rule": d.get("RuleID", ""),
                 "file": d.get("File", ""), "secret": d.get("Secret", "")[:20] + "...",
                 "line": d.get("StartLine", 0), "source": "gitleaks"} for d in data]
    except json.JSONDecodeError:
        return []

def _corsy_cmd(target, opts):
    return ["corsy", "-u", target]

def _corsy_parse(stdout):
    # Corsy outputs formatted text; parse for issues
    out = []
    for line in stdout.splitlines():
        if any(kw in line.lower() for kw in ["vulnerable", "misconfiguration", "acao", "credentials"]):
            out.append({"type": "cors", "detail": line.strip(), "source": "corsy"})
    return out

def _nmap_cmd(target, opts):
    ports = opts.get("ports", "1-1000")
    return ["nmap", "-sV", "-sC", "--open", "-p", ports, "-oX", "-", target]

def _nmap_parse(stdout):
    # Basic XML parse — just extract open ports and services
    import re
    out = []
    for m in re.finditer(r'<port\s+portid="(\d+)"\s+protocol="(\w+)">\s*<state\s+state="open"[^>]*/>\s*<service\s+name="([^"]*)"[^>]*/>', stdout):
        port, proto, service = m.groups()
        out.append({"type": "port", "port": int(port), "protocol": proto,
                    "service": service, "source": "nmap"})
    return out


# ─── Registry ───

PROFILES: Dict[str, ToolProfile] = {}

def register(profile: ToolProfile):
    PROFILES[profile.name] = profile
    return profile

# Wave 1 — Discovery
register(ToolProfile("subfinder", Wave.DISCOVERY, "subfinder",
    "Passive subdomain enumeration (30+ sources)",
    ["domain"], _subfinder_cmd, _subfinder_parse, timeout=120, requires_web=False))

register(ToolProfile("assetfinder", Wave.DISCOVERY, "assetfinder",
    "Fast passive subdomain discovery",
    ["domain"], _assetfinder_cmd, _assetfinder_parse, timeout=60, requires_web=False))

# Wave 2 — Deep Scan
register(ToolProfile("httpx", Wave.DEEP_SCAN, "httpx",
    "HTTP probe + tech fingerprint + title",
    ["domain", "ip", "url"], _httpx_cmd, _httpx_parse, timeout=120, requires_web=False))

register(ToolProfile("ffuf", Wave.DEEP_SCAN, "ffuf",
    "Content discovery with ranked wordlists",
    ["domain", "ip", "url"], _ffuf_cmd, _ffuf_parse, timeout=300))

register(ToolProfile("nuclei", Wave.DEEP_SCAN, "nuclei",
    "Vulnerability scanner (5000+ templates)",
    ["domain", "ip", "url"], _nuclei_cmd, _nuclei_parse, timeout=600))

register(ToolProfile("dalfox", Wave.DEEP_SCAN, "dalfox",
    "DOM-aware XSS scanner",
    ["domain", "ip", "url"], _dalfox_cmd, _dalfox_parse, timeout=300))

register(ToolProfile("gitleaks", Wave.DEEP_SCAN, "gitleaks",
    "Secret scanner (700+ patterns)",
    ["domain", "ip", "url"], _gitleaks_cmd, _gitleaks_parse, timeout=120, requires_web=False))

register(ToolProfile("corsy", Wave.DEEP_SCAN, "corsy",
    "CORS misconfiguration scanner",
    ["domain", "ip", "url"], _corsy_cmd, _corsy_parse, timeout=60))

register(ToolProfile("nmap", Wave.DEEP_SCAN, "nmap",
    "Port scanner + service detection",
    ["ip", "cidr"], _nmap_cmd, _nmap_parse, timeout=300, requires_web=False))


def get_wave_profiles(wave: Wave, target_type: str) -> List[ToolProfile]:
    """Get all profiles for a wave that apply to a target type."""
    return [p for p in PROFILES.values()
            if p.wave == wave and target_type in p.applies_to]

def get_profile(name: str) -> Optional[ToolProfile]:
    return PROFILES.get(name)
