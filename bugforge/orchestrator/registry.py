"""
Tool registry — definitions for every tool BugForge can orchestrate.

Each ToolDefinition describes:
  - name, category, description
  - how to check if it's installed (binary name)
  - how to auto-install it (go install / pip / docker)
  - how to run it (command builder)
  - how to parse its output (JSON parser)

This is the single source of truth for what tools BugForge wraps.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
from enum import Enum


class ToolCategory(str, Enum):
    RECON = "recon"
    FINGERPRINT = "fingerprint"
    DISCOVERY = "discovery"
    VULN_SCAN = "vuln_scan"
    XSS = "xss"
    SQLI = "sqli"
    SECRET = "secret"
    CORS = "cors"
    PORTS = "ports"


class InstallMethod(str, Enum):
    GO = "go"
    PIP = "pip"
    DOCKER = "docker"
    BUILTIN = "builtin"   # part of BugForge itself
    SYSTEM = "system"     # system package (apt/brew)


@dataclass
class ToolDefinition:
    name: str
    category: ToolCategory
    description: str
    binary: str                            # command to check/run
    install_method: InstallMethod
    install_command: str                   # full install command
    github: str = ""                       # source repo
    run_builder: Optional[Callable] = None # function(target, opts) -> list[str]
    json_parser: Optional[Callable] = None # function(stdout) -> list[dict]
    enabled: bool = True
    timeout: int = 300                     # seconds
    notes: str = ""


# ---- Tool Definitions ----

TOOL_REGISTRY: Dict[str, ToolDefinition] = {}


def register(tool: ToolDefinition):
    TOOL_REGISTRY[tool.name] = tool
    return tool


# ============ RECON ============

# Subfinder (passive subdomain enumeration, 30+ sources)
register(ToolDefinition(
    name="subfinder",
    category=ToolCategory.RECON,
    description="Passive subdomain enumeration (30+ sources)",
    binary="subfinder",
    install_method=InstallMethod.GO,
    install_command="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    github="https://github.com/projectdiscovery/subfinder",
    timeout=120,
    run_builder=lambda t, o: ["subfinder", "-d", t, "-silent", "-json", "-o", "-"],
    json_parser=lambda s: [
        {"subdomain": d["host"], "source": d.get("source", "")}
        for line in s.strip().splitlines()
        for d in [__import__("json").loads(line)]
        if "host" in d
    ] if s.strip() else [],
    notes="Best-in-class passive subdomain enumeration. 30+ sources.",
))

# Amass (active + passive)
register(ToolDefinition(
    name="amass",
    category=ToolCategory.RECON,
    description="Active + passive subdomain enumeration with permutation",
    binary="amass",
    install_method=InstallMethod.GO,
    install_command="go install -v github.com/owasp-amass/amass/v4/...@master",
    github="https://github.com/owasp-amass/amass",
    timeout=300,
    run_builder=lambda t, o: ["amass", "enum", "-passive", "-d", t, "-json", "-"],
    json_parser=lambda s: [
        {"subdomain": __import__("json").loads(l).get("name", "")}
        for l in s.strip().splitlines()
        if __import__("json").loads(l).get("name")
    ] if s.strip() else [],
    notes="Active + passive enum with permutation generation.",
))

# Assetfinder (faster, fewer sources)
register(ToolDefinition(
    name="assetfinder",
    category=ToolCategory.RECON,
    description="Fast passive subdomain discovery"
,
    binary="assetfinder",
    install_method=InstallMethod.GO,
    install_command="go install github.com/tomnomnom/assetfinder@latest",
    github="https://github.com/tomnomnom/assetfinder",
    timeout=60,
    run_builder=lambda t, o: ["assetfinder", "--subs-only", t],
    json_parser=lambda s: [{"subdomain": l.strip()} for l in s.strip().splitlines() if l.strip()],
    notes="Fast, lightweight subdomain finder.",
))

# ============ FINGERPRINT / PROBE ============

register(ToolDefinition(
    name="httpx",
    category=ToolCategory.FINGERPRINT,
    description="HTTP probe — status, title, tech stack, security headers",
    binary="httpx",
    install_method=InstallMethod.GO,
    install_command="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    github="https://github.com/projectdiscovery/httpx",
    timeout=120,
    run_builder=lambda t, o: ["httpx", "-l", o.get("input_file", "/dev/stdin"),
                               "-silent", "-json", "-title", "-tech-detect",
                               "-status-code", "-follow-redirects"],
    json_parser=lambda s: [
        {
            "url": d.get("url", ""),
            "status": d.get("status_code", 0),
            "title": d.get("title", ""),
            "tech": d.get("tech", []),
            "content_length": d.get("content_length", 0),
            "webserver": d.get("webserver", ""),
        }
        for line in s.strip().splitlines()
        for d in [__import__("json").loads(line)]
    ] if s.strip() else [],
    notes="Probes hosts for live HTTP, title, tech stack, headers.",
))

# ============ CONTENT DISCOVERY ============

register(ToolDefinition(
    name="ffuf",
    category=ToolCategory.DISCOVERY,
    description="High-speed content/endpoint fuzzer (200K+ wordlists)",
    binary="ffuf",
    install_method=InstallMethod.GO,
    install_command="go install github.com/ffuf/ffuf/v2@latest",
    github="https://github.com/ffuf/ffuf",
    timeout=300,
    run_builder=lambda t, o: [
        "ffuf", "-u", f"{t}/FUZZ",
        "-w", o.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        "-mc", o.get("match_codes", "200,204,301,302,307,401,403,405,500"),
        "-ac",  # auto-calibrate (filter out custom 404 pages)
        "-t", str(o.get("threads", 40)),
        "-json",
    ],
    json_parser=lambda s: [
        {
            "url": d.get("url", ""),
            "status": d.get("status", 0),
            "length": d.get("length", 0),
            "words": d.get("words", 0),
            "input": d.get("input", {}).get("FUZZ", ""),
        }
        for line in s.strip().splitlines()
        for d in [__import__("json").loads(line)]
        if d.get("status")
    ] if s.strip() else [],
    notes="Industry-standard fuzzer. Supports 200K+ wordlists, recursion, vhost.",
))

# ============ VULNERABILITY SCANNING ============

register(ToolDefinition(
    name="nuclei",
    category=ToolCategory.VULN_SCAN,
    description="Template-based vulnerability scanner (5000+ templates)",
    binary="nuclei",
    install_method=InstallMethod.GO,
    install_command="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    github="https://github.com/projectdiscovery/nuclei",
    timeout=600,
    run_builder=lambda t, o: [
        "nuclei", "-u", t,
        "-json", "-silent",
        "-severity", o.get("severity", "low,medium,high,critical"),
        "-rate-limit", str(o.get("rate_limit", 150)),
    ],
    json_parser=lambda s: [
        {
            "template": d.get("template-id", ""),
            "name": d.get("info", {}).get("name", ""),
            "severity": d.get("info", {}).get("severity", ""),
            "url": d.get("matched-at", d.get("host", "")),
            "type": d.get("type", ""),
            "description": d.get("info", {}).get("description", ""),
            "reference": d.get("info", {}).get("reference", []),
            "curl": d.get("curl-command", ""),
        }
        for line in s.strip().splitlines()
        for d in [__import__("json").loads(line)]
        if d.get("template-id")
    ] if s.strip() else [],
    notes="5000+ community templates. Scans for CVEs, misconfig, exposures, etc.",
))

# ============ XSS ============

register(ToolDefinition(
    name="dalfox",
    category=ToolCategory.XSS,
    description="DOM-aware XSS scanner with headless browser testing",
    binary="dalfox",
    install_method=InstallMethod.GO,
    install_command="go install github.com/hahwul/dalfox/v2@latest",
    github="https://github.com/hahwul/dalfox",
    timeout=300,
    run_builder=lambda t, o: [
        "dalfox", "url", t,
        "--silence", "--no-color",
        "--only-poc", "r",  # report only reflected (confirmed) XSS
        "--timeout", str(o.get("timeout", 10)),
    ],
    json_parser=lambda s: [
        {"xss_url": line.strip(), "type": "reflected"}
        for line in s.strip().splitlines()
        if line.strip().startswith("http")
    ] if s.strip() else [],
    notes="DOM-aware XSS scanning with headless browser. 200+ payloads.",
))

# ============ SQL INJECTION ============

register(ToolDefinition(
    name="sqlmap",
    category=ToolCategory.SQLI,
    description="Full SQL injection detection + exploitation framework",
    binary="sqlmap",
    install_method=InstallMethod.PIP,
    install_command="pip install sqlmap",
    github="https://github.com/sqlmapproject/sqlmap",
    timeout=600,
    run_builder=lambda t, o: [
        "sqlmap", "-u", t,
        "--batch", "--random-agent",
        "--level", str(o.get("level", 3)),
        "--risk", str(o.get("risk", 2)),
        "--output-dir", o.get("output_dir", "/tmp/bugforge-sqlmap"),
        "--json",
    ] if t else [],
    json_parser=lambda s: [],  # sqlmap writes to files, not stdout JSON
    notes="Full SQLi exploitation: data extraction, OS commands, DB dumping.",
))

# ============ SECRET SCANNING ============

register(ToolDefinition(
    name="gitleaks",
    category=ToolCategory.SECRET,
    description="Git history secret scanner (700+ patterns with verification)",
    binary="gitleaks",
    install_method=InstallMethod.GO,
    install_command="go install github.com/gitleaks/gitleaks/v8@latest",
    github="https://github.com/gitleaks/gitleaks",
    timeout=120,
    run_builder=lambda t, o: [
        "gitleaks", "detect",
        "--source", t,
        "--report-format", "json",
        "--report-path", "-",  # stdout
        "--no-banner",
    ],
    json_parser=lambda s: __import__("json").loads(s) if s.strip() else [],
    notes="Scans git repos for 700+ secret types. Verifies against live APIs.",
))

# TruffleHog (alternative secret scanner)
register(ToolDefinition(
    name="trufflehog",
    category=ToolCategory.SECRET,
    description="Secret scanner with live API verification",
    binary="trufflehog",
    install_method=InstallMethod.GO,
    install_command="go install github.com/trufflesecurity/trufflehog/v3@latest",
    github="https://github.com/trufflesecurity/trufflehog",
    timeout=120,
    run_builder=lambda t, o: [
        "trufflehog", "filesystem", t,
        "--json",
    ],
    json_parser=lambda s: [
        __import__("json").loads(l)
        for l in s.strip().splitlines()
        if l.strip()
    ] if s.strip() else [],
    notes="Verifies secrets against live APIs. 700+ detectors.",
))

# ============ CORS ============

register(ToolDefinition(
    name="corsy",
    category=ToolCategory.CORS,
    description="CORS misconfiguration scanner (15+ probe origins)",
    binary="corsy",
    install_method=InstallMethod.GO,
    install_command="go install github.com/saeedddqbd/corsy@latest",
    github="https://github.com/saeedddqbd/corsy",
    timeout=60,
    run_builder=lambda t, o: ["corsy", "-u", t],
    json_parser=lambda s: [],  # corsy outputs formatted text
    notes="Tests 15+ CORS misconfigurations including null, wildcard, reflection.",
))

# ============ PORT SCANNING ============

register(ToolDefinition(
    name="nmap",
    category=ToolCategory.PORTS,
    description="Network port scanner and service fingerprinter",
    binary="nmap",
    install_method=InstallMethod.SYSTEM,
    install_command="apt-get install -y nmap || brew install nmap",
    github="https://github.com/nmap/nmap",
    timeout=300,
    run_builder=lambda t, o: [
        "nmap", "-sV", "-sC", "-oX", "-",  # XML to stdout
        "-p", o.get("ports", "1-1000"),
        "--open",
        t,
    ],
    json_parser=lambda s: [],  # XML parsing handled separately
    notes="Industry standard. Service detection, script scanning, OS detection.",
))

# ============ BUILTIN (BugForge native) ============

register(ToolDefinition(
    name="bugforge-secrets",
    category=ToolCategory.SECRET,
    description="BugForge native secret scanner (no external deps)",
    binary="python3",
    install_method=InstallMethod.BUILTIN,
    install_command="",
    github="",
    timeout=30,
    run_builder=lambda t, o: ["python3", "-m", "bugforge", "vulns", "secrets", "--file", t, "--json"],
    json_parser=lambda s: __import__("json").loads(s) if s.strip() else [],
    notes="Fallback secret scanner when gitleaks/trufflehog not available.",
))

register(ToolDefinition(
    name="bugforge-cors",
    category=ToolCategory.CORS,
    description="BugForge native CORS checker (no external deps)",
    binary="python3",
    install_method=InstallMethod.BUILTIN,
    install_command="",
    github="",
    timeout=30,
    run_builder=lambda t, o: ["python3", "-m", "bugforge", "vulns", "cors", "--url", t],
    json_parser=lambda s: [],
    notes="Fallback CORS checker when corsy not available.",
))


def get_tools_by_category(category: ToolCategory) -> List[ToolDefinition]:
    return [t for t in TOOL_REGISTRY.values() if t.category == category]

def get_tool(name: str) -> Optional[ToolDefinition]:
    return TOOL_REGISTRY.get(name)

def list_tools() -> List[ToolDefinition]:
    return list(TOOL_REGISTRY.values())
