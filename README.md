# BugForge

> A modular, dependency-light toolkit for bug bounty hunters and security researchers — recon, vulnerability helpers, scope validation, and professional report generation. Built to help you hunt responsibly and earn.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/bugforge/actions/workflows/ci.yml/badge.svg)](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/bugforge/actions)

## Why BugForge?

Most bug-bounty tooling is either a giant dependency tree or a pile of loose scripts. **BugForge** is a single, cohesive Python package with **zero third-party runtime dependencies** — it runs anywhere Python 3.10+ does, on any cloud shell or VM.

It focuses on the parts of the workflow where automation genuinely helps:

- **Recon** that respects your program's scope
- **Payload & detection helpers** for the most common, high-paying bug classes
- **Scope validation** so you never accidentally test out-of-bounds assets
- **Report generation** that produces triager-friendly Markdown with CVSS scores

## ⚖️ Ethics & Responsible Disclosure

BugForge is for **authorized testing only**. Always:

1. Read and follow the program's brief, rules, and out-of-scope list.
2. Verify every target is in scope *before* testing — use the `scope` module.
3. Do **not** run destructive tests, denial-of-service, or mass scanning against targets.
4. Do **not** exfiltrate, modify, or retain other users' data.
5. Report vulnerabilities through the program's official channel.

**You are responsible for your own actions.** The authors are not liable for misuse.

## Installation

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/bugforge.git
cd bugforge
pip install -e .
```

No external dependencies required. Optional: install `pytest` for the test suite.

## Quick Start

### Validate scope first — always
```bash
# brief.txt
in_scope:
  - "*.example.com"
  - "10.0.0.0/24"
out_of_scope:
  - "*.staging.example.com"

bugforge scope check --brief brief.txt --target https://app.example.com --target https://staging.example.com
```

### Recon
```bash
# Enumerate subdomains (passive, multiple sources), resolving to IPs
bugforge recon subdomains --domain example.com --resolve --scope brief.txt --out subs.txt

# Content/endpoint discovery
bugforge recon content --url https://example.com --status 200,301,403

# Technology fingerprinting + security-header audit
bugforge recon fingerprint --url https://example.com --audit
```

### Vulnerability helpers
```bash
# Generate a mutated XSS payload wordlist
bugforge vulns xss --generate --out xss-payloads.txt

# Build SSRF payloads for cloud metadata & filter bypasses
bugforge vulns ssrf --metadata --bypass --callback your.interactsh.io --out ssrf.txt

# Check for CORS misconfiguration
bugforge vulns cors --url https://api.example.com/data

# Scan a response file for leaked secrets
bugforge vulns secrets --file response.html --json

# Boolean/time-based SQLi detection
bugforge vulns sqli --url 'https://example.com/item?id=1' --param id --value 1 --time
```

### Reports
```bash
# Generate a triager-friendly XSS report
bugforge report xss --url 'https://example.com/search?q=test' --payload '<script>alert(1)</script>' --out reports/xss.md

# Compute a CVSS v3.1 score
bugforge report cvss --vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
```

## Modules

| Module | Description |
|---|---|
| `bugforge.scope` | Parse Bugcrowd/HackerOne-style briefs; validate targets are in scope before testing |
| `bugforge.recon.subdomains` | Passive subdomain enumeration (crt.sh, HackerTarget, RapidDNS, Wayback) |
| `bugforge.recon.content` | Concurrent content/endpoint discovery with built-in wordlist |
| `bugforge.recon.fingerprint` | Technology & security-header fingerprinting |
| `bugforge.vulns.xss` | XSS payload generation + mutation engine |
| `bugforge.vulns.ssrf` | SSRF payload generation (metadata, bypass, OOB callback) + response analysis |
| `bugforge.vulns.secrets` | Secret scanner with curated regex set (AWS, GCP, GitHub, Stripe, JWT, keys…) |
| `bugforge.vulns.idor` | IDOR/access-control checker comparing two auth contexts |
| `bugforge.vulns.cors` | CORS misconfiguration detection |
| `bugforge.vulns.sqli` | Error/boolean/time-based SQLi detection |
| `bugforge.reporting.cvss` | Self-contained CVSS v3.1 base-score calculator |
| `bugforge.reporting.report` | Markdown report builder with templates for common bug classes |

## Library usage

BugForge is a library first, CLI second:

```python
from bugforge.vulns.xss import XssPayloadGen
from bugforge.scope.validator import parse_brief
from bugforge.reporting.report import ReportBuilder

# Validate scope
scope = parse_brief("""
in_scope:
  - *.example.com
""")
assert scope.is_in_scope("https://api.example.com/")[0] is True

# Generate payloads
payloads = XssPayloadGen().generate(mutate=True)
print(f"{len(payloads)} payloads ready")

# Build a report
report = ReportBuilder(ReportBuilder.ssrf_template(
    "https://api.example.com/fetch?url=http://evil",
    "http://169.254.169.254/latest/meta-data/")).build()
```

## Testing

```bash
pip install pytest
pytest -q
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome — especially new payload sets, detection signatures, and report templates.

## License

[MIT](LICENSE) — use it, fork it, build your reputation on it.

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Always obtain explicit authorization before testing any system, and adhere to the rules of engagement defined by the target program.
