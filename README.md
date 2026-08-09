# BugForge

> **v2.0** — A bug bounty orchestration platform with a web UI that automatically runs the best open-source security tools for you. One click → full pipeline. Users install nothing individually.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0--alpha-orange.svg)]()

## What's New in v2.0

BugForge v2.0 is a **fundamental redesign**. Instead of reimplementing what industry-standard tools already do well, BugForge now **orchestrates them**:

| v1.0 | v2.0 |
|---|---|
| 20 hardcoded XSS payloads | Wraps **Dalfox** (DOM-aware, headless browser, 200+ payloads) |
| 45-word content wordlist | Wraps **ffuf** (200K+ wordlists, recursion, vhost) |
| 4 subdomain sources | Wraps **Subfinder** (30+ sources) + **Amass** + **assetfinder** |
| 25 secret regexes | Wraps **gitleaks** (700+ patterns) + **trufflehog** (API verification) |
| Basic SQLi length comparison | Wraps **sqlmap** (full exploitation framework) |
| Basic CORS check | Wraps **corsy** (15+ probe origins) |
| No vuln templates | Wraps **Nuclei** (5000+ community templates) |
| CLI only | **Web UI dashboard** with real-time WebSocket progress |
| Manual tool chaining | **Pipeline engine** — recon → probe → scan → vuln → report |

### The Key Innovation

**Users don't install Subfinder, ffuf, Nuclei, sqlmap, Dalfox, gitleaks individually.** BugForge's orchestrator engine:

1. Checks if a tool is installed
2. Auto-installs it if missing (`go install`, `pip install`, or system package)
3. Runs it with optimal flags
4. Parses JSON output into standardized results
5. Feeds results into the next pipeline stage
6. Streams progress to the web dashboard in real-time

## Quick Start

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/bugforge.git
cd bugforge
pip install -e .

# Launch the web UI
bugforge serve
# → opens http://localhost:8000
```

Then in the web UI:
1. Enter your target domain
2. Paste your Bugcrowd/HackerOne scope brief
3. Select which pipeline stages to run
4. Click **Run Pipeline**
5. Watch results stream in real-time

## CLI Usage (v2.0)

```bash
# List all tools and their install status
bugforge orchestrate tools

# Install a specific tool
bugforge orchestrate install subfinder

# Run a single tool
bugforge orchestrate run --tool subfinder --target example.com

# Run the full pipeline
bugforge orchestrate pipeline --target example.com --brief brief.txt

# Start the web server
bugforge serve --host 0.0.0.0 --port 8000
```

## Tool Arsenal

BugForge orchestrates 14 tools across 9 categories:

| Tool | Category | What it does | Install |
|---|---|---|---|
| **subfinder** | recon | Passive subdomain enum (30+ sources) | `go install` |
| **amass** | recon | Active + passive enum with permutations | `go install` |
| **assetfinder** | recon | Fast lightweight subdomain discovery | `go install` |
| **httpx** | fingerprint | HTTP probe — status, title, tech, headers | `go install` |
| **ffuf** | discovery | Content/endpoint fuzzer (200K+ wordlists) | `go install` |
| **nuclei** | vuln_scan | Template-based scanner (5000+ templates) | `go install` |
| **dalfox** | xss | DOM-aware XSS scanner with headless browser | `go install` |
| **sqlmap** | sqli | Full SQLi exploitation framework | `pip install` |
| **gitleaks** | secret | Git history scanner (700+ patterns) | `go install` |
| **trufflehog** | secret | Secret scanner with API verification | `go install` |
| **corsy** | cors | CORS misconfiguration scanner (15+ origins) | `go install` |
| **nmap** | ports | Port scanner + service fingerprinter | system |
| **bugforge-secrets** | secret | Native fallback (no deps) | builtin |
| **bugforge-cors** | cors | Native fallback (no deps) | builtin |

## Pipeline Stages

```
1. RECON         → subfinder/amass/assetfinder  (find subdomains)
2. PROBE         → httpx                          (find live hosts)
3. FINGERPRINT   → httpx                          (identify tech stack)
4. DISCOVERY     → ffuf                           (find hidden endpoints)
5. VULN_SCAN     → nuclei                         (5000+ vulnerability templates)
6. XSS           → dalfox                         (DOM-aware XSS testing)
7. SQLI          → sqlmap                         (SQL injection testing)
8. SECRET        → gitleaks/trufflehog            (leaked secret scanning)
9. CORS          → corsy                          (CORS misconfiguration)
```

Each stage feeds its output into the next. Results stream via WebSocket.

## Prerequisites

- **Python 3.10+**
- **Go 1.21+** (for auto-installing Go-based tools — most of them)
- On first run, BugForge auto-installs tools via `go install` / `pip install`

## API

BugForge v2.0 exposes a full REST + WebSocket API:

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web UI dashboard |
| `/api/tools` | GET | List all tools + install status |
| `/api/tools/{name}/install` | POST | Manually install a tool |
| `/api/pipeline/run` | POST | Start a pipeline (returns run_id) |
| `/api/pipeline/{id}` | GET | Get pipeline results |
| `/ws/pipeline/{id}` | WS | Real-time progress updates |
| `/api/scope/check` | POST | Validate target against scope |
| `/api/report` | POST | Generate Markdown report |
| `/api/health` | GET | Health check |

## ⚖️ Ethics & Responsible Disclosure

BugForge is for **authorized testing only**. Always:
1. Read and follow the program's brief and scope
2. Use the built-in scope validator before testing
3. Do not run destructive tests or denial-of-service
4. Report vulnerabilities through official channels

**You are responsible for your own actions.**

## v1.0 Features (Still Included)

All v1.0 modules remain available as CLI commands and library imports:
- `scope` — brief parsing & in-scope validation
- `recon` — native subdomain/content/fingerprint tools (fallback when external tools unavailable)
- `vulns` — XSS payload gen, SSRF helper, secret scanner, IDOR, CORS, SQLi helpers
- `reporting` — CVSS v3.1 calculator + Markdown report templates

## License

[MIT](LICENSE)

## Status

**v2.0.0-alpha** — the orchestration layer, pipeline engine, web UI, and API are functional. Tool integrations are defined and tested via the registry. Production hardening, Docker support, and more tool integrations are in progress.
