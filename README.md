# GUNGNIR — Parallel Bug Bounty Intelligence Platform

<div align="center">

**GUNGNIR** — Odin's magical spear that never misses its target.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.0.0-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-134%20passing-green.svg)]()

**Created by [Syed Zada Abrar](https://andraxpentester.in)** — Certified Penetration Tester & Security Researcher

[🌐 andraxpentester.in](https://andraxpentester.in) · [🛡️ SentinelReign.com](https://sentinelreign.com) · [🐙 GitHub](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l) · [✉️ Contact](mailto:andraxpentester@gmail.com)

</div>

---

## What is GUNGNIR?

GUNGNIR is a parallel, intelligence-driven **bug bounty** and **penetration testing** platform that fires all security tools simultaneously, correlates findings into **attack chains**, verifies criticals, and presents prioritized, evidence-backed results.

It is designed for **bug bounty hunters**, **security researchers**, **penetration testers**, and **ethical hackers** who want to maximize their finding rate while minimizing false positives and scan time.

### Why GUNGNIR?

Most security tools run sequentially — one tool after another — producing raw output that you have to manually correlate. GUNGNIR changes this:

| Traditional Tools | GUNGNIR |
|---|---|
| Run one tool at a time | **14+ tools fire in parallel** |
| Raw scanner output dumped | **26 attack chain patterns** auto-correlated |
| Manual false positive filtering | **Rule-based FP filtering** built-in |
| No verification — trust the scanner | **Criticals re-tested** before reporting |
| No history — can't track changes | **SQLite persistence** with diffing |
| Fixed pipeline — can't customize | **YAML pipelines** with conditions |
| Need to install each tool separately | **Pre-compiled binaries** auto-downloaded |
| No web interface | **Password-protected web UI** with real-time progress |

## Quick Start

```bash
# Install
pip install gungnir-security

# Set up authentication (for web UI)
gungnir auth setup

# Start the web dashboard
gungnir serve
# → Web UI at http://localhost:8888

# Or use CLI directly
gungnir hunt example.com --scope brief.txt --json results.json --report report.md
```

## Features

### Parallel Execution Engine
All tools fire in **two parallel waves**:
- **Wave 1 (Discovery, ~30s):** subfinder, amass, assetfinder — all find subdomains simultaneously
- **Wave 2 (Deep Scan, ~2-4min):** httpx, ffuf, nuclei, dalfox, sqlmap, gitleaks, corsy, nmap — all scan in parallel
- **Native modules** (JS analyzer, parameter miner, API discovery) run alongside external tools

### 8 Native Security Modules
No external tools required — pure Python, runs anywhere:

| Module | What It Does |
|---|---|
| **JavaScript Analyzer** | Downloads JS files, extracts API routes, parameters, secrets, source maps |
| **Parameter Miner** | Tests 1000+ parameter names for reflection (XSS), errors (SQLi), response changes (IDOR) |
| **API Discovery** | Finds GraphQL (with introspection), Swagger/OpenAPI, Spring Boot Actuator, REST endpoints |
| **Security Header Analyzer** | Audits HSTS, CSP, X-Frame-Options, cookie security flags |
| **Subdomain Takeover Checker** | Checks 12 cloud services for dangling DNS + NXDOMAIN |
| **HTTP Method Tester** | Tests all 12 methods: GET, POST, PUT, DELETE, TRACE, PROPFIND, etc. |
| **Backup File Finder** | Checks .git, .svn, .env, .bak, .old, editor files, config files |
| **Redirect Chain Mapper** | Follows redirect chains, tests open redirect with 9 payload types |

### Intelligence Engine

#### 26 Attack Chain Patterns
GUNGNIR doesn't just dump raw tool output. It **correlates findings across tools**:

- SSRF + secret exposure → "SSRF → cloud metadata → credential theft" (90% confidence)
- .git exposed + secret → "Source code → secrets leaked" (95% confidence)
- Open redirect + SSRF → "Redirect → SSRF bypass" (70% confidence)
- XSS + admin endpoint → "XSS → session hijack → account takeover" (80% confidence)
- SQLi + admin panel → "SQLi → auth bypass → admin access" (85% confidence)
- CORS misconfig + auth cookie → "CORS + credentials → cross-origin data theft" (80% confidence)
- GraphQL introspection + API routes → "Full API mapping → injection testing" (80% confidence)
- ...and 19 more patterns

#### 10-Factor Priority Scoring
Each finding scored on **10 separate factors** — not one collapsed "AI score":

1. Severity (critical > high > medium > low)
2. Confidence (multi-source > single source)
3. Verification status (verified > unverified)
4. Endpoint sensitivity (`/admin` > `/about`)
5. Secret type (AWS key > generic string)
6. Technology relevance (old tech > new tech)
7. Exposure level (public > internal)
8. Attack chain membership (part of chain = boosted)
9. Novelty (new since last run = boosted)
10. Exploitability (easy > hard)

Each score is **explainable** — GUNGNIR tells you *why* a finding was prioritized.

#### Finding Lifecycle
9 lifecycle states for tracking findings over time:
`NEW → TRIAGED → REPORTED → ACCEPTED → RESOLVED → REGRESSED → DUPLICATE → REJECTED → OUT_OF_SCOPE`

- **Regression detection:** Previously resolved findings that reappear are flagged
- **False-positive suppression:** Rejected findings don't re-alert on future scans
- **Historical diffing:** "5 new findings since last run" — critical for recurring bug bounty work

### Custom Pipelines
Define your own scan workflow in YAML:

```yaml
name: API Hunter
description: Optimized for API endpoints
target_types: [domain, url]

stages:
  - name: recon
    tools: [subfinder, assetfinder]
    parallel: true
  - name: api-discover
    tools: [api-discoverer, js-analyzer]
    parallel: true
  - name: injection
    tools: [nuclei, sqlmap, dalfox]
    parallel: true
    condition: "endpoints contains '/api/' or api_routes > 0"
```

Features:
- **Stage I/O mapping:** Output from one stage feeds into the next
- **Conditional execution:** Skip stages based on conditions (`tech contains 'wordpress'`)
- **Per-tool configuration:** Custom flags, templates, wordlists per tool
- **Pipeline variables:** `{{target}}` templating
- **Validation + dry-run:** Test pipelines before running
- **5 built-in pipelines:** Default, API Hunter, WordPress, Quick Recon, Subdomain Only

### Custom Tool Registration
Register your own scripts as GUNGNIR tools:

```bash
gungnir tools add my-scanner --binary /path/to/script --category vuln_scan --parser json
```

### Session Manager
Capture authenticated sessions and replay them across all tools:
- POST to login URL, capture Set-Cookie headers
- Store auth context (cookies + headers)
- Replay across all subsequent tool requests
- Cookie values masked in logs (security)
- Session file stored with 0o600 permissions

### Tool Conflict Resolution
GUNGNIR **never breaks your existing tools**:

1. Check user-configured override path
2. Check GUNGNIR's own bin directory (`~/.gungnir/bin/`)
3. Check system PATH (your existing install)
4. Download to `~/.gungnir/bin/` only (NEVER to system paths)

### Web UI with Authentication
- **Password-protected** dashboard (bcrypt hashing)
- Session cookies + API keys
- Real-time scan progress via WebSocket
- 7 views: Dashboard, Hunt, Findings, Pipelines, Tools, History, Settings
- Create/edit custom pipelines
- Register custom tools
- View findings with evidence
- Scan history with diffs

### Multi-Format Output
- **Terminal:** Colorized, prioritized findings
- **JSON:** Machine-readable export
- **Markdown:** Bounty-ready report
- **HTML:** Standalone dark-theme report
- **CSV:** Spreadsheet import
- **SQLite:** Full history for diffing
- **Notifications:** Webhook/Slack/Discord on scan completion

## Tool Arsenal

GUNGNIR auto-downloads pre-compiled binaries for:

| Tool | Category | What It Does |
|---|---|
| **subfinder** | recon | Passive subdomain enumeration (30+ sources) |
| **amass** | recon | Active + passive subdomain enumeration |
| **assetfinder** | recon | Fast lightweight subdomain discovery |
| **httpx** | fingerprint | HTTP probe, tech detection, title, status |
| **ffuf** | discovery | Content/endpoint fuzzer (200K+ wordlists) |
| **nuclei** | vuln_scan | Template-based scanner (5000+ templates) |
| **dalfox** | xss | DOM-aware XSS scanner |
| **sqlmap** | sqli | Full SQL injection framework |
| **gitleaks** | secret | Secret scanner (700+ patterns) |
| **nmap** | ports | Port scanner + service detection |
| **corsy** | cors | CORS misconfiguration scanner |

## CLI Commands

```bash
gungnir hunt <target> [--scope brief.txt] [--pipeline name] [--json out.json] [--report out.md]
gungnir tools list
gungnir tools install <name>
gungnir tools add <name> --binary /path/to/script
gungnir pipelines list
gungnir pipelines show <name>
gungnir scope --brief brief.txt --target example.com
gungnir history <target>
gungnir auth setup
gungnir serve [--host 0.0.0.0] [--port 8888]
```

## Target Types

| Target | What GUNGNIR Does |
|---|---|
| `example.com` (domain) | Subdomain enum → probe → deep scan all subdomains |
| `192.168.1.1` (IP) | Port scan → service detect → web probe → vuln scan |
| `10.0.0.0/24` (CIDR) | Host discovery → per-host scan → aggregate |
| `https://app.example.com/search?q=1` (URL) | Direct deep scan with all tools + native modules |

## Evidence Section — Real Test Results

### Test 1: Native modules against example.com

```bash
$ gungnir hunt example.com --no-tools --no-verify
```

```
╔══════════════════════════════════════════════╗
║  GUNGNIR v4.0 — APEX                           ║
║  Target: example.com (domain)                  ║
╚══════════════════════════════════════════════╝

  [native] running JS analyzer, param miner, API discovery...
  [native] ✓ 1 native findings

  [correlate] Analyzing 1 findings...
  [save] Persisting to SQLite...

══════════════════════════════════════════════════════════
  RESULTS — 1 actionable findings, 0 attack chains
══════════════════════════════════════════════════════════

  🟡 MEDIUM  Js Files Found
     Asset: example.com  Source: js_analyzer

══════════════════════════════════════════════════════════
  DIFF vs last run
  1 NEW | 0 RESOLVED | 0 recurring
══════════════════════════════════════════════════════════
```

### Test 2: Historical diffing

Second scan of the same target shows the finding is recurring:
```
DIFF vs last run
0 NEW | 0 RESOLVED | 1 recurring
```

### Test 3: Scan history

```bash
$ gungnir history example.com
```
```
Scan History for example.com
  Run e566d12d  2026-08-09 12:59  1 assets  1 findings
  Run 613a4b92  2026-08-09 12:59  1 assets  1 findings
```

### Test 4: Scope validation

```bash
$ gungnir scope --brief brief.txt --target https://app.example.com --target https://staging.example.com
```
```
[IN SCOPE] https://app.example.com — matches in-scope rule '*.example.com'
[OUT OF SCOPE] https://staging.example.com — matches out-of-scope rule '*.staging.example.com'
```

## ⚖️ Ethics & Responsible Disclosure

GUNGNIR is for **authorized security testing only**. Always:
1. Validate scope before scanning (`gungnir scope --brief ... --target ...`)
2. Follow program rules and rate limits
3. Do not run destructive tests or denial-of-service
4. Report vulnerabilities through official channels

**You are responsible for your actions.**

## 📊 Statistics

- **134 passing tests**
- **68 Python source files**
- **13,120 lines of code**
- **8 native security modules**
- **26 attack chain patterns**
- **10-factor priority scoring**
- **5 built-in pipelines**
- **9 finding lifecycle states**
- **20+ REST API endpoints**
- **Zero tools required for native mode**

## 👨‍💻 About the Author

**Syed Zada Abrar** (also known as **Andrax Pentester** / **Cyb3rVolt3x**) is a certified penetration tester, full-stack web developer, and security researcher. He is the founder of [SentinelReign](https://sentinelreign.com) and runs [AndraxPentester](https://andraxpentester.in), a cybersecurity-focused platform.

- 🌐 **Website:** [andraxpentester.in](https://andraxpentester.in)
- 🛡️ **SentinelReign:** [sentinelreign.com](https://sentinelreign.com)
- 🐙 **GitHub:** [cyb3rvolt3x-A4lixhaS3ntin3l](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l)
- ✉️ **Email:** andraxpentester@gmail.com
- 🔧 **Skills:** Penetration testing, bug bounty hunting, web application security, Python development, security tool development

GUNGNIR was built to solve a real problem in the bug bounty community: too many tools, too much noise, not enough intelligence. It represents the culmination of years of security research experience distilled into a single, fast, intelligent platform.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome — especially new attack chain patterns, native modules, and pipeline templates.

## 📝 License

[MIT](LICENSE) — use it, fork it, build your reputation on it.

## 🔗 Links

- [GitHub Repository](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir)
- [Author's Website](https://andraxpentester.in)
- [SentinelReign](https://sentinelreign.com)
- [Report a Bug](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir/issues)
- [Request a Feature](https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/gungnir/issues)

---

<div align="center">

**GUNGNIR** — *Never misses its target.*

Built with ⚔️ by [Syed Zada Abrar](https://andraxpentester.in)

[andraxpentester.in](https://andraxpentester.in) · [sentinelreign.com](https://sentinelreign.com)

</div>
