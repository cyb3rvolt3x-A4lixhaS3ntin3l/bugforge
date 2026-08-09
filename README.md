# Gungnir

> **v3.0 — APEX**: A parallel, intelligence-driven bug bounty platform that fires all tools simultaneously, correlates findings into attack chains, verifies criticals, persists to SQLite, and diffs against previous runs.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0--alpha-orange.svg)]()

## What Gungnir Does

Gungnir runs a complete security sweep against any target — domain, IP, CIDR, or URL — in 3-5 minutes. It:

1. **Auto-detects** the target type (domain, IP, CIDR, URL) and selects the right tool combination
2. **Downloads pre-compiled binaries** for 10+ security tools on first run (no Go, no Docker needed)
3. **Fires all tools in parallel** in two waves: discovery → deep scan
4. **Runs native analysis modules** (JS analyzer, parameter miner, API discovery) alongside external tools
5. **Correlates** results across tools — detects attack chains (SSRF + secret = credential theft)
6. **Filters** false positives with rule-based logic
7. **Prioritizes** findings by real impact, not just scanner severity
8. **Verifies** critical/high findings by re-testing before reporting
9. **Persists** to SQLite and **diffs** against previous runs ("5 new since last scan")
10. **Outputs** to terminal, JSON, and Markdown report

## Quick Start

```bash
pip install gungnir

# First run — downloads tool binaries automatically (~30s)
gungnir hunt example.com --scope brief.txt

# Subsequent runs — everything cached
gungnir hunt example.com

# Native modules only (no external tools needed)
gungnir hunt example.com --no-tools

# Get JSON output
gungnir hunt example.com --json results.json

# Generate Markdown report
gungnir hunt example.com --report report.md
```

## CLI Commands

```bash
gungnir hunt <target> [--scope brief.txt] [--no-tools] [--no-verify] [--json out.json] [--report out.md]
gungnir tools list
gungnir tools install <name>
gungnir tools install-all
gungnir scope --brief brief.txt --target example.com
gungnir history example.com
```

## Architecture

```
gungnir hunt <target>
       │
       ▼
  TARGET AUTO-DETECTOR (IP? Domain? CIDR? URL?)
       │
       ▼
  SCOPE GUARD (block if out of scope)
       │
       ▼
  ┌─── WAVE 1: DISCOVERY (parallel, ~30s) ───┐
  │  subfinder │ amass │ assetfinder          │
  │  nmap (if IP) │ native DNS brute          │
  └───────────────┬──────────────────────────┘
                  │
       ▼
  ┌─── WAVE 2: DEEP SCAN (parallel, ~2-4min) ─┐
  │  httpx │ ffuf │ nuclei │ dalfox            │
  │  sqlmap │ gitleaks │ corsy │ nmap NSE     │
  │  + NATIVE: JS analyzer │ Param miner │    │
  │           API discovery                   │
  └───────────────┬──────────────────────────┘
                  │
       ▼
  CORRELATION ENGINE (in-memory, <1s)
  ├── Group by asset
  ├── Cross-reference findings
  ├── Build attack chains
  ├── Filter false positives
  └── Score priority
       │
       ▼
  VERIFICATION (criticals re-tested, ~30s)
       │
       ▼
  PERSISTENCE (SQLite, async, <1s)
  ├── Save findings
  ├── Diff vs last run
  └── Mark new/resolved/regressed
       │
       ▼
  OUTPUT (terminal + JSON + Markdown report)
```

## Tool Arsenal

Gungnir auto-downloads pre-compiled binaries for these tools:

| Tool | Category | What It Does |
|---|---|---|
| **subfinder** | recon | Passive subdomain enumeration (30+ sources) |
| **amass** | recon | Active + passive subdomain enumeration |
| **assetfinder** | recon | Fast lightweight subdomain discovery |
| **httpx** | fingerprint | HTTP probe, tech detection, title, status |
| **ffuf** | discovery | Content/endpoint fuzzer |
| **nuclei** | vuln_scan | Template-based vulnerability scanner (5000+ templates) |
| **dalfox** | xss | DOM-aware XSS scanner |
| **sqlmap** | sqli | Full SQL injection framework |
| **gitleaks** | secret | Secret scanner (700+ patterns) |
| **nmap** | ports | Port scanner + service detection |
| **corsy** | cors | CORS misconfiguration scanner |

## Native Modules (No External Tools Required)

Gungnir includes three analysis modules that run without any external tools:

### JavaScript Analyzer
Downloads and analyzes JS files from the target:
- Extracts API routes (`fetch()`, `axios()`, `$.ajax()` calls)
- Extracts hardcoded secrets (AWS keys, GitHub tokens, JWTs, Google API keys)
- Detects exposed source maps
- Extracts parameter names

### Parameter Miner
Tests common high-value parameter names against endpoints:
- `id`, `url`, `redirect`, `file`, `admin`, `debug`, `token`, etc.
- Detects parameter reflection (XSS candidate)
- Detects SQL error messages (SQLi candidate)
- Detects response length changes (IDOR candidate)
- Detects status code changes

### API Discovery
Probes for common API endpoints:
- GraphQL (with introspection test)
- Swagger/OpenAPI specs
- Spring Boot Actuator
- REST API paths (`/api/v1/`, `/api/v2/`)
- SOAP/WSDL

## Intelligence Engine

### Correlation + Attack Chains

Gungnir doesn't just dump raw tool output. It correlates findings across tools:

| Pattern | Attack Chain |
|---|---|
| SSRF + secret exposure | "SSRF → cloud metadata → credential theft" |
| .git exposed + secret | "Source code → secrets leaked" |
| Open redirect + SSRF | "Redirect → SSRF bypass" |
| XSS near admin endpoint | "XSS → session hijack → account takeover" |
| GraphQL introspection + API routes | "Full API mapping → injection testing" |
| Swagger exposed | "Endpoint enumeration → IDOR testing" |

### False Positive Filtering

Rules-based removal of noise:
- Nuclei info-level favicon/tech-detect findings → filtered
- XSS reflected inside `<code>`/`<pre>` blocks → filtered (not executable)
- CORS wildcard without credentials → filtered (not exploitable)
- Very low confidence + single source → filtered

### Priority Scoring

Findings scored by real impact:
- Severity (critical > high > medium > low)
- Confidence (multi-source > single source)
- Endpoint sensitivity (`/admin` > `/about`)
- Secret type (AWS key > generic string)
- Verification status (verified > unverified)

### Verification

Critical and high findings are re-tested before reporting:
- XSS: check if payload still reflected
- Exposed files (.git, .env): check if still returns 200
- GraphQL: check if introspection still works
- CORS: check if ACAO still reflects arbitrary origin

## Persistence + Diffing

Gungnir saves every scan to SQLite (`~/.gungnir/gungnir.db`). When you scan the same target again, it shows:

```
DIFF vs last run
5 NEW | 2 RESOLVED | 7 recurring
```

This is critical for recurring bug bounty work — you only care about what changed.

## Evidence Section — Real Test Results

### Test 1: Native modules against example.com

```bash
$ gungnir hunt example.com --no-tools --no-verify --json results.json --report report.md
```

**Output:**
```
╔══════════════════════════════════════════╗
║  GUNGNIR v3 — APEX                       ║
║  Target: example.com (domain)                 ║
╚══════════════════════════════════════════╝

  [native] running JS analyzer, param miner, API discovery...
  [native] ✓ 1 native findings

  [correlate] Analyzing 1 findings...
  [save] Persisting to SQLite...

══════════════════════════════════════════
  RESULTS — 1 actionable findings, 0 attack chains
══════════════════════════════════════════

  🟡 MEDIUM  Js Files Found
     Asset: example.com  Source: js_analyzer

══════════════════════════════════════════
  DIFF vs last run
  1 NEW | 0 RESOLVED | 0 recurring
══════════════════════════════════════════

  [report] Report saved to report.md
  [json] JSON saved to results.json
  Database: ~/.gungnir/gungnir.db
  Total time: 1.0s
```

### Test 2: Second scan — diffing works

Running the same target again shows the finding is now recurring (not new):

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

  Run e566d12d-8ac  2026-08-09 12:59  1 assets  1 findings
  Run 613a4b92-0f0  2026-08-09 12:59  1 assets  1 findings
```

### Test 4: Scope validation

```bash
$ gungnir scope --brief brief.txt --target https://app.example.com --target https://staging.example.com
```

```
[IN SCOPE] https://app.example.com  — matches in-scope rule '*.example.com'
[OUT OF SCOPE] https://staging.example.com  — matches out-of-scope rule '*.staging.example.com'
```

### Test 5: Tool management

```bash
$ gungnir tools list
```

```
Gungnir Tool Arsenal

  ✓ subfinder            /home/pi/.gungnir/bin/subfinder
  ✓ nuclei               /home/pi/.gungnir/bin/nuclei
  ✓ dalfox               /home/pi/.gungnir/bin/dalfox
  ✓ gitleaks             /home/pi/.gungnir/bin/gitleaks
  ✓ ffuf                 /home/pi/.gungnir/bin/ffuf
  ✗ httpx                (not installed)
  ✗ sqlmap               (not installed)
  ✗ nmap                 (not installed)
  ✗ amass                (not installed)
  ✗ assetfinder          (not installed)

Installed: 5/10
```

### Test 6: Generated Markdown Report

```markdown
# Gungnir Scan Report — example.com

**Date:** 2026-08-09 12:59 UTC  
**Findings:** 1  
**Attack Chains:** 0  

## Findings

### #1 [MEDIUM] Js Files Found

**Asset:** `example.com`  
**Source:** js_analyzer  
**Confidence:** 60%

---
*Generated with Gungnir v3 — APEX*
```

## What Gungnir Can Do With All Tools Installed

When all external tools are available, Gungnir fires them all in parallel:

**Wave 1 (Discovery, ~30s):**
- subfinder, amass, assetfinder — all find subdomains simultaneously
- nmap (if target is IP) — full port scan
- Native DNS brute force

**Wave 2 (Deep Scan, ~2-4min):**
- httpx — probes all discovered hosts for live HTTP + tech stack
- ffuf — fuzzes endpoints with ranked wordlists
- nuclei — runs 5000+ vulnerability templates
- dalfox — tests for XSS (DOM-aware)
- sqlmap — tests parameterized URLs for SQL injection
- gitleaks — scans for leaked secrets
- corsy — checks CORS misconfiguration
- nmap NSE — runs custom service scripts
- JS analyzer — extracts API routes, parameters, secrets from JS files
- Parameter miner — discovers hidden parameters
- API discovery — finds GraphQL, Swagger, Actuator endpoints

**Post-Scan Intelligence (<2s):**
- Correlate all findings by asset
- Build attack chains
- Filter false positives
- Score priority
- Re-verify criticals
- Save to SQLite
- Diff against last run

## Target Types

| Target | What Gungnir Does |
|---|---|
| `example.com` (domain) | Subdomain enum → probe → deep scan all subdomains |
| `192.168.1.1` (IP) | Port scan → service detect → web probe → vuln scan |
| `10.0.0.0/24` (CIDR) | Host discovery → per-host scan → aggregate |
| `https://app.example.com/search?q=1` (URL) | Direct deep scan: ffuf + nuclei + dalfox + sqlmap + param mining |

## ⚖️ Ethics

Gungnir is for **authorized testing only**. Always:
1. Validate scope before scanning (`gungnir scope --brief ... --target ...`)
2. Follow program rules and rate limits
3. Do not run destructive tests
4. Report through official channels

**You are responsible for your actions.**

## License

[MIT](LICENSE)

## Status

**v3.0.0-alpha** — Core architecture, parallel engine, intelligence layer, native modules, persistence, and CLI are functional. Pre-compiled binary download works for most tools. Full testing requires a network environment that can reach the target and download binaries from GitHub releases.