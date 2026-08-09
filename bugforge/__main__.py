"""
BugForge unified command-line interface.

Usage:
    python -m bugforge --help
    python -m bugforge scope check --brief brief.txt --target https://app.example.com
    python -m bugforge recon subdomains --domain example.com [--resolve] [--scope brief.txt]
    python -m bugforge recon content --url https://example.com [--wordlist path.txt]
    python -m bugforge recon fingerprint --url https://example.com
    python -m bugforge vulns xss --generate [--mutate] [--out payloads.txt]
    python -m bugforge vulns ssrf --callback your.interact.sh [--metadata]
    python -m bugforge vulns cors --url https://example.com
    python -m bugforge vulns secrets --file response.html
    python -m bugforge vulns sqli --url 'https://example.com/item?id=1' --param id --value 1
    python -m bugforge report xss --url 'https://...' --payload '<script>alert(1)</script>' --out report.md
    python -m bugforge report cvss --vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
"""
from __future__ import annotations
import argparse
import json
import sys

from . import __version__
from .utils.colors import c, Colors
from .utils.logger import set_verbose


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="bugforge",
        description="BugForge — modular bug bounty toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"bugforge {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose/debug output")
    sub = parser.add_subparsers(dest="module", required=True, metavar="<module>")

    _add_scope(sub)
    _add_recon(sub)
    _add_vulns(sub)
    _add_report(sub)
    _add_orchestrate(sub)
    _add_serve(sub)

    args = parser.parse_args(argv)
    set_verbose(args.verbose)
    return args.func(args)


# ---------------- scope ----------------
def _add_scope(sub):
    p = sub.add_parser("scope", help="scope parsing & validation")
    sp = p.add_subparsers(dest="cmd", required=True)
    c1 = sp.add_parser("check", help="check if a target is in scope")
    c1.add_argument("--brief", required=True, help="brief file path")
    c1.add_argument("--target", required=True, action="append", help="target URL/host (repeatable)")
    c1.set_defaults(func=_scope_check)

    c2 = sp.add_parser("show", help="print parsed scope")
    c2.add_argument("--brief", required=True)
    c2.set_defaults(func=_scope_show)


def _scope_check(args):
    from .scope.validator import load_brief_file
    scope = load_brief_file(args.brief)
    v = scope
    rc = 0
    for t in args.target:
        ok, reason = v.is_in_scope(t)
        tag = c("[IN SCOPE]", Colors.GREEN) if ok else c("[OUT OF SCOPE]", Colors.RED)
        print(f"{tag} {t}  — {reason}")
        if not ok:
            rc = 2
    return rc


def _scope_show(args):
    from .scope.validator import load_brief_file
    scope = load_brief_file(args.brief)
    print("In scope:")
    for r in scope.in_scope:
        print(f"  - {r.raw} ({r.kind})")
    print("Out of scope:")
    for r in scope.out_of_scope:
        print(f"  - {r.raw} ({r.kind})")
    return 0


# ---------------- recon ----------------
def _add_recon(sub):
    p = sub.add_parser("recon", help="reconnaissance")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("subdomains", help="enumerate subdomains (passive)")
    s.add_argument("--domain", required=True)
    s.add_argument("--resolve", action="store_true", help="resolve to IPs")
    s.add_argument("--scope", help="brief file to filter results to scope")
    s.add_argument("--out", help="write results to file (one per line)")
    s.set_defaults(func=_recon_subdomains)

    c = sp.add_parser("content", help="content/endpoint discovery")
    c.add_argument("--url", required=True)
    c.add_argument("--wordlist", help="custom wordlist file")
    c.add_argument("--threads", type=int, default=10)
    c.add_argument("--status", help="comma list of status codes to keep (e.g. 200,301,403)")
    c.set_defaults(func=_recon_content)

    f = sp.add_parser("fingerprint", help="technology fingerprinting")
    f.add_argument("--url", required=True)
    f.add_argument("--audit", action="store_true", help="also report missing security headers")
    f.set_defaults(func=_recon_fingerprint)


def _recon_subdomains(args):
    from .recon.subdomains import SubdomainEnum
    from .scope.validator import load_brief_file
    scope = None
    if args.scope:
        scope = load_brief_file(args.scope)
    enum = SubdomainEnum()
    results = enum.enumerate(args.domain, resolve=args.resolve, scope=scope)
    lines = []
    for r in results:
        line = r.name + (f" ({r.ip})" if r.ip else "")
        print(f"{c('[+]', Colors.GREEN)} {line}  [{r.source}]")
        lines.append(line)
    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(lines) + "\n")
    print(f"\n{c('Total:', Colors.BOLD)} {len(results)} subdomains")
    return 0


def _recon_content(args):
    from .recon.content import ContentDiscovery, BUILTIN_WORDLIST
    wordlist = BUILTIN_WORDLIST
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [w.strip() for w in f if w.strip()]
    status_filter = None
    if args.status:
        status_filter = [int(x) for x in args.status.split(",")]
    disc = ContentDiscovery(threads=args.threads)
    results = disc.discover(args.url, wordlist=wordlist, status_filter=status_filter)
    for r in results:
        color = Colors.GREEN if r.status in (200, 201) else Colors.YELLOW if r.status in (301, 302, 401, 403) else Colors.GREY
        print(f"{c(str(r.status), color):>5}  {r.length:>7}B  {r.url}")
    print(f"\n{c('Found:', Colors.BOLD)} {len(results)} paths")
    return 0


def _recon_fingerprint(args):
    from .recon.fingerprint import TechFingerprinter
    fp = TechFingerprinter()
    res = fp.fingerprint(args.url)
    print(f"{c('Status:', Colors.BOLD)} {res.status}")
    if res.technologies:
        print(f"{c('Technologies:', Colors.BOLD)}")
        for t in res.technologies:
            print(f"  - {t.technology}  [{t.source}] {c(t.evidence, Colors.GREY)}")
    else:
        print(f"{c('Technologies:', Colors.BOLD)} none detected")
    if args.audit:
        missing = fp.missing_security_headers(res.headers)
        if missing:
            print(f"{c('Missing security headers:', Colors.YELLOW)}")
            for h in missing:
                print(f"  - {h}")
    return 0


# ---------------- vulns ----------------
def _add_vulns(sub):
    p = sub.add_parser("vulns", help="vulnerability helpers")
    sp = p.add_subparsers(dest="cmd", required=True)

    x = sp.add_parser("xss", help="XSS payload generator")
    x.add_argument("--generate", action="store_true")
    x.add_argument("--mutate", action="store_true", default=True)
    x.add_argument("--max", type=int, default=0)
    x.add_argument("--out", help="write payloads to file")
    x.set_defaults(func=_vulns_xss)

    s = sp.add_parser("ssrf", help="SSRF helper")
    s.add_argument("--callback", help="OOB callback host for payload gen")
    s.add_argument("--metadata", action="store_true", help="print metadata endpoint payloads")
    s.add_argument("--bypass", action="store_true", help="print filter-bypass variants")
    s.add_argument("--out", help="write payloads to file")
    s.set_defaults(func=_vulns_ssrf)

    co = sp.add_parser("cors", help="CORS misconfiguration checker")
    co.add_argument("--url", required=True)
    co.set_defaults(func=_vulns_cors)

    se = sp.add_parser("secrets", help="scan a file/response for leaked secrets")
    se.add_argument("--file", required=True)
    se.add_argument("--json", action="store_true", help="output JSON")
    se.set_defaults(func=_vulns_secrets)

    sq = sp.add_parser("sqli", help="SQLi detection helper")
    sq.add_argument("--url", required=True)
    sq.add_argument("--param", required=True)
    sq.add_argument("--value", required=True)
    sq.add_argument("--time", action="store_true", help="run time-based detection")
    sq.set_defaults(func=_vulns_sqli)


def _vulns_xss(args):
    from .vulns.xss import XssPayloadGen
    gen = XssPayloadGen()
    payloads = gen.generate(mutate=args.mutate, max_count=args.max)
    out = "\n".join(payloads)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print(f"{c('[+]', Colors.GREEN)} wrote {len(payloads)} payloads to {args.out}")
    else:
        print(out)
    print(f"\n{c('Total:', Colors.BOLD)} {len(payloads)} payloads", file=sys.stderr)
    return 0


def _vulns_ssrf(args):
    from .vulns.ssrf import SsrfHelper
    helper = SsrfHelper()
    lines = []
    if args.metadata:
        for p in helper.metadata_payloads():
            lines.append(p.payload)
            print(f"{c('[meta]', Colors.CYAN)} {p.payload}")
    if args.bypass:
        for p in helper.bypass_payloads():
            lines.append(p.payload)
            print(f"{c('[bypass]', Colors.MAGENTA)} {p.payload}  ({p.technique})")
    if args.callback:
        for p in helper.callback_payloads(args.callback):
            lines.append(p.payload)
            print(f"{c('[oob]', Colors.GREEN)} {p.payload}  ({p.technique})")
    if not (args.metadata or args.bypass or args.callback):
        print("Use --metadata, --bypass, or --callback <host>. See --help.")
        return 1
    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\n{c('[+]', Colors.GREEN)} wrote {len(lines)} payloads to {args.out}")
    return 0


def _vulns_cors(args):
    from .vulns.cors import CorsChecker
    checker = CorsChecker()
    results = checker.check(args.url)
    vuln_found = False
    for r in results:
        if r.vulnerable:
            vuln_found = True
            print(f"{c('[VULN]', Colors.RED)} Origin {r.origin} — {r.reason}")
            print(f"        ACAO={r.acao} ACAC={r.acac}")
        else:
            print(f"{c('[ok]', Colors.GREY)} Origin {r.origin} — {r.reason}")
    return 0 if not vuln_found else 0


def _vulns_secrets(args):
    from .vulns.secrets import SecretScanner
    scanner = SecretScanner()
    matches = scanner.scan_file(args.file)
    if not matches:
        print(f"{c('[clean]', Colors.GREEN)} no secrets detected in {args.file}")
        return 0
    if args.json:
        print(json.dumps([m.__dict__ for m in matches], indent=2))
    else:
        print(f"{c('[!]', Colors.RED)} {len(matches)} potential secret(s) in {args.file}:")
        for m in matches:
            masked = m.value if len(m.value) <= 12 else m.value[:6] + "..." + m.value[-4:]
            print(f"  line {m.line:>5}  {c(m.type, Colors.YELLOW):<22}  {masked}")
    return 1 if matches else 0


def _vulns_sqli(args):
    from .vulns.sqli import SqliHelper
    helper = SqliHelper()
    # error-based: fetch and fingerprint
    r = helper.client.get(args.url)
    errors = helper.fingerprint_errors(r.text)
    found = False
    if errors:
        found = True
        for e in errors:
            print(f"{c('[ERR]', Colors.RED)} {e.database}: {e.match}")
    if args.time:
        res = helper.test_time_based(args.url, args.param, args.value)
        if res:
            found = True
            print(f"{c('[TIME]', Colors.RED)} {res}")
    else:
        res = helper.test_boolean(args.url, args.param, args.value)
        if res:
            found = True
            print(f"{c('[BOOL]', Colors.RED)} {res}")
    if not found:
        print(f"{c('[clean]', Colors.GREEN)} no SQLi indicators detected for {args.param}")
    return 0


# ---------------- report ----------------
def _add_report(sub):
    p = sub.add_parser("report", help="bug report generation")
    sp = p.add_subparsers(dest="cmd", required=True)

    for name in ("xss", "idor", "ssrf", "secret"):
        r = sp.add_parser(name, help=f"{name} report template")
        r.add_argument("--url", required=True)
        r.add_argument("--out", help="write report to file")
        r.add_argument("--reporter", default="")
        if name == "xss":
            r.add_argument("--payload", required=True)
        if name == "idor":
            r.add_argument("--object-id", required=True)
        if name == "ssrf":
            r.add_argument("--metadata", default="http://169.254.169.254/latest/meta-data/")
        if name == "secret":
            r.add_argument("--type", default="API Key")
            r.add_argument("--value", default="AKIA************")
        r.set_defaults(func=_report_template)

    cv = sp.add_parser("cvss", help="compute CVSS v3.1 base score from a vector")
    cv.add_argument("--vector", required=True)
    cv.set_defaults(func=_report_cvss)


def _report_template(args):
    from .reporting.report import ReportBuilder
    if args.cmd == "xss":
        t = ReportBuilder.xss_template(args.url, args.payload, args.reporter)
    elif args.cmd == "idor":
        t = ReportBuilder.idor_template(args.url, args.object_id, args.reporter)
    elif args.cmd == "ssrf":
        t = ReportBuilder.ssrf_template(args.url, args.metadata, args.reporter)
    elif args.cmd == "secret":
        t = ReportBuilder.secret_template(args.url, args.type, args.value, args.reporter)
    else:
        return 1
    md = ReportBuilder(t).build()
    if args.out:
        with open(args.out, "w") as f:
            f.write(md)
        print(f"{c('[+]', Colors.GREEN)} wrote report to {args.out}")
    else:
        print(md)
    return 0


def _report_cvss(args):
    from .reporting.cvss import Cvss31, CvssVector
    info = Cvss31.full(CvssVector.parse(args.vector))
    print(json.dumps(info, indent=2))
    return 0


# ---------------- orchestrate (v2.0) ----------------
def _add_orchestrate(sub):
    p = sub.add_parser("orchestrate", help="run external tools via orchestrator (v2.0)")
    sp = p.add_subparsers(dest="cmd", required=True)

    t = sp.add_parser("tools", help="list all registered tools and install status")
    t.set_defaults(func=_orch_tools)

    i = sp.add_parser("install", help="install a specific tool")
    i.add_argument("name", help="tool name")
    i.set_defaults(func=_orch_install)

    r = sp.add_parser("run", help="run a single tool against a target")
    r.add_argument("--tool", required=True, help="tool name (e.g. subfinder)")
    r.add_argument("--target", required=True, help="target domain/URL")
    r.set_defaults(func=_orch_run)

    pl = sp.add_parser("pipeline", help="run the full pipeline against a target")
    pl.add_argument("--target", required=True)
    pl.add_argument("--brief", help="scope brief file")
    pl.add_argument("--skip", nargs="*", help="stages to skip")
    pl.set_defaults(func=_orch_pipeline)


def _orch_tools(args):
    from .orchestrator.engine import ToolOrchestrator
    orch = ToolOrchestrator(auto_install=False)
    status = orch.status()
    print(f"{c('BugForge Tool Arsenal', Colors.BOLD)}\n")
    for t in status:
        icon = c("✓", Colors.GREEN) if t["installed"] else c("✗", Colors.YELLOW)
        print(f"  {icon} {t['name']:<20} {t['category']:<15} {t['description']}")
        if not t["installed"]:
            print(f"    {c('install:', Colors.GREY)} {t['install_method']}  {c(t['github'], Colors.GREY)}")
    installed = sum(1 for t in status if t["installed"])
    print(f"\n{c('Installed:', Colors.BOLD)} {installed}/{len(status)} tools")
    return 0


def _orch_install(args):
    from .orchestrator.engine import ToolOrchestrator
    orch = ToolOrchestrator(auto_install=True)
    print(f"{c('[*]', Colors.CYAN)} Installing {args.name}...")
    success = orch.install(args.name)
    if success:
        print(f"{c('[+]', Colors.GREEN)} {args.name} installed successfully")
    else:
        print(f"{c('[!]', Colors.RED)} Failed to install {args.name}")
    return 0 if success else 1


def _orch_run(args):
    import asyncio
    from .orchestrator.engine import ToolOrchestrator
    orch = ToolOrchestrator(auto_install=True)

    async def _run():
        result = await orch.run(args.tool, args.target)
        if result.status.value == "completed":
            print(f"{c('[+]', Colors.GREEN)} {args.tool} completed in {result.elapsed:.1f}s")
            print(f"{c('Findings:', Colors.BOLD)} {len(result.findings)}")
            for f in result.findings[:20]:
                print(f"  {json.dumps(f, indent=2) if isinstance(f, dict) else f}")
        else:
            print(f"{c('[!]', Colors.RED)} {args.tool} {result.status.value}: {result.error}")
        return result

    asyncio.run(_run())
    return 0


def _orch_pipeline(args):
    import asyncio
    from .orchestrator.engine import ToolOrchestrator
    from .pipeline.stages import Pipeline
    from .scope.validator import load_brief_file

    scope = None
    if args.brief:
        scope = load_brief_file(args.brief)
    orch = ToolOrchestrator(auto_install=True)
    pipe = Pipeline(orch, scope=scope)

    async def on_progress(stage, tool, msg):
        print(f"  {c(f'[{stage}]', Colors.CYAN)} {tool}: {msg}")

    async def _run():
        print(f"{c('[*]', Colors.CYAN)} Starting pipeline against {args.target}...\n")
        result = await pipe.run(args.target, on_progress=on_progress, skip_stages=args.skip)
        print(f"\n{c('Pipeline Complete', Colors.BOLD)}")
        print(f"  Target: {result.target}")
        print(f"  Total findings: {len(result.all_findings)}")
        print(f"  Elapsed: {result.total_elapsed:.1f}s")
        summary = result.summary()
        for cat, count in summary["by_category"].items():
            print(f"    {cat}: {count}")
        return result

    asyncio.run(_run())
    return 0


# ---------------- serve (v2.0) ----------------
def _add_serve(sub):
    p = sub.add_parser("serve", help="start the BugForge web UI server (v2.0)")
    p.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    p.add_argument("--no-browser", action="store_true", help="don't auto-open browser")
    p.set_defaults(func=_serve)


def _serve(args):
    from .web.server import serve
    serve(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
