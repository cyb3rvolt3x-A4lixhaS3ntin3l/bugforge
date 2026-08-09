"""
BugForge v3 — APEX CLI
Main entry point: bugforge hunt <target>
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys
import time

from . import __version__
from .core.config import get_config
from .core.detect import detect_target_type, normalize_target, TargetType
from .core.binaries import BinaryManager
from .core.parallel import ParallelEngine
from .intelligence.correlate import correlate, Finding, AttackChain, Severity
from .intelligence.prioritize import prioritize, prioritize_chains
from .intelligence.filter import filter_fps
from .intelligence.verify import verify_criticals
from .storage.db import Database
from .reporting.report import ReportBuilder, ReportTemplate
from .reporting.cvss import Cvss31, CvssVector
from .scope.validator import parse_brief
from .utils.colors import c, Colors
from .core.pipelines import PipelineLoader
from .core.custom_tools import CustomToolLoader
from .core.auth import AuthManager


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="bugforge",
        description="BugForge v3.1 — FORGE: Parallel bug bounty intelligence platform with custom pipelines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"bugforge {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # hunt
    h = sub.add_parser("hunt", help="Run a full scan against a target")
    h.add_argument("target", help="Target domain/IP/URL")
    h.add_argument("--scope", help="Scope brief file")
    h.add_argument("--no-tools", action="store_true", help="Only run native modules (no external tools)")
    h.add_argument("--no-verify", action="store_true", help="Skip verification of criticals")
    h.add_argument("--pipeline", help="Pipeline name to use (default: Default)")
    h.add_argument("--json", help="Output JSON to file")
    h.add_argument("--report", help="Output Markdown report to file")

    # tools
    t = sub.add_parser("tools", help="Manage tool binaries and custom tools")
    ts = t.add_subparsers(dest="tools_cmd", required=True)
    ts.add_parser("list", help="List all tools and status")
    ti = ts.add_parser("install", help="Install a specific tool")
    ti.add_argument("name")
    ts.add_parser("install-all", help="Install all tools")
    ta = ts.add_parser("add", help="Register a custom tool")
    ta.add_argument("name")
    ta.add_argument("--binary", required=True)
    ta.add_argument("--category", default="vuln_scan")
    ta.add_argument("--command", default="")
    ta.add_argument("--parser", default="none")
    ta.add_argument("--timeout", type=int, default=120)
    tr = ts.add_parser("remove", help="Remove a custom tool")
    tr.add_argument("name")
    tt = ts.add_parser("test", help="Test a tool against a target")
    tt.add_argument("name")
    tt.add_argument("--target", required=True)
    ts.add_parser("list-custom", help="List custom tools only")

    # scope
    sc = sub.add_parser("scope", help="Validate scope")
    sc.add_argument("--brief", required=True, help="Brief file")
    sc.add_argument("--target", required=True, action="append", help="Target to check")

    # history
    hist = sub.add_parser("history", help="Show scan history for a target")
    hist.add_argument("target")

    # pipelines
    pl = sub.add_parser("pipelines", help="Manage custom pipelines")
    pls = pl.add_subparsers(dest="pipelines_cmd", required=True)
    pls.add_parser("list", help="List all pipelines")
    plss = pls.add_parser("show", help="Show pipeline details")
    plss.add_argument("name")
    plsd = pls.add_parser("delete", help="Delete a pipeline")
    plsd.add_argument("name")

    # auth
    au = sub.add_parser("auth", help="Authentication management")
    aus = au.add_subparsers(dest="auth_cmd", required=True)
    aus.add_parser("setup", help="Set up authentication (first time)")
    aus.add_parser("password", help="Change password")
    aus.add_parser("status", help="Check auth status")

    # serve
    sv = sub.add_parser("serve", help="Start the BugForge web UI server")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8888)
    sv.add_argument("--no-browser", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "hunt":
        return asyncio.run(_cmd_hunt(args))
    elif args.command == "tools":
        return _cmd_tools(args)
    elif args.command == "scope":
        return _cmd_scope(args)
    elif args.command == "history":
        return _cmd_history(args)
    elif args.command == "pipelines":
        return _cmd_pipelines(args)
    elif args.command == "auth":
        return _cmd_auth(args)
    elif args.command == "serve":
        return _cmd_serve(args)

    return 0


async def _cmd_hunt(args) -> int:
    config = get_config()
    target = args.target.strip()
    target_type = detect_target_type(target)

    print(f"\n{c('╔══════════════════════════════════════════════╗', Colors.CYAN)}")
    print(f"{c('║  BUGFORGE v3 — APEX', Colors.BOLD)}{'':>27}{c('║', Colors.CYAN)}")
    print(f"{c('║', Colors.CYAN)} Target: {target} ({target_type.value}){'':>{36-len(target)-len(target_type.value)}}{c('║', Colors.CYAN)}")

    # Scope check
    scope = None
    if args.scope:
        scope = parse_brief(open(args.scope).read())
        ok, reason = scope.is_in_scope(target)
        status = c("validated ✓", Colors.GREEN) if ok else c("BLOCKED ✗", Colors.RED)
        print(f"{c('║', Colors.CYAN)} Scope: {status}{'':>{43-len(status)-8}}{c('║', Colors.CYAN)}")
        if not ok:
            print(f"{c('╚══════════════════════════════════════════════╝', Colors.CYAN)}")
            print(f"\n{c('[BLOCKED]', Colors.RED)} {reason}")
            return 2

    print(f"{c('╚══════════════════════════════════════════════╝', Colors.CYAN)}\n")

    # Setup
    bm = BinaryManager(str(config.bin_dir))
    engine = ParallelEngine(bm, max_concurrent=config.max_concurrent)
    db = Database(str(config.db_path))

    # Progress callback
    async def progress(tool_name, message):
        tag = c(f"[{tool_name}]", Colors.BLUE)
        print(f"  {tag:>25} {message}")

    # Run native modules in parallel with tools
    native_findings = []

    async def run_native():
        """Run native modules (JS analyzer, param miner, API discovery)."""
        await progress("native", "running JS analyzer, param miner, API discovery...")
        from .native.js_analyzer import analyze_js
        from .native.param_miner import mine_parameters
        from .native.api_discover import discover_apis

        # Normalize target for native modules
        native_target = normalize_target(target, target_type)
        domain = target if target_type == TargetType.DOMAIN else native_target

        # Ensure native_target has protocol for param_miner
        if not native_target.startswith(("http://", "https://")):
            native_target = f"https://{native_target}"

        # Run all native modules
        tasks = [
            asyncio.to_thread(analyze_js, native_target),
            asyncio.to_thread(discover_apis, native_target),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                continue
            native_findings.extend(r)

        # Param miner on the main target
        pm_findings = mine_parameters(native_target)
        native_findings.extend(pm_findings)

        await progress("native", f"✓ {len(native_findings)} native findings")

    # Run tool scan + native modules in parallel
    native_task = asyncio.create_task(run_native())

    if args.no_tools:
        # Skip external tools, only run native modules
        from bugforge.core.parallel import ScanResult, WaveResult
        scan_result = ScanResult(target=target, target_type=target_type)
        scan_result.wave1 = WaveResult(wave=1, assets_discovered=[target])
        scan_result.wave2 = WaveResult(wave=2)
    else:
        scan_result = await engine.full_scan(
            target, target_type,
            progress_cb=progress,
        )

    await native_task

    # Collect all findings
    all_findings = scan_result.all_findings + native_findings

    print(f"\n  {c('[correlate]', Colors.MAGENTA)} Analyzing {len(all_findings)} findings...")

    findings, chains = correlate(all_findings, target)
    findings = filter_fps(findings)
    findings = prioritize(findings, chains)
    chains = prioritize_chains(chains)

    # Verify criticals
    if not args.no_verify and config.verify_criticals:
        print(f"  {c('[verify]', Colors.YELLOW)} Re-testing {sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))} critical/high findings...")
        findings = await verify_criticals(findings)

    # Convert findings to dicts for storage
    findings_dicts = [_finding_to_dict(f) for f in findings]

    # Add dedup keys for diffing
    for fd in findings_dicts:
        fd["dedup_key"] = f"{fd.get('type')}:{fd.get('asset')}:{fd.get('title', '')[:50]}"

    # Save to DB
    print(f"  {c('[save]', Colors.GREEN)} Persisting to SQLite...")
    run_id = db.save_run(target, target_type.value,
                         assets_found=len(scan_result.wave1.assets_discovered if scan_result.wave1 else []),
                         findings_count=len(findings))
    db.save_findings(findings_dicts, run_id, target)
    if scan_result.wave1:
        db.save_assets(scan_result.wave1.assets_discovered, run_id, target)

    # Diff against last run
    diff = db.diff(findings_dicts, target)

    # Print results
    _print_results(findings, chains, diff, scan_result)

    # Generate report
    if args.report:
        _generate_report(findings, chains, target, args.report)
        print(f"\n  {c('[report]', Colors.GREEN)} Report saved to {args.report}")

    # JSON output
    if args.json:
        output = {
            "target": target,
            "type": target_type.value,
            "run_id": run_id,
            "elapsed": scan_result.total_elapsed,
            "findings": findings_dicts,
            "attack_chains": [_chain_to_dict(ch) for ch in chains],
            "diff": {"new": len(diff.new), "resolved": len(diff.resolved), "recurring": len(diff.recurring)},
        }
        with open(args.json, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"  {c('[json]', Colors.GREEN)} JSON saved to {args.json}")

    print(f"\n  {c('Database:', Colors.BOLD)} {config.db_path}")
    print(f"  {c('Total time:', Colors.BOLD)} {scan_result.total_elapsed:.1f}s\n")

    return 0


def _print_results(findings, chains, diff, scan_result):
    """Print colorized results to terminal."""
    print(f"\n{c('══════════════════════════════════════════════════', Colors.BOLD)}")
    print(f"  {c('RESULTS', Colors.BOLD)} — {len(findings)} actionable findings, {len(chains)} attack chains")
    print(f"{c('══════════════════════════════════════════════════', Colors.BOLD)}\n")

    # Attack chains first
    if chains:
        print(f"  {c('ATTACK CHAINS', Colors.RED)}\n")
        for i, ch in enumerate(chains, 1):
            conf_bar = "█" * int(ch.confidence * 10) + "░" * (10 - int(ch.confidence * 10))
            print(f"  {c(f'#{i}', Colors.RED)} {c(ch.title, Colors.BOLD)}")
            print(f"     Assets: {', '.join(ch.assets)}")
            print(f"     Confidence: {ch.confidence:.0%} [{conf_bar}]")
            print(f"     {ch.description[:200]}")
            print(f"     Findings: {', '.join(f.title[:40] for f in ch.findings[:5])}")
            print()

    # Findings
    sev_colors = {
        Severity.CRITICAL: Colors.RED,
        Severity.HIGH: Colors.YELLOW,
        Severity.MEDIUM: Colors.BLUE,
        Severity.LOW: Colors.GREEN,
        Severity.INFO: Colors.GREY,
    }
    sev_icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }

    for i, f in enumerate(findings[:30], 1):  # show top 30
        color = sev_colors.get(f.severity, Colors.GREY)
        icon = sev_icons.get(f.severity, "⚪")
        verified_tag = c(" ✓verified", Colors.GREEN) if f.verified else ""
        print(f"  {icon} {c(f.severity.value.upper(), color):<10} {f.title}")
        print(f"     Asset: {f.asset}  Source: {f.source}{verified_tag}")
        if f.url:
            print(f"     URL: {f.url[:80]}")
        if f.description:
            print(f"     {f.description[:150]}")
        if f.evidence:
            print(f"     Evidence: {f.evidence[:100]}")
        print()

    if len(findings) > 30:
        print(f"  ... and {len(findings) - 30} more (use --json for full output)\n")

    # Diff
    if diff.new or diff.resolved or diff.recurring:
        print(f"{c('══════════════════════════════════════════════════', Colors.BOLD)}")
        print(f"  {c('DIFF vs last run', Colors.CYAN)}")
        print(f"  {c(str(len(diff.new)), Colors.GREEN)} NEW"
              f" | {c(str(len(diff.resolved)), Colors.YELLOW)} RESOLVED"
              f" | {c(str(len(diff.recurring)), Colors.GREY)} recurring")
        print(f"{c('══════════════════════════════════════════════════', Colors.BOLD)}\n")


def _finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title, "severity": f.severity.value, "asset": f.asset,
        "source": f.source, "type": f.finding_type, "description": f.description,
        "evidence": f.evidence, "url": f.url, "confidence": f.confidence,
        "verified": f.verified, "extra": f.extra,
    }


def _chain_to_dict(ch: AttackChain) -> dict:
    return {
        "title": ch.title, "assets": ch.assets, "confidence": ch.confidence,
        "description": ch.description,
        "findings": [_finding_to_dict(f) for f in ch.findings],
    }


def _generate_report(findings, chains, target, path):
    """Generate a Markdown report from findings."""
    if not findings:
        with open(path, "w") as f:
            f.write(f"# BugForge Scan Report — {target}\n\nNo findings.\n")
        return

    lines = [f"# BugForge Scan Report — {target}", ""]
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  ")
    lines.append(f"**Findings:** {len(findings)}  ")
    lines.append(f"**Attack Chains:** {len(chains)}  ")
    lines.append("")

    if chains:
        lines.append("## Attack Chains\n")
        for i, ch in enumerate(chains, 1):
            lines.append(f"### Chain #{i}: {ch.title}\n")
            lines.append(f"**Confidence:** {ch.confidence:.0%}\n")
            lines.append(f"**Assets:** {', '.join(ch.assets)}\n")
            lines.append(f"{ch.description}\n")
            lines.append("**Component Findings:**\n")
            for f in ch.findings:
                lines.append(f"- {f.title} ({f.source})")
            lines.append("")

    lines.append("## Findings\n")
    for i, f in enumerate(findings, 1):
        sev = f.severity.value.upper()
        verified = " ✓ Verified" if f.verified else ""
        lines.append(f"### #{i} [{sev}] {f.title}{verified}\n")
        lines.append(f"**Asset:** `{f.asset}`  ")
        lines.append(f"**Source:** {f.source}  ")
        lines.append(f"**Confidence:** {f.confidence:.0%}\n")
        if f.url:
            lines.append(f"**URL:** `{f.url}`\n")
        if f.description:
            lines.append(f"**Description:** {f.description}\n")
        if f.evidence:
            lines.append(f"**Evidence:**\n```\n{f.evidence[:500]}\n```\n")
        lines.append("")

    lines.append("---")
    lines.append("*Generated with BugForge v3 — APEX*\n")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def _cmd_tools(args) -> int:
    config = get_config()
    bm = BinaryManager(str(config.bin_dir))

    if args.tools_cmd == "list":
        print(f"\n{c('BugForge Tool Arsenal', Colors.BOLD)}\n")
        for s in bm.status():
            icon = c("✓", Colors.GREEN) if s["installed"] else c("✗", Colors.YELLOW)
            path = s["path"] or "(not installed)"
            print(f"  {icon} {s['name']:<20} {path}")
        installed = sum(1 for s in bm.status() if s["installed"])
        print(f"\n{c('Installed:', Colors.BOLD)} {installed}/{len(bm.status())}")
        return 0

    elif args.tools_cmd == "install":
        print(f"{c('[*]', Colors.CYAN)} Installing {args.name}...")
        success = bm.install(args.name)
        if success:
            print(f"{c('[+]', Colors.GREEN)} {args.name} installed")
        else:
            print(f"{c('[!]', Colors.RED)} Failed to install {args.name}")
        return 0 if success else 1

    elif args.tools_cmd == "install-all":
        print(f"{c('[*]', Colors.CYAN)} Installing all tools...\n")
        results = bm.install_all()
        for name, success in results.items():
            icon = c("✓", Colors.GREEN) if success else c("✗", Colors.RED)
            print(f"  {icon} {name}")
        installed = sum(1 for v in results.values() if v)
        print(f"\n{c('Installed:', Colors.BOLD)} {installed}/{len(results)}")
        return 0

    elif args.tools_cmd == "add":
        loader = CustomToolLoader(str(config.home_dir / "tools"))
        path = loader.register(args.name, f"Custom tool: {args.name}", args.category,
                               args.binary, args.command, args.parser, args.timeout)
        print(f"{c('[+]', Colors.GREEN)} Custom tool '{args.name}' registered at {path}")
        return 0

    elif args.tools_cmd == "remove":
        loader = CustomToolLoader(str(config.home_dir / "tools"))
        if loader.delete(args.name):
            print(f"{c('[+]', Colors.GREEN)} Removed custom tool: {args.name}")
            return 0
        else:
            print(f"{c('[!]', Colors.RED)} Custom tool not found: {args.name}")
            return 1

    elif args.tools_cmd == "test":
        loader = CustomToolLoader(str(config.home_dir / "tools"))
        loader.load_all()
        tool = loader.get(args.name)
        if not tool:
            print(f"{c('[!]', Colors.RED)} Tool not found: {args.name}")
            return 1
        import subprocess
        cmd = loader.build_command(tool, args.target, {})
        print(f"{c('[*]', Colors.CYAN)} Testing: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=tool.timeout)
            findings = loader.parse_output(tool, r.stdout)
            print(f"{c('[+]', Colors.GREEN)} {len(findings)} findings")
            for f in findings[:10]:
                print(f"  {f}")
        except Exception as e:
            print(f"{c('[!]', Colors.RED)} Error: {e}")
        return 0

    elif args.tools_cmd == "list-custom":
        loader = CustomToolLoader(str(config.home_dir / "tools"))
        tools = loader.load_all()
        if not tools:
            print("No custom tools registered")
            return 0
        print(f"\n{c('Custom Tools', Colors.BOLD)}\n")
        for name, tool in tools.items():
            available = "✓" if tool.binary and os.path.isfile(tool.binary) else "✗"
            print(f"  {available} {name:<20} {tool.category:<15} {tool.binary or '(no binary)'}")
        return 0

    return 1


def _cmd_scope(args) -> int:
    scope = parse_brief(open(args.brief).read())
    rc = 0
    for t in args.target:
        ok, reason = scope.is_in_scope(t)
        tag = c("[IN SCOPE]", Colors.GREEN) if ok else c("[OUT OF SCOPE]", Colors.RED)
        print(f"{tag} {t}  — {reason}")
        if not ok:
            rc = 2
    return rc


def _cmd_history(args) -> int:
    config = get_config()
    db = Database(str(config.db_path))
    history = db.get_history(args.target)

    if not history:
        print(f"No scan history for {args.target}")
        return 0

    print(f"\n{c('Scan History for', Colors.BOLD)} {args.target}\n")
    for run in history:
        print(f"  Run {run['id']}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(run['completed_at']))}"
              f"  {run['assets_found']} assets  {run['findings_count']} findings")
    return 0


# ─── Pipeline commands ───

def _cmd_pipelines(args) -> int:
    config = get_config()
    loader = PipelineLoader(str(config.home_dir / "pipelines"))

    if args.pipelines_cmd == "list":
        pipes = loader.load_all()
        print(f"\n{c('BugForge Pipelines', Colors.BOLD)}\n")
        for name, pdef in pipes.items():
            stages = " → ".join(s.name for s in pdef.stages)
            print(f"  {c(name, Colors.CYAN):<25} {stages}")
            if pdef.description:
                print(f"    {c(pdef.description, Colors.GREY)}")
        print(f"\n{len(pipes)} pipelines available")
        return 0

    elif args.pipelines_cmd == "show":
        pdef = loader.get(args.name)
        if not pdef:
            print(f"{c('[!]', Colors.RED)} Pipeline not found: {args.name}")
            return 1
        print(f"\n{c(pdef.name, Colors.BOLD)}")
        print(f"  Description: {pdef.description}")
        print(f"  Target types: {', '.join(pdef.target_types)}")
        print(f"  Scope required: {pdef.scope_required}")
        print(f"\n  {c('Stages:', Colors.BOLD)}")
        for i, s in enumerate(pdef.stages, 1):
            tools = ", ".join(s.tools) if s.tools else "(none)"
            mode = "parallel" if s.parallel else "sequential"
            print(f"    {i}. {s.name} [{mode}] — tools: {tools}")
            if s.condition:
                print(f"       condition: {s.condition}")
            if s.options:
                print(f"       options: {json.dumps(s.options, indent=8)}")
        return 0

    elif args.pipelines_cmd == "delete":
        if loader.delete(args.name):
            print(f"{c('[+]', Colors.GREEN)} Deleted pipeline: {args.name}")
            return 0
        else:
            print(f"{c('[!]', Colors.RED)} Cannot delete (built-in or not found): {args.name}")
            return 1

    return 1


# ─── Auth commands ───

def _cmd_auth(args) -> int:
    config = get_config()
    auth = AuthManager(str(config.home_dir / "auth.json"))

    if args.auth_cmd == "setup":
        if auth.is_configured():
            print(f"{c('[!]', Colors.YELLOW)} Auth already configured. Use 'bugforge auth password' to change.")
            return 1
        import getpass
        username = input("Enter username: ").strip()
        if not username:
            print("Username required")
            return 1
        password = getpass.getpass("Enter password (6+ chars): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords don't match")
            return 1
        if auth.setup(username, password):
            print(f"{c('[+]', Colors.GREEN)} Auth configured. Web UI ready.")
            print(f"  Run: bugforge serve")
            return 0
        else:
            print(f"{c('[!]', Colors.RED)} Setup failed")
            return 1

    elif args.auth_cmd == "password":
        if not auth.is_configured():
            print(f"{c('[!]', Colors.RED)} Auth not configured. Run 'bugforge auth setup' first.")
            return 1
        import getpass
        username = input("Username: ").strip()
        old = getpass.getpass("Current password: ")
        new = getpass.getpass("New password (6+ chars): ")
        if auth.change_password(username, old, new):
            print(f"{c('[+]', Colors.GREEN)} Password changed")
            return 0
        else:
            print(f"{c('[!]', Colors.RED)} Password change failed")
            return 1

    elif args.auth_cmd == "status":
        if auth.is_configured():
            print(f"{c('[+]', Colors.GREEN)} Auth configured")
            return 0
        else:
            print(f"{c('[!]', Colors.YELLOW)} Auth not configured. Run 'bugforge auth setup' to enable login.")
            return 1

    return 1


# ─── Serve command ───

def _cmd_serve(args) -> int:
    from .web.app import serve
    serve(host=args.host, port=args.port, no_browser=args.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
