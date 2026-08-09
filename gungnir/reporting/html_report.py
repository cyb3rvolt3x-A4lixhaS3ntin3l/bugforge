"""
Standalone HTML report generator for Gungnir scan results.

Produces a single self-contained HTML document (inline CSS, no external
dependencies) with a dark theme matching the Gungnir web UI:

    bg      = #0d1117
    surface = #161b22
    accent  = #58a6ff

Accepts Finding objects or plain dicts (auto-converted) so it can be fed
directly from the correlate() output or from the persisted DB rows.
"""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from typing import Any, List, Optional, Union

from ..intelligence.correlate import Finding, AttackChain
from ..intelligence.severity import Severity
from ..utils.logger import get_logger

log = get_logger()

# ── Theme ──────────────────────────────────────────────────────────────────
BG = "#0d1117"
SURFACE = "#161b22"
SURFACE_HOVER = "#1f2630"
ACCENT = "#58a6ff"
TEXT = "#c9d1d9"
TEXT_MUTED = "#8b949e"
BORDER = "#30363d"

SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#ff7b72",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}


# ── Helpers ─────────────────────────────────────────────────────────────────
def _to_finding(item: Union[Finding, dict]) -> Finding:
    """Normalize dicts/objects into Finding instances (dict keys vary)."""
    if isinstance(item, Finding):
        return item

    if not isinstance(item, dict):
        # last-resort: treat as opaque object with attributes
        return Finding(
            title=getattr(item, "title", str(item)),
            severity=getattr(item, "severity", Severity.INFO),
            asset=getattr(item, "asset", ""),
            source=getattr(item, "source", ""),
            finding_type=getattr(item, "finding_type", getattr(item, "type", "")),
            description=getattr(item, "description", ""),
            evidence=getattr(item, "evidence", ""),
            url=getattr(item, "url", ""),
            confidence=getattr(item, "confidence", 0.0),
            verified=getattr(item, "verified", False),
            extra=getattr(item, "extra", {}),
        )

    # dict — support both dataclass field names and DB/persisted names
    sev_raw = item.get("severity", item.get("sev", Severity.INFO))
    if isinstance(sev_raw, Severity):
        severity = sev_raw
    else:
        severity = Severity._from_str(str(sev_raw)) if sev_raw else Severity.INFO

    return Finding(
        title=item.get("title", ""),
        severity=severity,
        asset=item.get("asset", item.get("host", "")),
        source=item.get("source", item.get("_source", item.get("tool", ""))),
        finding_type=item.get("finding_type", item.get("type", "")),
        description=item.get("description", ""),
        evidence=item.get("evidence", ""),
        url=item.get("url", ""),
        confidence=float(item.get("confidence", item.get("conf", 0.0)) or 0.0),
        verified=bool(item.get("verified", False)),
        extra=item.get("extra", {}) or {},
    )


def _chain_to_obj(item: Union[AttackChain, dict]) -> AttackChain:
    if isinstance(item, AttackChain):
        return item
    findings = [_to_finding(f) for f in item.get("findings", [])]
    return AttackChain(
        title=item.get("title", ""),
        assets=item.get("assets", []),
        findings=findings,
        confidence=float(item.get("confidence", 0.0)),
        description=item.get("description", ""),
    )


def _esc(text: Any) -> str:
    """HTML-escape, never raise on None."""
    if text is None:
        return ""
    return html.escape(str(text))


def _severity_str(sev: Union[Severity, str]) -> str:
    if isinstance(sev, Severity):
        return sev.value
    return str(sev).lower()


def _sev_badge(sev: Union[Severity, str]) -> str:
    name = _severity_str(sev)
    color = SEVERITY_COLORS.get(name, SEVERITY_COLORS["info"])
    return (f'<span class="badge" style="background:{color}22;color:{color};'
            f'border:1px solid {color}55;">{name.upper()}</span>')


def _confidence_bar(conf: float) -> str:
    pct = max(0, min(100, int(conf * 100)))
    color = "#58a6ff" if pct >= 70 else ("#d29922" if pct >= 40 else "#f85149")
    return (
        f'<div class="conf"><div class="conf-fill" style="width:{pct}%;background:{color};"></div>'
        f'<span>{pct}%</span></div>'
    )


def _verified_tag(verified: bool) -> str:
    if verified:
        return '<span class="tag verified">✓ Verified</span>'
    return '<span class="tag unverified">Unverified</span>'


# ── CSS ─────────────────────────────────────────────────────────────────────
_CSS = f"""
:root {{
  --bg: {BG};
  --surface: {SURFACE};
  --surface-hover: {SURFACE_HOVER};
  --accent: {ACCENT};
  --text: {TEXT};
  --text-muted: {TEXT_MUTED};
  --border: {BORDER};
}}
* {{ box-sizing: border-box; }}
body {{
  margin:0; padding:0;
  background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-size: 14px; line-height: 1.5;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
header {{ margin-bottom: 28px; }}
h1 {{ font-size: 26px; margin: 0 0 6px 0; color: var(--text); }}
h1 .accent {{ color: var(--accent); }}
h2 {{ font-size: 18px; margin: 32px 0 12px 0; color: var(--text);
     border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
.meta {{ color: var(--text-muted); font-size: 13px; margin-bottom: 4px; }}

/* Summary stats */
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
         gap: 12px; margin: 20px 0 8px 0; }}
.stat {{ background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 14px 16px; }}
.stat .num {{ font-size: 28px; font-weight: 700; line-height: 1; }}
.stat .lbl {{ color: var(--text-muted); font-size: 12px; margin-top: 6px;
             text-transform: uppercase; letter-spacing: 0.5px; }}
.stat.crit .num {{ color: #f85149; }}
.stat.high .num {{ color: #ff7b72; }}
.stat.med .num {{ color: #d29922; }}
.stat.low .num {{ color: #58a6ff; }}
.stat.chain .num {{ color: #bc8cff; }}

/* Attack chains */
.chain {{
  background: linear-gradient(90deg, rgba(248,81,73,0.10), var(--surface));
  border: 1px solid #f8514955; border-left: 4px solid #f85149;
  border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;
}}
.chain .title {{ color: #ff7b72; font-weight: 600; font-size: 15px; margin-bottom: 6px; }}
.chain .desc {{ color: var(--text); margin: 6px 0 10px 0; }}
.chain .meta-line {{ color: var(--text-muted); font-size: 12px; }}
.chain .conf-tag {{ color: #bc8cff; }}

/* Findings table */
table {{ width: 100%; border-collapse: collapse; background: var(--surface);
        border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
thead th {{ background: var(--bg); color: var(--text-muted); text-align: left;
           padding: 10px 12px; font-size: 12px; text-transform: uppercase;
           letter-spacing: 0.5px; border-bottom: 1px solid var(--border);
           cursor: pointer; user-select: none; white-space: nowrap; }}
thead th:hover {{ color: var(--accent); }}
thead th::after {{ content: " ⇅"; opacity: 0.4; font-size: 10px; }}
tbody tr {{ border-bottom: 1px solid var(--border); }}
tbody tr:hover {{ background: var(--surface-hover); }}
tbody td {{ padding: 12px; vertical-align: top; }}
.row-critical {{ background: rgba(248,81,73,0.06); }}
.row-high {{ background: rgba(255,123,114,0.04); }}

.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }}
.tag {{ font-size: 11px; padding: 1px 6px; border-radius: 4px; white-space: nowrap; }}
.tag.verified {{ color: #3fb950; border: 1px solid #3fb95055; }}
.tag.unverified {{ color: var(--text-muted); border: 1px solid var(--border); }}

.conf {{ position: relative; width: 80px; height: 16px;
        background: var(--bg); border: 1px solid var(--border); border-radius: 3px;
        overflow: hidden; }}
.conf .conf-fill {{ position: absolute; left: 0; top: 0; bottom: 0; opacity: 0.7; }}
.conf span {{ position: absolute; right: 4px; top: 0; font-size: 10px;
            color: var(--text); line-height: 16px; }}

a {{ color: var(--accent); text-decoration: none; word-break: break-all; }}
a:hover {{ text-decoration: underline; }}
.evidence {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 12px;
            color: var(--text-muted); white-space: pre-wrap; max-width: 340px;
            max-height: 120px; overflow: auto; }}
.foot {{ margin-top: 40px; color: var(--text-muted); font-size: 12px;
        text-align: center; border-top: 1px solid var(--border); padding-top: 16px; }}
.empty {{ color: var(--text-muted); font-style: italic; padding: 20px; text-align: center; }}
"""


# ── Sortable table JS (vanilla, no deps) ────────────────────────────────────
_JS = """
function sortTable(n) {
  const table = document.getElementById('findings-table');
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const ths = table.querySelectorAll('th');
  const dir = ths[n].dataset.dir === 'asc' ? 'desc' : 'asc';
  ths.forEach(t => t.dataset.dir = '');
  ths[n].dataset.dir = dir;
  const mult = dir === 'asc' ? 1 : -1;
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  rows.sort((a, b) => {
    let av = a.cells[n].dataset.sort || a.cells[n].textContent.trim();
    let bv = b.cells[n].dataset.sort || b.cells[n].textContent.trim();
    if (n === 1) { // severity column
      av = sevOrder[av.toLowerCase()] ?? 9; bv = sevOrder[bv.toLowerCase()] ?? 9;
    } else if (!isNaN(parseFloat(av)) && !isNaN(parseFloat(bv))) {
      av = parseFloat(av); bv = parseFloat(bv);
    } else {
      av = av.toLowerCase(); bv = bv.toLowerCase();
    }
    return av < bv ? -mult : av > bv ? mult : 0;
  });
  rows.forEach(r => tbody.appendChild(r));
}
"""


# ── Section builders ───────────────────────────────────────────────────────
def _build_stats(findings: List[Finding], chains: List[AttackChain]) -> str:
    sev_counts = Counter(_severity_str(f.severity) for f in findings)
    total = len(findings)
    cells = [
        ("Total", total, ""),
        ("Critical", sev_counts.get("critical", 0), "crit"),
        ("High", sev_counts.get("high", 0), "high"),
        ("Medium", sev_counts.get("medium", 0), "med"),
        ("Low", sev_counts.get("low", 0), "low"),
        ("Chains", len(chains), "chain"),
    ]
    blocks = "\n".join(
        f'<div class="stat {cls}"><div class="num">{n}</div><div class="lbl">{label}</div></div>'
        for label, n, cls in cells
    )
    return f'<div class="stats">{blocks}</div>'


def _build_chains(chains: List[AttackChain]) -> str:
    if not chains:
        return ""
    items = []
    for ch in chains:
        finding_titles = ", ".join(_esc(f.title) for f in ch.findings) or "—"
        assets = ", ".join(_esc(a) for a in ch.assets) or "—"
        conf_pct = int(ch.confidence * 100)
        items.append(
            f'<div class="chain">'
            f'<div class="title">⛓ {_esc(ch.title)}</div>'
            f'<div class="desc">{_esc(ch.description)}</div>'
            f'<div class="meta-line">Assets: {assets} &nbsp;·&nbsp; '
            f'Findings: {_esc(str(len(ch.findings)))} &nbsp;·&nbsp; '
            f'Confidence: <span class="conf-tag">{conf_pct}%</span></div>'
            f'<div class="meta-line">Linked: {finding_titles}</div>'
            f'</div>'
        )
    return (
        '<h2>⚠ Attack Chains</h2>'
        + "\n".join(items)
    )


def _build_findings_table(findings: List[Finding]) -> str:
    if not findings:
        return '<h2>Findings</h2><div class="empty">No findings recorded.</div>'

    # sort by severity desc by default
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings, key=lambda f: (sev_order.get(_severity_str(f.severity), 9), -f.confidence)
    )

    rows = []
    for i, f in enumerate(sorted_findings):
        sev_name = _severity_str(f.severity)
        row_class = f"row-{sev_name}" if sev_name in ("critical", "high") else ""
        url_cell = (
            f'<a href="{_esc(f.url)}" target="_blank" rel="noopener">{_esc(f.url)}</a>'
            if f.url else '<span class="meta">—</span>'
        )
        evidence = (
            f'<div class="evidence">{_esc(f.evidence)}</div>'
            if f.evidence else '<span class="meta">—</span>'
        )
        conf = _confidence_bar(f.confidence)
        rows.append(
            f'<tr class="{row_class}">'
            f'<td data-sort="{sev_name}">{_esc(f.title)}</td>'
            f'<td data-sort="{sev_name}">{_sev_badge(f.severity)}</td>'
            f'<td>{_esc(f.asset)}</td>'
            f'<td>{_esc(f.source)}</td>'
            f'<td data-sort="{f.confidence}">{conf}</td>'
            f'<td>{_verified_tag(f.verified)}</td>'
            f'<td>{url_cell}</td>'
            f'<td>{evidence}</td>'
            f'</tr>'
        )

    headers = ["Title", "Severity", "Asset", "Source", "Confidence",
               "Verified", "URL", "Evidence"]
    th = "\n".join(f'<th onclick="sortTable({i})">{h}</th>' for i, h in enumerate(headers))

    return (
        '<h2>Findings</h2>'
        '<table id="findings-table">'
        f'<thead><tr>{th}</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
    )


# ── Public API ──────────────────────────────────────────────────────────────
def generate_html_report(
    findings: List[Union[Finding, dict]],
    chains: List[Union[AttackChain, dict]],
    target: str,
    run_id: str,
) -> str:
    """
    Build a complete standalone HTML report.

    Args:
        findings: list of Finding objects or dicts (auto-converted).
        chains:   list of AttackChain objects or dicts (auto-converted).
        target:   the scanned target string.
        run_id:   the run identifier for this scan.

    Returns:
        A complete HTML document as a string.
    """
    norm_findings: List[Finding] = [_to_finding(f) for f in (findings or [])]
    norm_chains: List[AttackChain] = [_chain_to_obj(c) for c in (chains or [])]

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    crit_count = sum(1 for f in norm_findings if _severity_str(f.severity) == "critical")
    high_count = sum(1 for f in norm_findings if _severity_str(f.severity) == "high")

    risk_summary = "No critical or high findings." if not (crit_count or high_count) else (
        f"{crit_count} critical and {high_count} high severity issues require attention."
    )

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gungnir Report — {_esc(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span class="accent">Gungnir</span> Scan Report</h1>
    <div class="meta">Target: <strong>{_esc(target)}</strong></div>
    <div class="meta">Run ID: <code>{_esc(run_id)}</code> &nbsp;·&nbsp; Generated: {now}</div>
    <div class="meta">{risk_summary}</div>
  </header>

  {_build_stats(norm_findings, norm_chains)}

  {_build_chains(norm_chains)}

  {_build_findings_table(norm_findings)}

  <div class="foot">
    Generated by <span class="accent">Gungnir</span> — this report is self-contained and contains no external dependencies.
  </div>
</div>
<script>{_JS}</script>
</body>
</html>
"""
    log.debug("html_report: generated for %s (%d findings, %d chains)",
              target, len(norm_findings), len(norm_chains))
    return body
