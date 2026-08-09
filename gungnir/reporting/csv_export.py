"""
CSV export for Gungnir findings.

Uses the stdlib `csv` module only. Produces a flat, machine-readable
table of every finding — convenient for importing into spreadsheets,
ticket trackers, or downstream analysis pipelines.

Accepts Finding objects or plain dicts (auto-converted) so it can be
fed directly from the correlate() output or from persisted DB rows.
"""
from __future__ import annotations

import csv
import io
from typing import List, Union

from ..intelligence.correlate import Finding
from ..intelligence.severity import Severity
from ..utils.logger import get_logger

log = get_logger()

# Column order (must stay stable — external consumers depend on it).
COLUMNS = [
    "title",
    "severity",
    "asset",
    "source",
    "type",
    "confidence",
    "verified",
    "url",
    "description",
    "evidence",
]


def _severity_str(sev: Union[Severity, str]) -> str:
    if isinstance(sev, Severity):
        return sev.value
    return str(sev).lower()


def _to_row(item: Union[Finding, dict]) -> dict:
    """Normalize dicts/objects into a flat row keyed by COLUMNS."""
    if isinstance(item, Finding):
        return {
            "title": item.title,
            "severity": _severity_str(item.severity),
            "asset": item.asset,
            "source": item.source,
            "type": item.finding_type,
            "confidence": item.confidence,
            "verified": item.verified,
            "url": item.url,
            "description": item.description,
            "evidence": item.evidence,
        }

    if not isinstance(item, dict):
        # opaque object — pull attributes defensively
        return {
            "title": getattr(item, "title", ""),
            "severity": _severity_str(getattr(item, "severity", Severity.INFO)),
            "asset": getattr(item, "asset", ""),
            "source": getattr(item, "source", ""),
            "type": getattr(item, "finding_type", getattr(item, "type", "")),
            "confidence": getattr(item, "confidence", 0.0),
            "verified": getattr(item, "verified", False),
            "url": getattr(item, "url", ""),
            "description": getattr(item, "description", ""),
            "evidence": getattr(item, "evidence", ""),
        }

    # dict — support both dataclass field names and DB/persisted aliases
    sev_raw = item.get("severity", item.get("sev", ""))
    return {
        "title": item.get("title", ""),
        "severity": _severity_str(sev_raw) if sev_raw else "",
        "asset": item.get("asset", item.get("host", "")),
        "source": item.get("source", item.get("_source", item.get("tool", ""))),
        "type": item.get("finding_type", item.get("type", "")),
        "confidence": item.get("confidence", item.get("conf", 0.0)),
        "verified": item.get("verified", False),
        "url": item.get("url", ""),
        "description": item.get("description", ""),
        "evidence": item.get("evidence", ""),
    }


def _fmt_value(col: str, val) -> str:
    """Stringify a value for CSV output."""
    if col == "confidence":
        try:
            return f"{float(val):.2f}"
        except (TypeError, ValueError):
            return ""
    if col == "verified":
        return "true" if val else "false"
    if val is None:
        return ""
    return str(val)


def export_csv_string(findings: List[Union[Finding, dict]]) -> str:
    """
    Render findings to a CSV string.

    Returns:
        A complete CSV document (header + rows) as a string.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(COLUMNS)

    for item in findings or []:
        row = _to_row(item)
        writer.writerow([_fmt_value(c, row.get(c, "")) for c in COLUMNS])

    return buf.getvalue()


def export_csv(findings: List[Union[Finding, dict]], filepath: str) -> None:
    """
    Write findings to a CSV file at `filepath`.

    Creates parent directories as needed. Failures are logged.
    """
    import os
    try:
        parent = os.path.dirname(os.path.abspath(filepath))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as fh:
            fh.write(export_csv_string(findings))
        log.debug("csv_export: wrote %d findings to %s", len(findings or []), filepath)
    except OSError as exc:
        log.error("csv_export: failed to write %s: %s", filepath, exc)
        raise
