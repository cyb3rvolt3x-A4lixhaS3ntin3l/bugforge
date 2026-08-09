"""Tests for the new I/O modules: html_report, csv_export, notifications, batch."""
import os
import tempfile

from gungnir.intelligence.correlate import Finding, AttackChain
from gungnir.intelligence.severity import Severity
from gungnir.reporting.html_report import generate_html_report
from gungnir.reporting.csv_export import export_csv, export_csv_string
from gungnir.core.notifications import (
    NotificationConfig, Notifier, load_notification_config, _post_json,
)
from gungnir.core.batch import batch_scan, batch_scan_async
from gungnir.core.parallel import ScanResult


def _sample_findings():
    return [
        Finding(
            title="Reflected XSS", severity=Severity.HIGH, asset="app.example.com",
            source="dalfox", finding_type="xss", url="https://app.example.com/s?q=x",
            evidence="alert fired", confidence=0.9, verified=True,
            description="Reflected XSS via q param",
        ),
        Finding(
            title="Leaked AWS key", severity=Severity.CRITICAL, asset="cdn.example.com",
            source="trufflehog", finding_type="secret", url="https://cdn.example.com/app.js",
            evidence="AKIA1234", confidence=0.95, verified=True,
        ),
        {  # dict form (DB/persisted)
            "title": "Open CORS", "severity": "medium", "asset": "api.example.com",
            "source": "native", "type": "cors", "url": "https://api.example.com",
            "confidence": 0.6, "verified": False, "description": "ACAO reflects origin",
            "evidence": "ACAO: *",
        },
    ]


def _sample_chains(findings):
    return [
        AttackChain(
            title="SSRF -> metadata -> creds", assets=["app.example.com"],
            findings=[findings[1]], confidence=0.9,
            description="SSRF lets attacker reach metadata and steal creds",
        ),
        {  # dict form
            "title": "git+secret chain", "assets": ["x.com"],
            "findings": [findings[0]], "confidence": 0.5,
            "description": "git exposed plus secret",
        },
    ]


# ── HTML ──────────────────────────────────────────────────────────────────────
def test_html_report_basic_structure():
    fs = _sample_findings()
    html = generate_html_report(fs, _sample_chains(fs), "example.com", "run-42")
    assert html.startswith("<!DOCTYPE html>")
    assert "example.com" in html and "run-42" in html
    assert "Reflected XSS" in html and "Leaked AWS key" in html


def test_html_report_dark_theme_colors():
    html = generate_html_report(_sample_findings(), [], "t", "r")
    assert "#0d1117" in html
    assert "#161b22" in html
    assert "#58a6ff" in html


def test_html_report_stats_counts():
    fs = _sample_findings()
    html = generate_html_report(fs, _sample_chains(fs), "t", "r")
    assert "Total" in html and "Critical" in html and "High" in html
    assert "Medium" in html and "Chains" in html
    # 1 critical, 1 high, 1 medium, 3 total, 2 chains
    assert "3" in html  # total findings


def test_html_report_handles_dicts_and_objects():
    fs = _sample_findings()
    html = generate_html_report(fs, _sample_chains(fs), "t", "r")
    assert "Open CORS" in html  # dict finding
    assert "git+secret chain" in html  # dict chain


def test_html_report_empty_inputs():
    html = generate_html_report([], [], "t", "r")
    assert "No findings recorded." in html
    assert "Attack Chains" not in html  # no chains section when empty


def test_html_report_self_contained_no_external_deps():
    html = generate_html_report(_sample_findings(), [], "t", "r")
    assert "<style>" in html and "</style>" in html
    assert "<script>" in html
    # no external link/script tags
    assert 'src="http' not in html
    assert 'href="http' not in html or 'target="_blank"' in html  # finding URLs are ok


# ── CSV ───────────────────────────────────────────────────────────────────────
def test_csv_string_header_and_rows():
    fs = _sample_findings()
    out = export_csv_string(fs)
    lines = out.strip().splitlines()
    assert lines[0] == "title,severity,asset,source,type,confidence,verified,url,description,evidence"
    assert len(lines) == 4  # header + 3 rows
    assert "Reflected XSS" in lines[1]
    assert "high" in lines[1]
    assert "true" in lines[1]
    assert "AKIA1234" in lines[2]


def test_csv_dict_findings_converted():
    out = export_csv_string(_sample_findings())
    assert "Open CORS" in out
    assert "cors" in out


def test_csv_file_write_creates_dirs():
    fs = _sample_findings()
    d = tempfile.mkdtemp()
    p = os.path.join(d, "nested", "dir", "out.csv")
    export_csv(fs, p)
    assert os.path.exists(p)
    with open(p) as fh:
        content = fh.read()
    assert content.startswith("title,severity")


def test_csv_empty_findings():
    out = export_csv_string([])
    lines = out.strip().splitlines()
    assert len(lines) == 1  # header only
    assert lines[0].startswith("title")


# ── Notifications ──────────────────────────────────────────────────────────────
def test_notification_config_has_any():
    assert not NotificationConfig().has_any
    assert NotificationConfig(webhook_url="http://x").has_any
    assert NotificationConfig(slack_webhook="http://x").has_any
    assert NotificationConfig(discord_webhook="http://x").has_any


def test_notifier_no_config_is_noop():
    n = Notifier(NotificationConfig())
    # should not raise even with no webhooks configured
    n.notify_scan_complete("example.com", 3, 1, 12.3, "run-42")
    n.notify_finding(_sample_findings()[1])


def test_notifier_with_config_does_not_crash_on_bad_url():
    n = Notifier(NotificationConfig(slack_webhook="http://127.0.0.1:1/no-such",
                                   discord_webhook="http://127.0.0.1:1/no-such",
                                   webhook_url="http://127.0.0.1:1/no-such"))
    # All posts fail but must not raise.
    n.notify_scan_complete("example.com", 3, 1, 12.3, "run-42")
    n.notify_finding(_sample_findings()[1])


def test_load_notification_config_missing_file():
    os.environ["GUNGNIR_HOME"] = tempfile.mkdtemp()
    cfg = load_notification_config()
    assert isinstance(cfg, NotificationConfig)
    assert not cfg.has_any


def test_post_json_returns_false_on_unreachable():
    assert _post_json("http://127.0.0.1:1/x", {"a": 1}, timeout=1) is False


# ── Batch ──────────────────────────────────────────────────────────────────────
def test_batch_scan_empty_targets():
    assert batch_scan([]) == {}


def test_batch_scan_async_empty():
    import asyncio
    assert asyncio.new_event_loop().run_until_complete(batch_scan_async([])) == {}
