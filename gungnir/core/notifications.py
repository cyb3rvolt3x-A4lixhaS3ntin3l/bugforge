"""
Notification system for Gungnir.

Sends scan-completion and critical-finding alerts to webhooks:
  - Slack   (incoming webhook — `text` + `attachments`)
  - Discord (webhook — `content` + `embeds`)
  - Generic JSON webhook (`event` + `data`)

Uses only stdlib (urllib.request). Failures are logged but never crash
the scan. Configuration is loaded from ~/.gungnir/config.yaml under the
`notifications:` section.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional, Union
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError

from ..utils.logger import get_logger

log = get_logger()

# How long to wait for a webhook to respond before giving up (seconds).
DEFAULT_TIMEOUT = 10


@dataclass
class NotificationConfig:
    """Webhook endpoints to notify. All fields optional."""
    webhook_url: str = ""
    slack_webhook: str = ""
    discord_webhook: str = ""

    @property
    def has_any(self) -> bool:
        return bool(self.webhook_url or self.slack_webhook or self.discord_webhook)


# ── Finding coercion (avoid hard import cycle with correlate) ────────
def _severity_str(sev) -> str:
    # Severity is a str-Enum, so str(sev) gives the value already,
    # but be defensive for plain strings.
    try:
        return sev.value  # type: ignore[attr-defined]
    except AttributeError:
        return str(sev).lower() if sev else ""


def _finding_brief(finding: Union[dict, object]) -> dict:
    """Extract a small dict from a Finding object or raw dict."""
    if isinstance(finding, dict):
        return {
            "title": finding.get("title", ""),
            "severity": _severity_str(finding.get("severity", "")),
            "asset": finding.get("asset", finding.get("host", "")),
            "url": finding.get("url", ""),
            "source": finding.get("source", finding.get("_source", "")),
            "confidence": finding.get("confidence", finding.get("conf", 0.0)),
            "verified": bool(finding.get("verified", False)),
        }
    return {
        "title": getattr(finding, "title", ""),
        "severity": _severity_str(getattr(finding, "severity", "")),
        "asset": getattr(finding, "asset", ""),
        "url": getattr(finding, "url", ""),
        "source": getattr(finding, "source", ""),
        "confidence": getattr(finding, "confidence", 0.0),
        "verified": bool(getattr(finding, "verified", False)),
    }


# ── HTTP transport ────────────────────────────────────────────────────
def _post_json(url: str, payload: dict, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """POST JSON to a webhook. Returns True on 2xx, logs on failure."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "gungnir/notify"},
        )
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", resp.getcode())
            if 200 <= status < 300:
                return True
            log.warning("notify: %s returned HTTP %d", url, status)
            return False
    except HTTPError as exc:
        log.warning("notify: %s returned HTTP %d: %s", url, exc.code, exc.reason)
        return False
    except (URLError, TimeoutError, OSError) as exc:
        log.warning("notify: %s unreachable: %s", url, exc)
        return False
    except Exception as exc:  # never crash the scan
        log.warning("notify: %s unexpected error: %s", url, exc)
        return False


# ── Notifier ──────────────────────────────────────────────────────────
class Notifier:
    """Sends scan events to configured webhooks."""

    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or load_notification_config()

    # ── scan-complete ──────────────────────────────────────────────
    def notify_scan_complete(
        self,
        target: str,
        findings_count: int,
        chains_count: int,
        elapsed: float,
        run_id: str,
    ) -> None:
        """Notify all configured webhooks that a scan finished."""
        if not self.config.has_any:
            return

        summary = (
            f"🎯 Gungnir scan complete\n"
            f"Target: {target}\n"
            f"Findings: {findings_count}\n"
            f"Attack chains: {chains_count}\n"
            f"Elapsed: {elapsed:.1f}s\n"
            f"Run ID: {run_id}"
        )

        # Slack
        if self.config.slack_webhook:
            payload = {
                "text": f"Gungnir scan complete — `{target}`",
                "attachments": [{
                    "color": "#58a6ff",
                    "text": summary,
                    "fields": [
                        {"title": "Target", "value": target, "short": True},
                        {"title": "Run ID", "value": run_id, "short": True},
                        {"title": "Findings", "value": str(findings_count), "short": True},
                        {"title": "Chains", "value": str(chains_count), "short": True},
                        {"title": "Elapsed", "value": f"{elapsed:.1f}s", "short": True},
                    ],
                }],
            }
            _post_json(self.config.slack_webhook, payload)

        # Discord
        if self.config.discord_webhook:
            payload = {
                "content": f"Gungnir scan complete — `{target}`",
                "embeds": [{
                    "title": "Scan Summary",
                    "color": 0x58a6ff,
                    "description": summary,
                    "fields": [
                        {"name": "Target", "value": target, "inline": True},
                        {"name": "Run ID", "value": run_id, "inline": True},
                        {"name": "Findings", "value": str(findings_count), "inline": True},
                        {"name": "Chains", "value": str(chains_count), "inline": True},
                        {"name": "Elapsed", "value": f"{elapsed:.1f}s", "inline": True},
                    ],
                }],
            }
            _post_json(self.config.discord_webhook, payload)

        # Generic webhook
        if self.config.webhook_url:
            payload = {
                "event": "scan_complete",
                "data": {
                    "target": target,
                    "findings_count": findings_count,
                    "chains_count": chains_count,
                    "elapsed": elapsed,
                    "run_id": run_id,
                },
            }
            _post_json(self.config.webhook_url, payload)

    # ── single critical finding ──────────────────────────────────
    def notify_finding(self, finding: Union[dict, object]) -> None:
        """Notify all configured webhooks about a single critical finding."""
        if not self.config.has_any:
            return

        brief = _finding_brief(finding)
        title = brief["title"]
        sev = brief["severity"]
        asset = brief["asset"]
        url = brief["url"]
        verified = brief["verified"]

        text = (
            f"🚨 Critical finding\n"
            f"{title}\n"
            f"Severity: {sev}  |  Asset: {asset}  |  Verified: {verified}\n"
            f"URL: {url or '—'}"
        )

        # Slack
        if self.config.slack_webhook:
            color = "#f85149" if sev == "critical" else "#ff7b72"
            payload = {
                "text": f"🚨 Gungnir critical finding — `{asset}`",
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": text,
                    "fields": [
                        {"title": "Severity", "value": sev, "short": True},
                        {"title": "Verified", "value": str(verified), "short": True},
                        {"title": "Asset", "value": asset, "short": True},
                        {"title": "Source", "value": brief["source"] or "—", "short": True},
                    ],
                }],
            }
            _post_json(self.config.slack_webhook, payload)

        # Discord
        if self.config.discord_webhook:
            color = 0xf85149 if sev == "critical" else 0xff7b72
            payload = {
                "content": f"🚨 Gungnir critical finding — `{asset}`",
                "embeds": [{
                    "title": title,
                    "description": text,
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": sev, "inline": True},
                        {"name": "Verified", "value": str(verified), "inline": True},
                        {"name": "Asset", "value": asset, "inline": True},
                        {"name": "Source", "value": brief["source"] or "—", "inline": True},
                    ],
                }],
            }
            _post_json(self.config.discord_webhook, payload)

        # Generic webhook
        if self.config.webhook_url:
            payload = {
                "event": "critical_finding",
                "data": brief,
            }
            _post_json(self.config.webhook_url, payload)


# ── Config loading ───────────────────────────────────────────────────
def load_notification_config() -> NotificationConfig:
    """
    Load webhook config from ~/.gungnir/config.yaml (notifications: section).

    Returns an empty NotificationConfig if the file or section is absent, or
    if PyYAML is not installed (the file is optional, never crash here).
    """
    home = os.environ.get("GUNGNIR_HOME", os.path.join(os.path.expanduser("~"), ".gungnir"))
    path = os.path.join(home, "config.yaml")
    if not os.path.exists(path):
        return NotificationConfig()

    try:
        import yaml  # type: ignore
    except ImportError:
        log.debug("notify: PyYAML not installed; skipping config.yaml")
        return NotificationConfig()

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("notify: could not read %s: %s", path, exc)
        return NotificationConfig()

    section = raw.get("notifications", {}) if isinstance(raw, dict) else {}
    if not isinstance(section, dict):
        return NotificationConfig()

    return NotificationConfig(
        webhook_url=section.get("webhook_url", "") or "",
        slack_webhook=section.get("slack_webhook", section.get("slack", "")) or "",
        discord_webhook=section.get("discord_webhook", section.get("discord", "")) or "",
    )
