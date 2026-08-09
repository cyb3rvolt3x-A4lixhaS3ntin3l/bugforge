"""
Backup file finder — probes a target for common backup artifacts, source
control leftovers, exposed config files, and editor metadata that may leak
secrets or source code.

No external tool dependency — pure Python (urllib only).
"""
from __future__ import annotations
import ssl
import urllib.request
import urllib.error
from typing import List
from ..utils.logger import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Probe lists
# ---------------------------------------------------------------------------

# Backup / swap / archive patterns appended to a base path or to the site root.
BACKUP_SUFFIXES = [
    ".bak", ".old", ".orig", ".save", ".copy", ".txt", ".backup", "~",
    ".swp", ".swo", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".7z",
    ".rar", ".gz",
]

# Source control leak paths.
SOURCE_CONTROL_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/store",
    "/.hg/store/data",
    "/.bzr/README",
    "/CVS/Root",
    "/CVS/Entries",
]

# Config / env files.
CONFIG_FILES = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.dev",
    "/.env.backup",
    "/.env.bak",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/config.php",
    "/configuration.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.txt",
    "/settings.php",
    "/local_settings.php",
    "/database.yml",
    "/app.config",
    "/web.config",
    "/config/database.yml",
    "/application.properties",
    "/application.yml",
    "/config/app.config",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/phpinfo.php",
    "/info.php",
]

# Editor / OS metadata files.
EDITOR_FILES = [
    "/.DS_Store",
    "/.idea/workspace.xml",
    "/.idea/modules.xml",
    "/.vscode/settings.json",
    "/.vscode/tasks.json",
    "/.vscode/launch.json",
    "/.project",
    "/.classpath",
    "/Thumbs.db",
    "/.npmrc",
    "/.yarnrc",
    "/.editorconfig",
    "/.dockerenv",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
]

# Common source file backups (built dynamically against the base path).
SOURCE_BACKUP_TEMPLATES = [
    "index.php", "index.html", "index.htm",
    "main.js", "app.js", "server.js", "api.py", "app.py",
    "login.php", "admin.php", "config.php", "db.php",
]


def find_backups(url: str) -> List[dict]:
    """
    Probe `url` for backup files, source control leaks, exposed configs, and
    editor metadata.

    Returns a list of finding dicts.
    """
    findings: List[dict] = []
    url = _normalize(url)
    base_path = url.rstrip("/")

    # 1. Source control leaks — highest signal.
    for path in SOURCE_CONTROL_PATHS:
        status, body, length = _probe(f"{base_path}{path}")
        if _is_hit(status, body, path):
            findings.append({
                "type": "backup_file",
                "severity": "critical",
                "description": (
                    f"Source control file exposed: {path}"
                ),
                "url": f"{base_path}{path}",
                "source": "backup_finder",
                "status": status,
                "length": length,
                "indicator": "source_control_leak",
            })

    # 2. Config / env files.
    for path in CONFIG_FILES:
        status, body, length = _probe(f"{base_path}{path}")
        if _is_hit(status, body, path):
            severity = "high" if path.startswith("/.env") else "medium"
            findings.append({
                "type": "backup_file",
                "severity": severity,
                "description": f"Config file exposed: {path}",
                "url": f"{base_path}{path}",
                "source": "backup_finder",
                "status": status,
                "length": length,
                "indicator": "config_exposed",
            })

    # 3. Editor / OS metadata.
    for path in EDITOR_FILES:
        status, body, length = _probe(f"{base_path}{path}")
        if _is_hit(status, body, path):
            findings.append({
                "type": "backup_file",
                "severity": "low",
                "description": f"Editor/metadata file exposed: {path}",
                "url": f"{base_path}{path}",
                "source": "backup_finder",
                "status": status,
                "length": length,
                "indicator": "editor_file_exposed",
            })

    # 4. Backup copies of common source files at the site root.
    for src in SOURCE_BACKUP_TEMPLATES:
        for suffix in BACKUP_SUFFIXES:
            candidate = f"{base_path}/{src}{suffix}"
            status, body, length = _probe(candidate)
            if _is_hit(status, body, candidate):
                findings.append({
                    "type": "backup_file",
                    "severity": "high",
                    "description": (
                        f"Backup file exposed: /{src}{suffix} — may contain "
                        "source code or secrets"
                    ),
                    "url": candidate,
                    "source": "backup_finder",
                    "status": status,
                    "length": length,
                    "indicator": "source_backup_exposed",
                })

    # 5. Bare root-level backup archives (e.g. /backup.zip, /site.tar.gz).
    for archive in [
        "/backup.zip", "/backups.zip", "/site.zip", "/www.zip",
        "/web.zip", "/html.zip", "/public.zip", "/archive.zip",
        "/backup.tar.gz", "/site.tar.gz", "/www.tar.gz", "/dump.tar.gz",
        "/backup.tar", "/database.sql", "/db.sql", "/dump.sql",
        "/backup.sql",
    ]:
        status, body, length = _probe(f"{base_path}{archive}")
        if _is_hit(status, body, archive):
            findings.append({
                "type": "backup_file",
                "severity": "critical",
                "description": (
                    f"Backup archive exposed: {archive} — likely contains "
                    "full source or database"
                ),
                "url": f"{base_path}{archive}",
                "source": "backup_finder",
                "status": status,
                "length": length,
                "indicator": "archive_exposed",
            })

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_hit(status, body: str, path: str) -> bool:
    """Decide whether a probe response counts as an exposed file."""
    if not status:
        return False
    # 2xx is a hit. 3xx to a login page is not a real file.
    if 200 <= status < 300:
        # Filter out generic landing pages (some servers return 200 for
        # everything via SPA routing).
        if _looks_like_landing(body):
            return False
        return True
    # Some servers return 403 for files that exist but are forbidden —
    # flag those as a softer signal.
    if status == 403 and not _looks_like_landing(body):
        return True
    return False


def _looks_like_landing(body: str) -> bool:
    """Heuristic: detect SPA catch-all / generic landing HTML."""
    if not body:
        return False
    head = body[:2000].lower()
    # Common SPA catch-all markers.
    spa_markers = ["<div id=\"root\"", "<div id=\"app\"", "<ng-app",
                   "vue", "react", "<noscript>you need to enable javascript"]
    return any(m in head for m in spa_markers)


def _probe(url: str, timeout: int = 8):
    """HEAD-ish probe; fall back to GET for servers that disallow HEAD.

    Returns (status, body_text, content_length).
    """
    status, body = _fetch(url, method="GET", timeout=timeout)
    if status is None:
        return None, "", 0
    return status, body, len(body)


def _fetch(url: str, method: str = "GET", timeout: int = 8):
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "Chrome/120.0 Safari/537.36",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # Only read the first 4KB for fingerprinting; we don't need the
            # whole archive to decide it exists.
            data = resp.read(4096)
            return resp.status, data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return None, ""


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target
