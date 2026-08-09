"""
Async SQLite database — lightweight persistence for findings, assets, and runs.
Enables diffing between scans: "5 new findings since last run".
"""
from __future__ import annotations
import sqlite3
import json
import time
import uuid
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path
from ..utils.logger import get_logger

log = get_logger()

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT,
    started_at REAL,
    completed_at REAL,
    assets_found INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    summary_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    asset TEXT,
    type TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    evidence TEXT,
    url TEXT,
    source TEXT,
    confidence REAL DEFAULT 0.5,
    verified INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    status TEXT DEFAULT 'new',
    extra_json TEXT,
    dedup_key TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    value TEXT NOT NULL,
    type TEXT,
    tech_json TEXT,
    status_code INTEGER,
    first_seen REAL,
    last_seen REAL,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target);
"""


@dataclass
class DiffResult:
    new: List[dict] = field(default_factory=list)
    resolved: List[dict] = field(default_factory=list)
    recurring: List[dict] = field(default_factory=list)


class Database:
    """Async-friendly SQLite database. Uses sync sqlite3 (fast enough for our scale)."""

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def save_run(self, target: str, target_type: str, assets_found: int = 0,
                 findings_count: int = 0, summary: dict = None) -> str:
        """Save a run record. Returns run_id."""
        run_id = str(uuid.uuid4())[:12]
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO runs (id, target, target_type, started_at, completed_at, "
                "assets_found, findings_count, summary_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, target, target_type, now, now, assets_found, findings_count,
                 json.dumps(summary or {}))
            )
            conn.commit()
        return run_id

    def save_findings(self, findings: List[dict], run_id: str, target: str):
        """Save findings to the database."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            for f in findings:
                dedup_key = f"{f.get('type', 'unknown')}:{f.get('asset', target)}:{f.get('title', '')[:50]}"
                finding_id = str(uuid.uuid4())[:12]
                conn.execute(
                    "INSERT INTO findings (id, run_id, target, asset, type, severity, title, "
                    "description, evidence, url, source, confidence, verified, first_seen, "
                    "last_seen, status, extra_json, dedup_key) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (finding_id, run_id, target,
                     f.get("asset", target), f.get("type", ""), f.get("severity", ""),
                     f.get("title", ""), f.get("description", ""), f.get("evidence", ""),
                     f.get("url", ""), f.get("source", ""), f.get("confidence", 0.5),
                     1 if f.get("verified") else 0, now, now, f.get("status", "new"),
                     json.dumps(f.get("extra", {})), dedup_key)
                )
            conn.commit()

    def save_assets(self, assets: List[str], run_id: str, target: str):
        """Save discovered assets."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            for asset in assets:
                asset_id = str(uuid.uuid4())[:12]
                conn.execute(
                    "INSERT INTO assets (id, run_id, target, value, type, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (asset_id, run_id, target, asset, "subdomain", now, now)
                )
            conn.commit()

    def get_previous_findings(self, target: str) -> List[dict]:
        """Get findings from the previous run for a target."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            # Get the most recent run before now
            runs = conn.execute(
                "SELECT id FROM runs WHERE target = ? ORDER BY completed_at DESC LIMIT 1",
                (target,)
            ).fetchall()

            if not runs:
                return []

            # Get findings from the second-to-last run (the one before current)
            runs = conn.execute(
                "SELECT id FROM runs WHERE target = ? ORDER BY completed_at DESC LIMIT 2",
                (target,)
            ).fetchall()

            if len(runs) < 2:
                return []

            prev_run_id = runs[1]["id"]
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (prev_run_id,)
            ).fetchall()

            return [dict(r) for r in rows]

    def diff(self, current_findings: List[dict], target: str) -> DiffResult:
        """Diff current findings against the previous run."""
        previous = self.get_previous_findings(target)

        prev_keys = {f.get("dedup_key", f"{f.get('type')}:{f.get('asset')}:{f.get('title', '')[:50]}")
                     for f in previous}
        curr_keys = {f.get("dedup_key", f"{f.get('type')}:{f.get('asset')}:{f.get('title', '')[:50]}")
                     for f in current_findings}

        new = [f for f in current_findings if f.get("dedup_key") not in prev_keys]
        resolved = [f for f in previous if f.get("dedup_key") not in curr_keys]
        recurring = [f for f in current_findings if f.get("dedup_key") in prev_keys]

        return DiffResult(new=new, resolved=resolved, recurring=recurring)

    def get_history(self, target: str) -> List[dict]:
        """Get run history for a target."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM runs WHERE target = ? ORDER BY completed_at DESC",
                (target,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_all_findings(self, target: str) -> List[dict]:
        """Get all findings for a target across all runs."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM findings WHERE target = ? ORDER BY last_seen DESC",
                (target,)
            ).fetchall()
            return [dict(r) for r in rows]
