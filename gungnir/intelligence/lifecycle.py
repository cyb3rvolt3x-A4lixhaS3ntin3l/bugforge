"""
Finding lifecycle management — tracks every finding from discovery to
resolution and prevents re-alerting on recurring false positives.

A finding moves through a well-defined status pipeline:

    NEW -> TRIAGED -> REPORTED -> ACCEPTED -> RESOLVED
                         |          |
                         +-> DUPLICATE / REJECTED / OUT_OF_SCOPE

The two terminal-ish "do not bother me again" states are REJECTED,
DUPLICATE and OUT_OF_SCOPE: when such a finding reappears in a later scan we
keep the old status and stay quiet. The only re-alert case is REGRESSED — a
previously RESOLVED finding that came back.

Cross-run identity
------------------
The ``findings`` table assigns a fresh UUID to every finding on every run, so a
finding_id is *not* stable across scans. The stable identity is ``dedup_key``
(``type:asset:title``), which the Database already computes. The lifecycle
tables therefore store ``dedup_key`` alongside ``finding_id`` so a recurring
finding can inherit the status of its predecessor.

Schema (created lazily, never touches db.py)
-------------------------------------------
    finding_lifecycle(finding_id, dedup_key, status, note, changed_at, changed_by)
    finding_notes(finding_id, note, created_at)

Both use ``CREATE TABLE IF NOT EXISTS`` so existing databases are unaffected.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict

from ..storage.db import Database
from ..utils.logger import get_logger

log = get_logger()


# ---------------------------------------------------------------------------
# Schema (private to this module; created on first use)
# ---------------------------------------------------------------------------

_LIFECYCLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_lifecycle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    dedup_key TEXT,
    status TEXT NOT NULL,
    note TEXT,
    changed_at REAL NOT NULL,
    changed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_finding ON finding_lifecycle(finding_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_dedup ON finding_lifecycle(dedup_key);
CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON finding_lifecycle(status);

CREATE TABLE IF NOT EXISTS finding_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_finding ON finding_notes(finding_id);
"""

# Statuses that, once set, suppress re-alerting on recurrence. The finding is
# considered "closed" from an alerting standpoint even if it shows up again.
_SUPPRESSED_STATUSES = frozenset(
    {
        "rejected",
        "duplicate",
        "out_of_scope",
    }
)


class FindingStatus(str, Enum):
    """Lifecycle states for a finding.

    Values are lowercase so they can be written directly into the existing
    ``findings.status`` column (whose default is already ``'new'``).
    """

    NEW = "new"
    TRIAGED = "triaged"
    REPORTED = "reported"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    OUT_OF_SCOPE = "out_of_scope"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "FindingStatus":
        """Best-effort parse; unknown/empty values fall back to NEW."""
        if not value:
            return cls.NEW
        try:
            return cls(value)
        except ValueError:
            # tolerate uppercase or whitespace
            norm = str(value).strip().lower()
            for member in cls:
                if member.value == norm or member.name.lower() == norm:
                    return member
            log.debug(f"Unknown finding status {value!r}; defaulting to NEW")
            return cls.NEW


@dataclass
class LifecycleSummary:
    """Result of running LifecycleManager.process_scan over a fresh scan."""

    target: str
    total: int = 0
    new: int = 0
    regressed: int = 0
    suppressed: int = 0  # recurring findings kept in a suppressed state
    retained: int = 0  # recurring findings kept in an active (in-progress) state
    updates: List[dict] = field(default_factory=list)


def _dedup_key(finding: dict, target: str = "") -> str:
    """Compute the canonical dedup key for a finding dict.

    Mirrors Database.save_findings' key derivation so lifecycle state matches
    across runs even though finding_id changes every run.
    """
    if finding.get("dedup_key"):
        return finding["dedup_key"]
    ftype = finding.get("type", "unknown")
    asset = finding.get("asset", target) or target
    title = finding.get("title", "")
    return f"{ftype}:{asset}:{title[:50]}"


class FindingLifecycle:
    """Per-finding status tracking and history, backed by the shared Database.

    The lifecycle tables live in the same SQLite file as the rest of Gungnir's
    data. They are created lazily on first use and never modify the existing
    schema.
    """

    def __init__(self, db: Database):
        self.db = db
        self._init_schema()

    # -- schema ---------------------------------------------------------------

    def _init_schema(self) -> None:
        with sqlite3.connect(self.db.db_path) as conn:
            conn.executescript(_LIFECYCLE_SCHEMA)
            conn.commit()

    # -- helpers --------------------------------------------------------------

    def _get_dedup_key(self, finding_id: str) -> Optional[str]:
        """Look up the dedup_key for a finding from the findings table, then
        fall back to the lifecycle history."""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT dedup_key FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row and row["dedup_key"]:
                return row["dedup_key"]
            # fall back to whatever the lifecycle recorded
            row = conn.execute(
                "SELECT dedup_key FROM finding_lifecycle WHERE finding_id = ? "
                "ORDER BY changed_at DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
            return row["dedup_key"] if row else None

    def _get_target(self, finding_id: str) -> Optional[str]:
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT target FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return row["target"] if row else None

    # -- public API -----------------------------------------------------------

    def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
        note: str = "",
        changed_by: str = "system",
    ) -> bool:
        """Record a status transition for a finding.

        Appends a row to ``finding_lifecycle`` (full history is preserved) and
        mirrors the latest status into ``findings.status`` for fast filtering.
        Returns True on success, False if the finding is unknown.
        """
        dedup_key = self._get_dedup_key(finding_id)
        if dedup_key is None:
            # No dedup_key means we have no record of this finding at all; we
            # still record the lifecycle event so the caller's intent isn't
            # lost, but warn that the finding is orphaned.
            log.debug(
                f"update_status: finding {finding_id} has no dedup_key "
                "(not yet persisted?); recording lifecycle event anyway"
            )

        now = time.time()
        status_value = status.value if isinstance(status, FindingStatus) else str(status)
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    "INSERT INTO finding_lifecycle "
                    "(finding_id, dedup_key, status, note, changed_at, changed_by) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (finding_id, dedup_key, status_value, note, now, changed_by),
                )
                # Mirror into the findings table if the row exists.
                conn.execute(
                    "UPDATE findings SET status = ? WHERE id = ?",
                    (status_value, finding_id),
                )
                conn.commit()
            log.info(
                f"lifecycle: {finding_id} -> {status_value}"
                + (f" ({note})" if note else "")
            )
            return True
        except sqlite3.Error as e:
            log.error(f"lifecycle: failed to update {finding_id}: {e}")
            return False

    def get_status(self, finding_id: str) -> FindingStatus:
        """Return the current status of a finding.

        Priority: latest ``finding_lifecycle`` row > ``findings.status`` > NEW.
        """
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT status FROM finding_lifecycle WHERE finding_id = ? "
                "ORDER BY changed_at DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
            if row:
                return FindingStatus.from_str(row["status"])

            row = conn.execute(
                "SELECT status FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row:
                return FindingStatus.from_str(row["status"])
        return FindingStatus.NEW

    def get_history(self, finding_id: str) -> List[dict]:
        """Return the full status-change history (oldest first)."""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT finding_id, dedup_key, status, note, changed_at, changed_by "
                "FROM finding_lifecycle WHERE finding_id = ? ORDER BY changed_at ASC",
                (finding_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def find_by_status(
        self, status: FindingStatus, target: Optional[str] = None
    ) -> List[dict]:
        """Return all findings currently in ``status``.

        A finding's *current* status is the latest lifecycle row if any,
        otherwise its ``findings.status`` column. Optionally filter by target.
        """
        status_value = (
            status.value if isinstance(status, FindingStatus) else str(status)
        )
        results: List[dict] = []
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # 1) Findings that have lifecycle history.
            latest_rows = conn.execute(
                "SELECT l.finding_id, l.status, l.changed_at, f.* "
                "FROM finding_lifecycle l "
                "JOIN findings f ON f.id = l.finding_id "
                "WHERE l.changed_at = ("
                "    SELECT MAX(l2.changed_at) FROM finding_lifecycle l2 "
                "    WHERE l2.finding_id = l.finding_id"
                ") "
                + ("AND f.target = ? " if target else "")
                + "ORDER BY l.changed_at DESC",
                ((target,) if target else ()),
            ).fetchall()

            seen_ids = set()
            for r in latest_rows:
                if r["status"] == status_value:
                    results.append(dict(r))
                seen_ids.add(r["finding_id"])

            # 2) Findings with NO lifecycle history whose findings.status
            #    column matches (e.g. brand-new findings never lifecycle'd).
            if not seen_ids:
                placeholders = ""
                params: tuple = (status_value,)
            else:
                placeholders = (
                    "AND id NOT IN ("
                    + ",".join("?" for _ in seen_ids)
                    + ") "
                )
                params = (status_value, *seen_ids)

            sql = (
                "SELECT * FROM findings WHERE status = ? "
                + placeholders
                + ("AND target = ? " if target else "")
                + "ORDER BY last_seen DESC"
            )
            params = params + ((target,) if target else ())
            for r in conn.execute(sql, params).fetchall():
                results.append(dict(r))

        return results

    def add_note(self, finding_id: str, note: str) -> bool:
        """Attach a free-form note to a finding."""
        if not note:
            return False
        now = time.time()
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.execute(
                    "INSERT INTO finding_notes (finding_id, note, created_at) "
                    "VALUES (?, ?, ?)",
                    (finding_id, note, now),
                )
                conn.commit()
            return True
        except sqlite3.Error as e:
            log.error(f"lifecycle: failed to add note to {finding_id}: {e}")
            return False

    def get_notes(self, finding_id: str) -> List[dict]:
        """Return all notes for a finding (oldest first)."""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT finding_id, note, created_at FROM finding_notes "
                "WHERE finding_id = ? ORDER BY created_at ASC",
                (finding_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_duplicate(self, finding_id: str, original_finding_id: str) -> bool:
        """Mark ``finding_id`` as a duplicate of ``original_finding_id``.

        Records a DUPLICATE status transition with a referencing note and
        stashes the link in the finding's ``extra_json`` for downstream tools.
        """
        ok = self.update_status(
            finding_id,
            FindingStatus.DUPLICATE,
            note=f"Duplicate of finding {original_finding_id}",
        )
        if not ok:
            return False
        # Persist the cross-reference into extra_json for convenience.
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT extra_json FROM findings WHERE id = ?", (finding_id,)
                ).fetchone()
                extra: dict = {}
                if row and row["extra_json"]:
                    try:
                        extra = json.loads(row["extra_json"]) or {}
                    except (json.JSONDecodeError, TypeError):
                        extra = {}
                extra["duplicate_of"] = original_finding_id
                conn.execute(
                    "UPDATE findings SET extra_json = ? WHERE id = ?",
                    (json.dumps(extra), finding_id),
                )
                conn.commit()
            return True
        except sqlite3.Error as e:
            log.error(f"lifecycle: failed to record duplicate link: {e}")
            return False

    def check_regression(
        self, finding_id: str, current_findings: List[dict], target: str = ""
    ) -> bool:
        """Detect whether a previously RESOLVED finding has reappeared.

        Returns True (and flips the finding to REGRESSED) when the finding's
        dedup_key is present in ``current_findings`` and its current status is
        RESOLVED. Returns False otherwise. Non-RESOLVED findings never regress.
        """
        current_status = self.get_status(finding_id)
        if current_status != FindingStatus.RESOLVED:
            return False

        dedup_key = self._get_dedup_key(finding_id)
        if not dedup_key:
            return False

        current_keys = {_dedup_key(f, target) for f in current_findings}
        if dedup_key in current_keys:
            log.warning(
                f"lifecycle: REGRESSION detected for {finding_id} "
                f"(dedup_key={dedup_key})"
            )
            self.update_status(
                finding_id,
                FindingStatus.REGRESSED,
                note="Finding reappeared after being marked RESOLVED",
            )
            return True
        return False

    # -- cross-run correlation helpers ---------------------------------------

    def _latest_status_by_dedup(self, dedup_key: str) -> Optional[FindingStatus]:
        """Return the most recent status ever recorded for a dedup_key across
        all finding_ids that shared it."""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT status FROM finding_lifecycle WHERE dedup_key = ? "
                "ORDER BY changed_at DESC LIMIT 1",
                (dedup_key,),
            ).fetchone()
            if row:
                return FindingStatus.from_str(row["status"])
        return None


class LifecycleManager:
    """Scan-integration helper that assigns sane lifecycle statuses after a
    scan runs and prevents re-alerting on recurring false positives.

    Wire it up after findings are persisted:

        mgr = LifecycleManager(db)
        summary = mgr.process_scan(target, current_findings)

    Policy (applied per current finding, keyed by dedup_key):

        * never seen before                -> NEW            (alert)
        * previously RESOLVED, reappeared  -> REGRESSED      (alert)
        * previously REJECTED/DUPLICATE/
          OUT_OF_SCOPE, reappeared         -> keep status    (suppress)
        * previously in-progress (TRIAGED/
          REPORTED/ACCEPTED/REGRESSED)     -> keep status    (retain)
    """

    def __init__(self, db: Database):
        self.db = db
        self.lifecycle = FindingLifecycle(db)

    def process_scan(
        self, target: str, current_findings: List[dict]
    ) -> LifecycleSummary:
        """Assign lifecycle statuses to freshly-saved findings.

        ``current_findings`` are the findings dicts produced by this scan.
        Each must carry (or allow derivation of) a dedup_key. The findings are
        expected to already be persisted to the ``findings`` table (so we can
        map dedup_key -> finding_id for this run); if a finding isn't in the DB
        yet we still record its lifecycle state keyed by dedup_key alone.
        """
        summary = LifecycleSummary(target=target, total=len(current_findings))

        # Map dedup_key -> finding_id for findings persisted in this run.
        key_to_id: Dict[str, str] = {}
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, dedup_key FROM findings WHERE target = ? "
                "ORDER BY last_seen DESC",
                (target,),
            ).fetchall()
        # Most recent finding_id per dedup_key wins (this run's IDs are newest).
        for r in rows:
            key = r["dedup_key"]
            if key and key not in key_to_id:
                key_to_id[key] = r["id"]

        for finding in current_findings:
            dkey = _dedup_key(finding, target)
            finding_id = key_to_id.get(dkey)
            if not finding_id:
                # Not persisted yet — record by dedup_key only, skip update of
                # findings table (the row doesn't exist to update).
                log.debug(
                    f"lifecycle: no persisted finding_id for dedup_key={dkey}; "
                    "recording by dedup_key only"
                )
                finding_id = finding.get("id") or dkey

            prev_status = self.lifecycle._latest_status_by_dedup(dkey)

            if prev_status is None:
                # Brand new finding.
                self.lifecycle.update_status(
                    finding_id, FindingStatus.NEW, note="First observed"
                )
                summary.new += 1
                summary.updates.append(
                    {"finding_id": finding_id, "dedup_key": dkey, "action": "new"}
                )
            elif prev_status == FindingStatus.RESOLVED:
                # Resolved but back again -> regression. Alert.
                self.lifecycle.update_status(
                    finding_id,
                    FindingStatus.REGRESSED,
                    note="Previously RESOLVED; reappeared in new scan",
                )
                summary.regressed += 1
                summary.updates.append(
                    {
                        "finding_id": finding_id,
                        "dedup_key": dkey,
                        "action": "regressed",
                    }
                )
            elif prev_status.value in _SUPPRESSED_STATUSES:
                # Recurring false positive / dup / OOS — keep quiet.
                self.lifecycle.update_status(
                    finding_id,
                    prev_status,
                    note=f"Reappeared; keeping suppressed status {prev_status.value}",
                )
                summary.suppressed += 1
                summary.updates.append(
                    {
                        "finding_id": finding_id,
                        "dedup_key": dkey,
                        "action": "suppressed",
                        "status": prev_status.value,
                    }
                )
            else:
                # In-progress (TRIAGED/REPORTED/ACCEPTED/REGRESSED) — retain.
                self.lifecycle.update_status(
                    finding_id,
                    prev_status,
                    note="Reappeared; retaining in-progress status",
                )
                summary.retained += 1
                summary.updates.append(
                    {
                        "finding_id": finding_id,
                        "dedup_key": dkey,
                        "action": "retained",
                        "status": prev_status.value,
                    }
                )

        log.info(
            f"lifecycle: scan for {target} -> "
            f"{summary.new} new, {summary.regressed} regressed, "
            f"{summary.suppressed} suppressed, {summary.retained} retained"
        )
        return summary
