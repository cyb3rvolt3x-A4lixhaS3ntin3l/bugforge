"""Tests for the finding lifecycle management system."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gungnir.storage.db import Database
from gungnir.intelligence.lifecycle import (
    FindingStatus,
    FindingLifecycle,
    LifecycleManager,
    LifecycleSummary,
)


def _make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # let Database create it fresh
    return Database(path), path


def _sample_finding(target="example.com", ftype="xss", asset="example.com",
                    title="Reflected XSS in search", extra=None):
    f = {
        "type": ftype,
        "asset": asset,
        "target": target,
        "title": title,
        "severity": "high",
        "description": "desc",
        "evidence": "evidence",
        "url": f"https://{asset}/?q=test",
        "source": "manual",
    }
    if extra:
        f.update(extra)
    return f


def test_schema_created_without_breaking_existing_db():
    db, path = _make_db()
    lc = FindingLifecycle(db)
    # existing tables still present
    import sqlite3
    with sqlite3.connect(path) as conn:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert {"runs", "findings", "assets", "finding_lifecycle", "finding_notes"} <= names
    os.unlink(path)


def test_update_and_get_status():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding()], run_id, "example.com")
    fid = db.get_all_findings("example.com")[0]["id"]

    lc = FindingLifecycle(db)
    assert lc.get_status(fid) == FindingStatus.NEW  # default from findings table

    assert lc.update_status(fid, FindingStatus.TRIAGED, "reviewed by alice")
    assert lc.get_status(fid) == FindingStatus.TRIAGED

    assert lc.update_status(fid, FindingStatus.REPORTED, "sent to BBP")
    assert lc.get_status(fid) == FindingStatus.REPORTED

    # findings.status mirrored
    with __import__("sqlite3").connect(path) as conn:
        row = conn.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
    assert row[0] == "reported"
    os.unlink(path)


def test_history_ordering():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding()], run_id, "example.com")
    fid = db.get_all_findings("example.com")[0]["id"]

    lc = FindingLifecycle(db)
    # Record an explicit NEW first so the full chain is in history.
    lc.update_status(fid, FindingStatus.NEW, "discovered")
    lc.update_status(fid, FindingStatus.TRIAGED, "1")
    lc.update_status(fid, FindingStatus.REPORTED, "2")
    lc.update_status(fid, FindingStatus.ACCEPTED, "3")
    hist = lc.get_history(fid)
    assert [h["status"] for h in hist] == ["new", "triaged", "reported", "accepted"]
    # notes are preserved
    assert [h["note"] for h in hist] == ["discovered", "1", "2", "3"]
    os.unlink(path)


def test_notes():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding()], run_id, "example.com")
    fid = db.get_all_findings("example.com")[0]["id"]

    lc = FindingLifecycle(db)
    assert lc.add_note(fid, "needs repro")
    assert lc.add_note(fid, "confirmed")
    notes = lc.get_notes(fid)
    assert [n["note"] for n in notes] == ["needs repro", "confirmed"]
    assert lc.add_note(fid, "") is False
    os.unlink(path)


def test_mark_duplicate():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding(title="A"), _sample_finding(title="B")],
                     run_id, "example.com")
    findings = db.get_all_findings("example.com")
    dup = next(f for f in findings if f["title"] == "A")
    orig = next(f for f in findings if f["title"] == "B")

    lc = FindingLifecycle(db)
    assert lc.mark_duplicate(dup["id"], orig["id"])
    assert lc.get_status(dup["id"]) == FindingStatus.DUPLICATE
    import json
    with __import__("sqlite3").connect(path) as conn:
        row = conn.execute(
            "SELECT extra_json FROM findings WHERE id=?", (dup["id"],)
        ).fetchone()
    extra = json.loads(row[0])
    assert extra["duplicate_of"] == orig["id"]
    os.unlink(path)


def test_find_by_status():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings(
        [_sample_finding(title="A"), _sample_finding(title="B"),
         _sample_finding(title="C")],
        run_id, "example.com",
    )
    findings = {f["title"]: f for f in db.get_all_findings("example.com")}

    lc = FindingLifecycle(db)
    lc.update_status(findings["A"]["id"], FindingStatus.REPORTED)
    lc.update_status(findings["B"]["id"], FindingStatus.REJECTED)
    # C stays NEW (no lifecycle row yet)

    new_findings = lc.find_by_status(FindingStatus.NEW)
    new_titles = {f["title"] for f in new_findings}
    assert "C" in new_titles
    assert "A" not in new_titles

    reported = lc.find_by_status(FindingStatus.REPORTED)
    assert {f["title"] for f in reported} == {"A"}

    rejected = lc.find_by_status(FindingStatus.REJECTED)
    assert {f["title"] for f in rejected} == {"B"}

    # target filter
    assert all(f["target"] == "example.com" for f in reported)
    assert lc.find_by_status(FindingStatus.REPORTED, target="other.com") == []
    os.unlink(path)


def test_check_regression():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding()], run_id, "example.com")
    fid = db.get_all_findings("example.com")[0]["id"]

    lc = FindingLifecycle(db)
    lc.update_status(fid, FindingStatus.RESOLVED, "patched")

    # finding absent from current scan -> no regression
    assert lc.check_regression(fid, [], target="example.com") is False
    assert lc.get_status(fid) == FindingStatus.RESOLVED

    # finding reappears -> regression
    assert lc.check_regression(
        fid, [_sample_finding()], target="example.com"
    ) is True
    assert lc.get_status(fid) == FindingStatus.REGRESSED
    os.unlink(path)


def test_check_regression_non_resolved_is_noop():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding()], run_id, "example.com")
    fid = db.get_all_findings("example.com")[0]["id"]
    lc = FindingLifecycle(db)
    lc.update_status(fid, FindingStatus.TRIAGED)
    # reappears but not resolved -> no regression flag
    assert lc.check_regression(fid, [_sample_finding()], "example.com") is False
    assert lc.get_status(fid) == FindingStatus.TRIAGED
    os.unlink(path)


def test_lifecycle_manager_new():
    db, path = _make_db()
    run_id = db.save_run("example.com", "domain")
    current = [_sample_finding(title="A"), _sample_finding(title="B")]
    db.save_findings(current, run_id, "example.com")

    mgr = LifecycleManager(db)
    summary = mgr.process_scan("example.com", current)
    assert isinstance(summary, LifecycleSummary)
    assert summary.new == 2
    assert summary.regressed == 0
    assert summary.suppressed == 0
    assert summary.retained == 0

    findings = {f["title"]: f for f in db.get_all_findings("example.com")}
    assert mgr.lifecycle.get_status(findings["A"]["id"]) == FindingStatus.NEW
    os.unlink(path)


def test_lifecycle_manager_regressed():
    db, path = _make_db()
    # run 1
    run1 = db.save_run("example.com", "domain")
    current = [_sample_finding(title="A")]
    db.save_findings(current, run1, "example.com")
    mgr = LifecycleManager(db)
    mgr.process_scan("example.com", current)
    findings = db.get_all_findings("example.com")
    fid = findings[0]["id"]
    mgr.lifecycle.update_status(fid, FindingStatus.RESOLVED, "fixed")

    # run 2 — same finding reappears, gets a NEW finding_id (per-run UUID)
    time.sleep(0.01)
    run2 = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding(title="A")], run2, "example.com")
    summary = mgr.process_scan("example.com", [_sample_finding(title="A")])
    assert summary.regressed == 1
    assert summary.new == 0
    # newest finding_id for this dedup_key should be REGRESSED
    allf = db.get_all_findings("example.com")
    newest = max(allf, key=lambda f: f["last_seen"])
    assert mgr.lifecycle.get_status(newest["id"]) == FindingStatus.REGRESSED
    os.unlink(path)


def test_lifecycle_manager_suppresses_recurring_false_positive():
    db, path = _make_db()
    run1 = db.save_run("example.com", "domain")
    current = [_sample_finding(title="FP")]
    db.save_findings(current, run1, "example.com")
    mgr = LifecycleManager(db)
    mgr.process_scan("example.com", current)
    fid = db.get_all_findings("example.com")[0]["id"]
    mgr.lifecycle.update_status(fid, FindingStatus.REJECTED, "false positive")

    # run 2 — same FP reappears
    time.sleep(0.01)
    run2 = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding(title="FP")], run2, "example.com")
    summary = mgr.process_scan("example.com", [_sample_finding(title="FP")])
    assert summary.suppressed == 1
    assert summary.new == 0
    assert summary.regressed == 0
    newest = max(db.get_all_findings("example.com"), key=lambda f: f["last_seen"])
    assert mgr.lifecycle.get_status(newest["id"]) == FindingStatus.REJECTED
    os.unlink(path)


def test_lifecycle_manager_retains_in_progress():
    db, path = _make_db()
    run1 = db.save_run("example.com", "domain")
    current = [_sample_finding(title="X")]
    db.save_findings(current, run1, "example.com")
    mgr = LifecycleManager(db)
    mgr.process_scan("example.com", current)
    fid = db.get_all_findings("example.com")[0]["id"]
    mgr.lifecycle.update_status(fid, FindingStatus.REPORTED, "reported")

    time.sleep(0.01)
    run2 = db.save_run("example.com", "domain")
    db.save_findings([_sample_finding(title="X")], run2, "example.com")
    summary = mgr.process_scan("example.com", [_sample_finding(title="X")])
    assert summary.retained == 1
    assert summary.new == 0
    assert summary.regressed == 0
    newest = max(db.get_all_findings("example.com"), key=lambda f: f["last_seen"])
    assert mgr.lifecycle.get_status(newest["id"]) == FindingStatus.REPORTED
    os.unlink(path)


def test_finding_status_from_str():
    assert FindingStatus.from_str("new") == FindingStatus.NEW
    assert FindingStatus.from_str("RESOLVED") == FindingStatus.RESOLVED
    assert FindingStatus.from_str(None) == FindingStatus.NEW
    assert FindingStatus.from_str("garbage") == FindingStatus.NEW
    assert FindingStatus.RESOLVED == "resolved"  # str enum


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
