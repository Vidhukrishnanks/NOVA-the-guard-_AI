"""
SQLite persistence (Python standard library, no server needed).

Privacy by design:
  * Scan history is stored ONLY after the user consents (Settings / banner).
  * Stored scan URLs are masked: query-parameter VALUES and fragments are removed.
  * Every row has an 'owner' (random ID kept in the signed session cookie), and
    every query filters by owner, so one browser can't read another's data.
  * Reports are stored only when the user ticks "save this report".
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    owner TEXT PRIMARY KEY,
    save_history INTEGER NOT NULL DEFAULT 0,
    consent_answered INTEGER NOT NULL DEFAULT 0,
    consent_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    url_masked TEXT NOT NULL,
    hostname TEXT,
    final_category TEXT NOT NULL,
    ml_category TEXT NOT NULL,
    score REAL NOT NULL,
    model_version TEXT,
    details_json TEXT NOT NULL,
    feedback TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner, created_at);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    reference TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    data_json TEXT NOT NULL,
    external_ack TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    owner TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

REPORT_STATUSES = ["Draft", "Ready to Submit", "Submitted Externally — User Confirmed"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"], timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app):
    with app.app_context():
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
    app.teardown_appcontext(close_db)


# ------------------------------ settings ---------------------------------- #
def get_settings(owner: str) -> dict:
    row = get_db().execute("SELECT * FROM settings WHERE owner=?", (owner,)).fetchone()
    if row is None:
        return {"save_history": False, "consent_answered": False, "consent_at": None}
    return {"save_history": bool(row["save_history"]), "consent_answered": bool(row["consent_answered"]),
            "consent_at": row["consent_at"]}


def set_history_consent(owner: str, allowed: bool):
    db = get_db()
    db.execute(
        "INSERT INTO settings(owner, save_history, consent_answered, consent_at) VALUES(?,?,1,?) "
        "ON CONFLICT(owner) DO UPDATE SET save_history=excluded.save_history, consent_answered=1, "
        "consent_at=excluded.consent_at",
        (owner, int(allowed), now_iso()))
    db.commit()


# -------------------------------- scans ----------------------------------- #
def save_scan(owner: str, result: dict, model_version: str | None) -> int:
    details = {
        "features": result["ml"]["features"],
        "contributions": result["ml"]["contributions"],
        "model_name": result["ml"]["model_name"],
        "model_label": result["ml"]["model_label"],
        "rules": result["rules"],
        "reasons": result["reasons"],
        "recommendations": result["recommendations"],
        "info": result["info"],
        "threat_intel": result["threat_intel"],
        "escalated_by_rules": result["escalated_by_rules"],
        "verified": result["verified"],
        "final_label": result["final_label"],
    }
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans(owner,url_masked,hostname,final_category,ml_category,score,model_version,"
        "details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (owner, result["url_masked"], result["info"]["hostname"], result["final_category"],
         result["ml"]["category"], result["ml"]["score"], model_version,
         json.dumps(details), result["timestamp"]))
    db.commit()
    return cur.lastrowid


def _scan_row(row) -> dict:
    d = dict(row)
    d["details"] = json.loads(d.pop("details_json"))
    return d


def get_scan(owner: str, scan_id: int) -> dict | None:
    row = get_db().execute("SELECT * FROM scans WHERE id=? AND owner=?", (scan_id, owner)).fetchone()
    return _scan_row(row) if row else None


def list_scans(owner: str, q: str = "", category: str = "", limit: int = 500) -> list[dict]:
    sql = "SELECT * FROM scans WHERE owner=?"
    params: list = [owner]
    if q:
        sql += " AND (url_masked LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\')"
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [like, like]
    if category in ("legitimate", "suspicious", "malicious"):
        sql += " AND final_category=?"
        params.append(category)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [_scan_row(r) for r in get_db().execute(sql, params).fetchall()]


def delete_scan(owner: str, scan_id: int) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM scans WHERE id=? AND owner=?", (scan_id, owner))
    db.commit()
    return cur.rowcount > 0


def clear_scans(owner: str) -> int:
    db = get_db()
    cur = db.execute("DELETE FROM scans WHERE owner=?", (owner,))
    db.commit()
    return cur.rowcount


def set_feedback(owner: str, scan_id: int, feedback: str | None) -> bool:
    if feedback not in (None, "correct", "false_positive", "false_negative"):
        return False
    db = get_db()
    cur = db.execute("UPDATE scans SET feedback=? WHERE id=? AND owner=?", (feedback, scan_id, owner))
    db.commit()
    return cur.rowcount > 0


def scan_stats(owner: str) -> dict:
    db = get_db()
    rows = db.execute("SELECT final_category, COUNT(*) n FROM scans WHERE owner=? GROUP BY final_category",
                      (owner,)).fetchall()
    counts = {"legitimate": 0, "suspicious": 0, "malicious": 0}
    for r in rows:
        counts[r["final_category"]] = r["n"]
    total = sum(counts.values())
    avg = db.execute("SELECT AVG(score) a FROM scans WHERE owner=?", (owner,)).fetchone()["a"]
    since = (datetime.now(timezone.utc) - timedelta(days=13)).date().isoformat()
    daily_rows = db.execute(
        "SELECT substr(created_at,1,10) d, final_category c, COUNT(*) n FROM scans "
        "WHERE owner=? AND substr(created_at,1,10) >= ? GROUP BY d, c ORDER BY d", (owner, since)).fetchall()
    days = [(datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat() for i in range(13, -1, -1)]
    daily = {d: {"legitimate": 0, "suspicious": 0, "malicious": 0} for d in days}
    for r in daily_rows:
        if r["d"] in daily:
            daily[r["d"]][r["c"]] = r["n"]
    fb_rows = db.execute("SELECT feedback, COUNT(*) n FROM scans WHERE owner=? AND feedback IS NOT NULL "
                         "GROUP BY feedback", (owner,)).fetchall()
    feedback = {"correct": 0, "false_positive": 0, "false_negative": 0}
    for r in fb_rows:
        feedback[r["feedback"]] = r["n"]
    return {"total": total, "counts": counts, "avg_score": round(avg, 1) if avg is not None else None,
            "daily": daily, "feedback": feedback}


# ------------------------------- reports ---------------------------------- #
def create_report(owner: str, reference: str, data: dict, status: str = "Draft") -> int:
    ts = now_iso()
    db = get_db()
    cur = db.execute("INSERT INTO reports(owner,reference,status,data_json,created_at,updated_at) "
                     "VALUES(?,?,?,?,?,?)", (owner, reference, status, json.dumps(data), ts, ts))
    db.commit()
    return cur.lastrowid


def update_report_data(owner: str, report_id: int, data: dict) -> bool:
    db = get_db()
    cur = db.execute("UPDATE reports SET data_json=?, status='Draft', external_ack=NULL, updated_at=? "
                     "WHERE id=? AND owner=?", (json.dumps(data), now_iso(), report_id, owner))
    db.commit()
    return cur.rowcount > 0


def set_report_status(owner: str, report_id: int, status: str, external_ack: str | None = None) -> bool:
    if status not in REPORT_STATUSES:
        return False
    db = get_db()
    cur = db.execute("UPDATE reports SET status=?, external_ack=?, updated_at=? WHERE id=? AND owner=?",
                     (status, external_ack, now_iso(), report_id, owner))
    db.commit()
    return cur.rowcount > 0


def _report_row(row) -> dict:
    d = dict(row)
    d["data"] = json.loads(d.pop("data_json"))
    return d


def get_report(owner: str, report_id: int) -> dict | None:
    row = get_db().execute("SELECT * FROM reports WHERE id=? AND owner=?", (report_id, owner)).fetchone()
    if not row:
        return None
    rep = _report_row(row)
    rep["evidence"] = list_evidence(owner, report_id)
    return rep


def list_reports(owner: str) -> list[dict]:
    rows = get_db().execute("SELECT * FROM reports WHERE owner=? ORDER BY id DESC", (owner,)).fetchall()
    return [_report_row(r) for r in rows]


def delete_report(owner: str, report_id: int) -> list[str]:
    """Delete a report; returns the stored evidence filenames so files can be removed."""
    db = get_db()
    names = [r["stored_name"] for r in db.execute(
        "SELECT stored_name FROM evidence WHERE report_id=? AND owner=?", (report_id, owner))]
    db.execute("DELETE FROM evidence WHERE report_id=? AND owner=?", (report_id, owner))
    db.execute("DELETE FROM reports WHERE id=? AND owner=?", (report_id, owner))
    db.commit()
    return names


def add_evidence(owner: str, report_id: int, meta: dict) -> int:
    db = get_db()
    cur = db.execute("INSERT INTO evidence(report_id,owner,original_name,stored_name,size,mime,sha256,created_at) "
                     "VALUES(?,?,?,?,?,?,?,?)",
                     (report_id, owner, meta["original_name"], meta["stored_name"], meta["size"],
                      meta["mime"], meta["sha256"], now_iso()))
    db.commit()
    return cur.lastrowid


def list_evidence(owner: str, report_id: int) -> list[dict]:
    rows = get_db().execute("SELECT * FROM evidence WHERE report_id=? AND owner=? ORDER BY id",
                            (report_id, owner)).fetchall()
    return [dict(r) for r in rows]


def get_evidence(owner: str, report_id: int, evidence_id: int) -> dict | None:
    row = get_db().execute("SELECT * FROM evidence WHERE id=? AND report_id=? AND owner=?",
                           (evidence_id, report_id, owner)).fetchone()
    return dict(row) if row else None


def delete_evidence(owner: str, report_id: int, evidence_id: int) -> str | None:
    ev = get_evidence(owner, report_id, evidence_id)
    if not ev:
        return None
    db = get_db()
    db.execute("DELETE FROM evidence WHERE id=? AND owner=?", (evidence_id, owner))
    db.commit()
    return ev["stored_name"]


def delete_all_reports(owner: str) -> list[str]:
    db = get_db()
    names = [r["stored_name"] for r in db.execute("SELECT stored_name FROM evidence WHERE owner=?", (owner,))]
    db.execute("DELETE FROM evidence WHERE owner=?", (owner,))
    db.execute("DELETE FROM reports WHERE owner=?", (owner,))
    db.commit()
    return names
