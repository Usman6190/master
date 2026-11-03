"""SQLite persistence for audit history. Never stores raw credentials."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from config.settings import db_path
from core.models import ModuleResult, utcnow_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    audit_type TEXT NOT NULL,
    status TEXT NOT NULL,
    config_json TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_s REAL,
    scores_json TEXT,
    pdf_path TEXT,
    xlsx_path TEXT,
    state_json TEXT
);
CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    finding_id TEXT, fingerprint TEXT, module TEXT, category TEXT,
    title TEXT, severity TEXT, affected_url TEXT, description TEXT,
    evidence TEXT, reproduction_steps TEXT, impact TEXT, recommendation TEXT,
    verification_status TEXT, references_ TEXT, timestamp TEXT
);
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    module TEXT, category TEXT, name TEXT, status TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    module TEXT, name TEXT, value TEXT, unit TEXT, context TEXT
);
CREATE TABLE IF NOT EXISTS error_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER REFERENCES audits(id) ON DELETE CASCADE,
    module TEXT, message TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS ix_checks_audit ON checks(audit_id);
"""

_SECRET_KEYS = {"api_token", "login_password", "pagespeed_api_key", "admin_password", "secondary_password", "password", "token"}


def _scrub(cfg: dict[str, Any]) -> dict[str, Any]:
    return {k: ("[stored encrypted]" if k in _SECRET_KEYS and v else v) for k, v in cfg.items()}


class DBManager:
    def __init__(self, path: Path | str | None = None):
        self.path = str(path or db_path())
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def create_audit(self, target_url: str, audit_type: str, config: dict[str, Any]) -> int:
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT INTO audits(target_url, audit_type, status, config_json, started_at) VALUES (?,?,?,?,?)",
                (target_url, audit_type, "running", json.dumps(_scrub(config)), utcnow_iso()),
            )
            return int(cur.lastrowid)

    def save_module_result(self, audit_id: int, result: ModuleResult) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO module_runs(audit_id, module, status, error, started_at, finished_at) VALUES (?,?,?,?,?,?)",
                (audit_id, result.module, result.status, result.error, result.started_at, result.finished_at),
            )
            for f in result.findings:
                d = f.to_dict()
                c.execute(
                    """INSERT INTO findings(audit_id, finding_id, fingerprint, module, category, title, severity,
                    affected_url, description, evidence, reproduction_steps, impact, recommendation,
                    verification_status, references_, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (audit_id, d["finding_id"], d["fingerprint"], d["module"], d["category"], d["title"], d["severity"],
                     d["affected_url"], d["description"], d["evidence"], d["reproduction_steps"], d["impact"],
                     d["recommendation"], d["verification_status"], d["references"], d["timestamp"]),
                )
            for ch in result.checks:
                c.execute(
                    "INSERT INTO checks(audit_id, module, category, name, status, detail) VALUES (?,?,?,?,?,?)",
                    (audit_id, ch.module, ch.category.value, ch.name, ch.status.value, ch.detail),
                )
            for m in result.metrics:
                c.execute(
                    "INSERT INTO metrics(audit_id, module, name, value, unit, context) VALUES (?,?,?,?,?,?)",
                    (audit_id, m.module or result.module, m.name, None if m.value is None else str(m.value), m.unit, m.context),
                )
            if result.error:
                c.execute("INSERT INTO error_log(audit_id, module, message, ts) VALUES (?,?,?,?)",
                          (audit_id, result.module, result.error, utcnow_iso()))

    def save_state(self, audit_id: int, state: dict[str, Any]) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE audits SET state_json=? WHERE id=?", (json.dumps(state), audit_id))

    def finish_audit(self, audit_id: int, status: str, duration_s: float, scores: dict[str, Any]) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE audits SET status=?, finished_at=?, duration_s=?, scores_json=? WHERE id=?",
                      (status, utcnow_iso(), duration_s, json.dumps(scores), audit_id))

    def set_report_paths(self, audit_id: int, pdf: str | None, xlsx: str | None) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE audits SET pdf_path=?, xlsx_path=? WHERE id=?", (pdf, xlsx, audit_id))

    def log_error(self, audit_id: int | None, module: str, message: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO error_log(audit_id, module, message, ts) VALUES (?,?,?,?)",
                      (audit_id, module, message, utcnow_iso()))

    # ---- queries ----
    def list_audits(self, search: str = "", status: str = "") -> list[dict[str, Any]]:
        q = "SELECT * FROM audits WHERE 1=1"
        args: list[Any] = []
        if search:
            q += " AND (target_url LIKE ? OR audit_type LIKE ?)"
            args += [f"%{search}%", f"%{search}%"]
        if status:
            q += " AND status=?"
            args.append(status)
        q += " ORDER BY id DESC"
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args)]

    def get_audit(self, audit_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM audits WHERE id=?", (audit_id,)).fetchone()
            return dict(r) if r else None

    def _rows(self, table: str, audit_id: int) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(f"SELECT * FROM {table} WHERE audit_id=? ORDER BY id", (audit_id,))]

    def get_findings(self, audit_id: int) -> list[dict[str, Any]]:
        rows = self._rows("findings", audit_id)
        for r in rows:
            r["references"] = r.pop("references_", "")
        return rows

    def get_checks(self, audit_id: int) -> list[dict[str, Any]]:
        return self._rows("checks", audit_id)

    def get_metrics(self, audit_id: int) -> list[dict[str, Any]]:
        return self._rows("metrics", audit_id)

    def get_module_runs(self, audit_id: int) -> list[dict[str, Any]]:
        return self._rows("module_runs", audit_id)

    def get_errors(self, audit_id: int) -> list[dict[str, Any]]:
        return self._rows("error_log", audit_id)

    def delete_audit(self, audit_id: int) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM audits WHERE id=?", (audit_id,))

    def delete_all(self) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM audits")
            c.execute("DELETE FROM error_log")

    def compare(self, old_id: int, new_id: int) -> dict[str, list[dict[str, Any]]]:
        old = {f["fingerprint"]: f for f in self.get_findings(old_id)}
        new = {f["fingerprint"]: f for f in self.get_findings(new_id)}
        return {
            "new": [new[k] for k in new.keys() - old.keys()],
            "resolved": [old[k] for k in old.keys() - new.keys()],
            "persisting": [new[k] for k in new.keys() & old.keys()],
        }

    def stats(self) -> dict[str, Any]:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
            last = c.execute("SELECT * FROM audits ORDER BY id DESC LIMIT 1").fetchone()
        return {"total_audits": total, "latest": dict(last) if last else None}
