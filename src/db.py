"""
DatabaseManager - the single persistence gateway (class diagram, Figure 7).

Every other module (LogParser, BaselineEngine, RiskScorer, Dashboard) talks to
the database ONLY through this class. No raw SQL anywhere else. This decouples
detection logic from the storage backend and directly supports NFR-10.

Secrets / config come from environment variables (NFR-07): no hardcoded paths
to anything sensitive; the DB path itself is configurable via ITDS_DB_PATH.
"""

import os
import json
import sqlite3
from pathlib import Path

# Default DB location; overridable by env var so nothing is hardcoded at release.
DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "itds.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class DatabaseManager:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.environ.get("ITDS_DB_PATH", str(DEFAULT_DB))
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row          # rows behave like dicts
        conn.execute("PRAGMA foreign_keys = ON")  # enforce FK integrity
        return conn

    def _init_schema(self) -> None:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = f.read()
        with self._connect() as conn:
            conn.executescript(schema)

    def reset(self) -> None:
        """Drop all data. Used by the data generator and tests for clean runs."""
        with self._connect() as conn:
            for tbl in ("alerts", "baseline_profiles", "log_records", "users"):
                conn.execute(f"DELETE FROM {tbl}")
            conn.execute("DELETE FROM sqlite_sequence")  # reset autoincrement

    # ---- Users -----------------------------------------------------------
    def get_or_create_user(self, username: str, email: str | None = None) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT user_id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row:
                return row["user_id"]
            cur = conn.execute(
                "INSERT INTO users (username, email) VALUES (?, ?)",
                (username, email),
            )
            return cur.lastrowid

    # ---- Log records -----------------------------------------------------
    def insert_log(self, user_id, timestamp, source_ip, auth_outcome, privilege_level) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO log_records
                   (user_id, timestamp, source_ip, auth_outcome, privilege_level)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, timestamp, source_ip, auth_outcome, privilege_level),
            )
            return cur.lastrowid

    def insert_logs_batch(self, records: list) -> int:
        """
        Insert many validated log rows in a SINGLE transaction.

        `records` is a list of dicts with keys: username, timestamp, source_ip,
        auth_outcome, privilege_level. Users are resolved/created in the same
        transaction. This replaces thousands of one-row commits with one bulk
        commit, which is what keeps NFR-01 (10,000 records < 30s) satisfiable.
        Returns the number of log rows inserted.
        """
        if not records:
            return 0
        with self._connect() as conn:
            # Resolve usernames -> ids once, creating any that are new.
            existing = {r["username"]: r["user_id"]
                        for r in conn.execute("SELECT user_id, username FROM users")}
            for rec in records:
                name = rec["username"]
                if name not in existing:
                    cur = conn.execute(
                        "INSERT INTO users (username) VALUES (?)", (name,))
                    existing[name] = cur.lastrowid
            conn.executemany(
                """INSERT INTO log_records
                   (user_id, timestamp, source_ip, auth_outcome, privilege_level)
                   VALUES (?, ?, ?, ?, ?)""",
                [(existing[r["username"]], r["timestamp"], r["source_ip"],
                  r["auth_outcome"], r["privilege_level"]) for r in records],
            )
        return len(records)

    def get_logs_for_user(self, user_id) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM log_records WHERE user_id = ? ORDER BY timestamp",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def all_user_ids(self) -> list:
        with self._connect() as conn:
            rows = conn.execute("SELECT user_id FROM users").fetchall()
            return [r["user_id"] for r in rows]

    def all_baselines_with_usernames(self) -> list:
        """Baselines joined to usernames + counts, for the Users page."""
        import json as _json
        q = """SELECT u.username, b.active_hours, b.common_ips,
                      b.avg_login_frequency, b.known_privileges,
                      (SELECT COUNT(*) FROM log_records l
                       WHERE l.user_id = u.user_id) AS log_count,
                      (SELECT COUNT(*) FROM alerts a
                       WHERE a.user_id = u.user_id) AS alert_count
               FROM users u
               JOIN baseline_profiles b ON b.user_id = u.user_id
               ORDER BY u.username"""
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(q).fetchall()]
        for r in rows:
            r["active_hours"] = _json.loads(r["active_hours"]) if r["active_hours"] else None
            r["common_ips"] = _json.loads(r["common_ips"]) if r["common_ips"] else []
            r["known_privileges"] = _json.loads(r["known_privileges"]) if r["known_privileges"] else []
        return rows

    # ---- Baseline profiles ----------------------------------------------
    def save_baseline(self, user_id, active_hours, common_ips,
                      avg_login_frequency, known_privileges) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM baseline_profiles WHERE user_id = ?", (user_id,))
            conn.execute(
                """INSERT INTO baseline_profiles
                   (user_id, active_hours, common_ips, avg_login_frequency, known_privileges)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, json.dumps(active_hours), json.dumps(common_ips),
                 avg_login_frequency, json.dumps(known_privileges)),
            )

    def get_baseline(self, user_id) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM baseline_profiles WHERE user_id = ?", (user_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["active_hours"] = json.loads(d["active_hours"]) if d["active_hours"] else None
            d["common_ips"] = json.loads(d["common_ips"]) if d["common_ips"] else []
            d["known_privileges"] = json.loads(d["known_privileges"]) if d["known_privileges"] else []
            return d

    # ---- Alerts ----------------------------------------------------------
    def insert_alert(self, user_id, log_id, anomaly_type, risk_score, risk_level, explanation) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO alerts
                   (user_id, log_id, anomaly_type, risk_score, risk_level, explanation)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, log_id, anomaly_type, risk_score, risk_level, explanation),
            )
            return cur.lastrowid

    def get_alerts(self, user=None, risk_level=None, date_from=None, date_to=None) -> list:
        """Returns alerts joined with username + log detail. Supports FR-11 filtering."""
        q = """SELECT a.*, u.username, l.timestamp, l.source_ip,
                      l.auth_outcome, l.privilege_level
               FROM alerts a
               JOIN users u ON a.user_id = u.user_id
               JOIN log_records l ON a.log_id = l.log_id
               WHERE 1=1"""
        params = []
        if user:
            q += " AND u.username = ?"; params.append(user)
        if risk_level:
            q += " AND a.risk_level = ?"; params.append(risk_level)
        if date_from:
            q += " AND l.timestamp >= ?"; params.append(date_from)
        if date_to:
            q += " AND l.timestamp <= ?"; params.append(date_to)
        q += " ORDER BY a.risk_score DESC, l.timestamp DESC"
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]

    def alert_counts_by_level(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT risk_level, COUNT(*) c FROM alerts GROUP BY risk_level"
            ).fetchall()
        counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in rows:
            counts[r["risk_level"]] = r["c"]
        counts["Total"] = sum(counts.values())
        return counts
