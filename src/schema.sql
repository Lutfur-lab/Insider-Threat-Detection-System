-- Behaviour-Based Insider Threat Detection System
-- Schema matches the ERD (Figure 3). Four tables, explicit keys + types.
-- PRAGMA foreign_keys=ON is enforced per-connection in db.py.

CREATE TABLE IF NOT EXISTS users (
    user_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    email      TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS log_records (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    timestamp       TEXT    NOT NULL,        -- ISO 8601 string
    source_ip       TEXT    NOT NULL,
    auth_outcome    TEXT    NOT NULL,        -- 'success' | 'failure'
    privilege_level TEXT    NOT NULL,        -- 'standard' | 'admin' etc.
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

CREATE TABLE IF NOT EXISTS baseline_profiles (
    baseline_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id               INTEGER NOT NULL UNIQUE,
    active_hours          TEXT,              -- JSON: [start_hour, end_hour]
    common_ips            TEXT,              -- JSON: list of IP strings
    avg_login_frequency   REAL,              -- avg logins per day
    known_privileges      TEXT,              -- JSON: list of seen privilege levels
    updated_at            TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    log_id        INTEGER NOT NULL,
    anomaly_type  TEXT    NOT NULL,          -- comma-joined types for multi-anomaly events
    risk_score    INTEGER NOT NULL,
    risk_level    TEXT    NOT NULL,          -- 'Low' | 'Medium' | 'High'
    explanation   TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (log_id)  REFERENCES log_records (log_id)
);

CREATE INDEX IF NOT EXISTS idx_logs_user ON log_records (user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts (user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts (risk_level);
