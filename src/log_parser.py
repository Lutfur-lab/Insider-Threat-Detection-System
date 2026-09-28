"""
LogParser - log ingestion and validation (FR-01, FR-02).

Responsibilities:
  - Ingest a CSV containing the five required fields (FR-01).
  - Validate every row; reject malformed/incomplete records and log the reason
    per invalid row, while valid rows pass through unchanged (FR-02).
  - Persist valid records via DatabaseManager (single-gateway pattern, NFR-10).

The parser holds NO SQL itself. It delegates all persistence to DatabaseManager.
It is unit-testable in isolation: pass it a DatabaseManager (or a fake) and a
CSV path; it returns a structured result you can assert on.
"""

import ipaddress
import re
from datetime import datetime

import pandas as pd

REQUIRED_COLUMNS = [
    "username", "timestamp", "source_ip", "auth_outcome", "privilege_level",
]
VALID_OUTCOMES = {"success", "failure"}

# Security: whitelist patterns prevent stored XSS via crafted CSV uploads.
# A malicious username like <script>alert(1)</script> would otherwise execute
# in the analyst's browser when the dashboard renders the alert detail panel.
USERNAME_PATTERN = re.compile(r"^[\w.@\-]{1,64}$")
VALID_PRIVILEGES = {"standard", "elevated", "admin", "root", "service"}


class LogParser:
    def __init__(self, db):
        self.db = db

    # ---- public API ------------------------------------------------------
    def parse_csv(self, csv_path: str) -> dict:
        """
        Read, validate, and store a CSV log file.

        Returns a result dict:
            {
              "total_rows": int,
              "valid_rows": int,
              "rejected_rows": int,
              "rejections": [ {"row": int, "reason": str, "data": {...}}, ... ],
            }
        """
        df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)

        # FR-01: confirm the five required columns are present.
        missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(f"CSV missing required column(s): {', '.join(missing)}")

        result = {"total_rows": len(df), "valid_rows": 0,
                  "rejected_rows": 0, "rejections": []}

        valid_records = []
        for idx, row in df.iterrows():
            ok, reason, cleaned = self._validate_row(row)
            if not ok:
                # FR-02: log the rejection reason for each invalid row.
                result["rejected_rows"] += 1
                result["rejections"].append({
                    "row": int(idx) + 2,   # +2 = header line + 0-based offset
                    "reason": reason,
                    "data": {c: row.get(c, "") for c in REQUIRED_COLUMNS},
                })
                continue
            valid_records.append(cleaned)

        # Persist all valid rows in ONE transaction via the gateway (no raw SQL
        # here). Batching keeps NFR-01 satisfiable for large files — thousands
        # of individual commits were the bottleneck.
        result["valid_rows"] = self.db.insert_logs_batch(valid_records)

        return result

    # ---- validation ------------------------------------------------------
    def _validate_row(self, row) -> tuple[bool, str, dict]:
        """Return (is_valid, reason_if_invalid, cleaned_dict)."""
        username = (row.get("username") or "").strip()
        timestamp = (row.get("timestamp") or "").strip()
        source_ip = (row.get("source_ip") or "").strip()
        outcome = (row.get("auth_outcome") or "").strip().lower()
        privilege = (row.get("privilege_level") or "").strip().lower()

        # 1. No empty required fields.
        for name, value in (("username", username), ("timestamp", timestamp),
                            ("source_ip", source_ip), ("auth_outcome", outcome),
                            ("privilege_level", privilege)):
            if not value:
                return False, f"empty field: {name}", {}

        # 2. Username must match a safe pattern (no HTML/script injection).
        if not USERNAME_PATTERN.match(username):
            return False, f"invalid username format: {username!r}", {}

        # 3. Privilege level must be from a known set.
        if privilege not in VALID_PRIVILEGES:
            return False, f"invalid privilege_level: {privilege!r}", {}

        # 4. Timestamp must be ISO 8601 parseable.
        try:
            ts = datetime.fromisoformat(timestamp)
        except ValueError:
            return False, f"invalid timestamp: {timestamp!r}", {}

        # 5. Source IP must be a valid address.
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return False, f"invalid source_ip: {source_ip!r}", {}

        # 6. Outcome must be success/failure.
        if outcome not in VALID_OUTCOMES:
            return False, f"invalid auth_outcome: {outcome!r}", {}

        cleaned = {
            "username": username,
            "timestamp": ts.isoformat(),
            "source_ip": source_ip,
            "auth_outcome": outcome,
            "privilege_level": privilege,
        }
        return True, "", cleaned


if __name__ == "__main__":
    from pathlib import Path
    from db import DatabaseManager

    db = DatabaseManager()
    db.reset()
    csv_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"
    res = LogParser(db).parse_csv(str(csv_path))
    print(f"Total rows:    {res['total_rows']}")
    print(f"Valid stored:  {res['valid_rows']}")
    print(f"Rejected:      {res['rejected_rows']}")
    for r in res["rejections"]:
        print(f"  row {r['row']}: {r['reason']}")
