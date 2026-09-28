"""
Tests for BaselineEngine (FR-03).

Uses a temp-backed DatabaseManager. Verifies active-hours banding, common-IP
selection, the sparse-user flag (Risk R7), and that the cutoff excludes later
records from the learned baseline.
"""

import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from db import DatabaseManager
from baseline_engine import BaselineEngine


@pytest.fixture
def db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    manager = DatabaseManager(db_path=tmp.name)
    yield manager
    try:
        Path(tmp.name).unlink(missing_ok=True)
    except PermissionError:
        pass


def _seed_user(db, username, days=20, hour=10, ip="10.0.0.1"):
    """Insert `days` successful logins, one per day at a fixed hour."""
    uid = db.get_or_create_user(username)
    start = datetime(2026, 1, 1, hour, 0)
    for d in range(days):
        ts = (start + timedelta(days=d)).isoformat()
        db.insert_log(uid, ts, ip, "success", "standard")
    return uid


def test_baseline_captures_active_hours(db):
    uid = _seed_user(db, "alice", days=20, hour=10)
    profile = BaselineEngine(db).build_for_user(uid)
    lo, hi = profile["active_hours"]
    assert lo <= 10 <= hi


def test_common_ip_is_identified(db):
    uid = _seed_user(db, "bob", days=20, ip="10.0.0.5")
    profile = BaselineEngine(db).build_for_user(uid)
    assert "10.0.0.5" in profile["common_ips"]


def test_sparse_user_is_flagged(db):
    # Only 5 days of history -> below the 14-day minimum (Risk R7).
    uid = _seed_user(db, "carol", days=5)
    profile = BaselineEngine(db).build_for_user(uid)
    assert profile["sparse"] is True


def test_sufficient_history_not_sparse(db):
    uid = _seed_user(db, "dave", days=20)
    profile = BaselineEngine(db).build_for_user(uid)
    assert profile["sparse"] is False


def test_cutoff_excludes_later_records(db):
    # 20 days of standard logins, then an admin login on day 25.
    uid = _seed_user(db, "eve", days=20, hour=10)
    late = datetime(2026, 1, 25, 3, 0).isoformat()
    db.insert_log(uid, late, "10.0.0.1", "success", "admin")

    # Without cutoff, 'admin' is learned as known.
    full = BaselineEngine(db).build_for_user(uid)
    assert "admin" in full["known_privileges"]

    # With a cutoff before day 25, 'admin' must NOT be in the baseline.
    cut = BaselineEngine(db).build_for_user(uid, cutoff="2026-01-22")
    assert "admin" not in cut["known_privileges"]
