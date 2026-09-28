"""
Tests for DatabaseManager (the persistence gateway).

Each test uses an isolated temporary database, so nothing here depends on the
real data/itds.db or on any other module. This isolation is the practical
evidence for NFR-10.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from db import DatabaseManager


@pytest.fixture
def db():
    """A fresh DatabaseManager backed by a throwaway file."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    manager = DatabaseManager(db_path=tmp.name)
    yield manager
    try:
        Path(tmp.name).unlink(missing_ok=True)
    except PermissionError:
        pass

def test_get_or_create_user_is_idempotent(db):
    uid1 = db.get_or_create_user("alice")
    uid2 = db.get_or_create_user("alice")
    assert uid1 == uid2                       # same user -> same id
    assert db.all_user_ids() == [uid1]        # not duplicated


def test_insert_and_retrieve_log(db):
    uid = db.get_or_create_user("bob")
    db.insert_log(uid, "2026-01-01T09:00:00", "10.0.0.1", "success", "standard")
    logs = db.get_logs_for_user(uid)
    assert len(logs) == 1
    assert logs[0]["source_ip"] == "10.0.0.1"
    assert logs[0]["auth_outcome"] == "success"


def test_baseline_roundtrip_preserves_types(db):
    uid = db.get_or_create_user("carol")
    db.save_baseline(uid, active_hours=[9, 17], common_ips=["10.0.0.1"],
                     avg_login_frequency=2.5, known_privileges=["standard"])
    b = db.get_baseline(uid)
    # JSON fields must come back as Python lists, not strings.
    assert b["active_hours"] == [9, 17]
    assert b["common_ips"] == ["10.0.0.1"]
    assert b["known_privileges"] == ["standard"]
    assert b["avg_login_frequency"] == 2.5


def test_save_baseline_overwrites_not_duplicates(db):
    uid = db.get_or_create_user("dave")
    db.save_baseline(uid, [9, 17], ["10.0.0.1"], 2.0, ["standard"])
    db.save_baseline(uid, [8, 18], ["10.0.0.2"], 3.0, ["admin"])
    b = db.get_baseline(uid)
    assert b["active_hours"] == [8, 18]       # the second write wins
    assert b["common_ips"] == ["10.0.0.2"]


def test_alert_counts_by_level(db):
    uid = db.get_or_create_user("eve")
    lid = db.insert_log(uid, "2026-01-01T03:00:00", "10.0.0.1", "success", "standard")
    db.insert_alert(uid, lid, "time", 30, "Low", "off hours")
    db.insert_alert(uid, lid, "time,privilege", 75, "High", "off hours | new priv")
    counts = db.alert_counts_by_level()
    assert counts["Low"] == 1
    assert counts["High"] == 1
    assert counts["Total"] == 2


def test_get_alerts_filters_by_level(db):
    uid = db.get_or_create_user("frank")
    lid = db.insert_log(uid, "2026-01-01T03:00:00", "10.0.0.1", "success", "standard")
    db.insert_alert(uid, lid, "time", 30, "Low", "x")
    db.insert_alert(uid, lid, "privilege", 75, "High", "y")
    high = db.get_alerts(risk_level="High")
    assert len(high) == 1
    assert high[0]["risk_level"] == "High"


def test_reset_clears_all_data(db):
    uid = db.get_or_create_user("grace")
    db.insert_log(uid, "2026-01-01T09:00:00", "10.0.0.1", "success", "standard")
    db.reset()
    assert db.all_user_ids() == []
    assert db.alert_counts_by_level()["Total"] == 0
