"""
Tests for RiskScorer (FR-04..FR-09, FR-14).

These are the most important tests: the evaluation numbers are only meaningful
if the scorer is correct. We use a lightweight FakeDB (no SQLite at all) to
prove the scorer works in genuine isolation — strong evidence for NFR-10 — and
we test each detector independently, the cumulative scoring rule (FR-08), and
the exact classification boundaries (FR-09).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from risk_scorer import RiskScorer, classify


class FakeDB:
    """Minimal in-memory stand-in for DatabaseManager."""
    def __init__(self, baseline, logs):
        self._baseline = baseline
        self._logs = logs
        self.alerts = []

    def all_user_ids(self):
        return [1]

    def get_baseline(self, user_id):
        return self._baseline

    def get_logs_for_user(self, user_id):
        return self._logs

    def insert_alert(self, user_id, log_id, anomaly_type, risk_score,
                     risk_level, explanation):
        self.alerts.append({
            "log_id": log_id, "anomaly_type": anomaly_type,
            "risk_score": risk_score, "risk_level": risk_level,
            "explanation": explanation,
        })


BASELINE = {
    "active_hours": [9, 17],
    "common_ips": ["10.0.0.1"],
    "avg_login_frequency": 2.0,
    "known_privileges": ["standard"],
}


def _log(log_id, ts, ip="10.0.0.1", outcome="success", priv="standard"):
    return {"log_id": log_id, "user_id": 1, "timestamp": ts,
            "source_ip": ip, "auth_outcome": outcome, "privilege_level": priv}


# ---- classification boundaries (FR-09) -------------------------------------
@pytest.mark.parametrize("score,level", [
    (0, "Low"), (30, "Low"),
    (31, "Medium"), (70, "Medium"),
    (71, "High"), (100, "High"),
])
def test_classification_boundaries(score, level):
    assert classify(score) == level


# ---- individual detectors --------------------------------------------------
def test_time_anomaly_fires_outside_hours():
    db = FakeDB(BASELINE, [_log(1, "2026-02-01T03:00:00")])
    RiskScorer(db).score_all()
    assert len(db.alerts) == 1
    assert "time" in db.alerts[0]["anomaly_type"]


def test_time_anomaly_silent_within_hours():
    db = FakeDB(BASELINE, [_log(1, "2026-02-01T12:00:00")])
    RiskScorer(db).score_all()
    assert db.alerts == []


def test_privilege_anomaly_fires_on_unseen_privilege():
    db = FakeDB(BASELINE, [_log(1, "2026-02-01T12:00:00", priv="admin")])
    RiskScorer(db).score_all()
    assert len(db.alerts) == 1
    assert "privilege" in db.alerts[0]["anomaly_type"]


def test_count_anomaly_fires_on_failure_burst():
    logs = [_log(i, f"2026-02-01T11:0{i}:00", outcome="failure")
            for i in range(6)]   # 6 failures in 6 minutes
    db = FakeDB(BASELINE, logs)
    RiskScorer(db).score_all()
    assert any("count" in a["anomaly_type"] for a in db.alerts)


def test_pattern_anomaly_fires_on_fails_then_new_ip_success():
    new_ip = "203.0.1.1"
    logs = [
        _log(1, "2026-02-01T14:00:00", ip=new_ip, outcome="failure"),
        _log(2, "2026-02-01T14:01:00", ip=new_ip, outcome="failure"),
        _log(3, "2026-02-01T14:02:00", ip=new_ip, outcome="failure"),
        _log(4, "2026-02-01T14:03:00", ip=new_ip, outcome="success"),
    ]
    db = FakeDB(BASELINE, logs)
    RiskScorer(db).score_all()
    assert any("pattern" in a["anomaly_type"] for a in db.alerts)


# ---- cumulative scoring (FR-08) --------------------------------------------
def test_multi_anomaly_scores_higher_than_single():
    # An off-hours admin login trips BOTH time and privilege.
    combined = FakeDB(BASELINE, [_log(1, "2026-02-01T03:00:00", priv="admin")])
    RiskScorer(combined).score_all()

    single = FakeDB(BASELINE, [_log(1, "2026-02-01T03:00:00")])  # time only
    RiskScorer(single).score_all()

    combined_score = combined.alerts[0]["risk_score"]
    single_score = single.alerts[0]["risk_score"]
    assert combined_score > single_score
    assert combined.alerts[0]["risk_level"] == "High"


# ---- explanation (FR-14) ---------------------------------------------------
def test_explanation_names_each_indicator():
    db = FakeDB(BASELINE, [_log(1, "2026-02-01T03:00:00", priv="admin")])
    RiskScorer(db).score_all()
    expl = db.alerts[0]["explanation"]
    assert "active hours" in expl       # the time indicator
    assert "Privilege" in expl          # the privilege indicator


# ---- determinism (NFR-09) --------------------------------------------------
def test_scoring_is_deterministic():
    logs = [_log(1, "2026-02-01T03:00:00", priv="admin")]
    runs = []
    for _ in range(3):
        db = FakeDB(BASELINE, list(logs))
        RiskScorer(db).score_all()
        runs.append((db.alerts[0]["risk_score"], db.alerts[0]["explanation"]))
    assert runs[0] == runs[1] == runs[2]
