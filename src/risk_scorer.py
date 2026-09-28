"""
RiskScorer - detection, scoring, classification, explanation (FR-04..FR-09, FR-14).

The core engine. For each user it walks their log records in time order,
comparing every event against the stored baseline and applying four rule-based
detectors:

  FR-04  time anomaly      - login outside the user's active-hours band
  FR-05  count anomaly     - too many failed logins within a time window
  FR-06  pattern anomaly   - failures then success from a never-seen IP
  FR-07  privilege anomaly - privilege level the baseline has never seen

Each firing detector contributes points. Points are summed into a cumulative
risk score (FR-08): a multi-anomaly event therefore scores strictly higher than
any single anomaly. The score maps to Low/Medium/High bands (FR-09), and a
plain-English explanation lists each contributing indicator by name (FR-14).

Design choices tied to the report:
  - Rule-based, not ML: every score traces to a named indicator (transparency,
    Section 2.2). Thresholds are constants here so they can be tuned against the
    evaluation set (Risk R1, Agile rationale Section 4.1) without touching logic.
  - Deterministic: same input -> same output every run (NFR-09).
  - All persistence via DatabaseManager (NFR-10).
"""

import json
from datetime import datetime, timedelta

# --- tunable detector parameters (Risk R1: tuned against evaluation set) -----
FAILED_LOGIN_THRESHOLD = 5            # FR-05: > this many failures...
FAILED_LOGIN_WINDOW_MIN = 10         # ...within this many minutes
PATTERN_FAILURE_MIN = 3              # FR-06: at least this many failures before success
TIME_TOLERANCE_HOURS = 1            # FR-04: grace band at each edge of active hours

# --- points each detector contributes to the cumulative score (FR-08) -------
POINTS = {
    "time": 30,
    "count": 35,
    "pattern": 40,
    "privilege": 45,
}

# --- classification bands (FR-09) -------------------------------------------
def classify(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 70:
        return "Medium"
    return "High"


class RiskScorer:
    def __init__(self, db):
        self.db = db

    def score_all(self) -> dict:
        """Score every user's events; persist alerts. Returns a summary."""
        summary = {"alerts": 0, "by_type": {"time": 0, "count": 0,
                                            "pattern": 0, "privilege": 0}}
        for user_id in self.db.all_user_ids():
            baseline = self.db.get_baseline(user_id)
            if not baseline:
                continue
            logs = self.db.get_logs_for_user(user_id)
            alerts = self._score_user(baseline, logs)
            for a in alerts:
                self.db.insert_alert(
                    user_id=user_id,
                    log_id=a["log_id"],
                    anomaly_type=",".join(a["indicators"]),
                    risk_score=a["score"],
                    risk_level=a["level"],
                    explanation=a["explanation"],
                )
                summary["alerts"] += 1
                for ind in a["indicators"]:
                    summary["by_type"][ind] += 1
        return summary

    # ---- per-user scoring -----------------------------------------------
    def _score_user(self, baseline, logs) -> list:
        """Return a list of alert dicts for one user's log records."""
        active_hours = baseline.get("active_hours")
        common_ips = set(baseline.get("common_ips") or [])
        known_privs = set(baseline.get("known_privileges") or [])

        # Pre-parse timestamps once for the whole user.
        parsed = []
        for l in logs:
            parsed.append({**l, "_ts": datetime.fromisoformat(l["timestamp"])})
        parsed.sort(key=lambda r: r["_ts"])

        alerts = []
        for i, rec in enumerate(parsed):
            indicators = []
            reasons = []
            score = 0

            # FR-04 time anomaly -----------------------------------------
            if rec["auth_outcome"] == "success" and active_hours:
                lo, hi = active_hours
                hour = rec["_ts"].hour
                if hour < lo - TIME_TOLERANCE_HOURS or hour > hi + TIME_TOLERANCE_HOURS:
                    indicators.append("time")
                    reasons.append(
                        f"Login at {rec['_ts'].strftime('%H:%M')} is outside "
                        f"normal active hours ({lo:02d}:00-{hi:02d}:00)"
                    )
                    score += POINTS["time"]

            # FR-07 privilege anomaly ------------------------------------
            if rec["privilege_level"] not in known_privs:
                indicators.append("privilege")
                reasons.append(
                    f"Privilege level '{rec['privilege_level']}' has never "
                    f"been used by this account before"
                )
                score += POINTS["privilege"]

            # FR-05 count anomaly ----------------------------------------
            # Raise on the event that pushes failures over threshold in-window.
            if rec["auth_outcome"] == "failure":
                window_start = rec["_ts"] - timedelta(minutes=FAILED_LOGIN_WINDOW_MIN)
                recent_failures = sum(
                    1 for r in parsed[: i + 1]
                    if r["auth_outcome"] == "failure" and r["_ts"] >= window_start
                )
                if recent_failures == FAILED_LOGIN_THRESHOLD + 1:
                    indicators.append("count")
                    reasons.append(
                        f"{recent_failures} failed logins within "
                        f"{FAILED_LOGIN_WINDOW_MIN} minutes"
                    )
                    score += POINTS["count"]

            # FR-06 pattern anomaly --------------------------------------
            # Success from an unseen IP, immediately preceded by >= N failures.
            if rec["auth_outcome"] == "success" and rec["source_ip"] not in common_ips:
                preceding_failures = 0
                for r in reversed(parsed[:i]):
                    if r["source_ip"] != rec["source_ip"]:
                        break
                    if r["auth_outcome"] == "failure":
                        preceding_failures += 1
                    else:
                        break
                if preceding_failures >= PATTERN_FAILURE_MIN:
                    indicators.append("pattern")
                    reasons.append(
                        f"Successful login from previously unseen IP "
                        f"{rec['source_ip']} after {preceding_failures} "
                        f"failed attempts"
                    )
                    score += POINTS["pattern"]

            if indicators:
                alerts.append({
                    "log_id": rec["log_id"],
                    "indicators": indicators,
                    "score": score,
                    "level": classify(score),
                    "explanation": " | ".join(reasons),
                })
        return alerts


if __name__ == "__main__":
    from db import DatabaseManager

    db = DatabaseManager()
    summary = RiskScorer(db).score_all()
    print(f"Alerts generated: {summary['alerts']}")
    print(f"By indicator:     {summary['by_type']}\n")

    counts = db.alert_counts_by_level()
    print(f"Risk levels -> High: {counts['High']}  "
          f"Medium: {counts['Medium']}  Low: {counts['Low']}")
