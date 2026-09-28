"""
BaselineEngine - per-user behavioural profiling (FR-03).

For each user, builds a profile from their historical log records:
  - active_hours        : [earliest_typical_hour, latest_typical_hour]
  - common_ips          : IPs the user normally logs in from
  - avg_login_frequency : average successful logins per active day
  - known_privileges    : privilege levels ever legitimately seen

This is the "normal" the RiskScorer measures deviation against. It reads logs
and writes baselines ONLY through DatabaseManager (no raw SQL, NFR-10), and is
unit-testable in isolation.

Two design safeguards from the report:
  - MIN_BASELINE_DAYS (Risk R7): a user needs >= 14 days of history before a
    baseline is trusted; sparser users are flagged, not silently profiled.
  - Active hours use a percentile band (5th-95th) rather than absolute min/max,
    so a single odd-hour login during the baseline period doesn't widen the
    "normal" window and mask future time anomalies.
"""

import json
from collections import Counter
from datetime import datetime

MIN_BASELINE_DAYS = 14          # Risk R7 minimum window
IP_COMMON_THRESHOLD = 0.10      # an IP seen in >=10% of logins counts as "common"
LOWER_PCTL, UPPER_PCTL = 5, 95  # active-hour band


class BaselineEngine:
    def __init__(self, db):
        self.db = db

    def build_all(self, cutoff: str | None = None) -> dict:
        """
        Build/refresh baselines for every user. Returns a summary.

        cutoff: optional ISO timestamp. If given, only log records strictly
        before it are used to learn the baseline. This models the real-world
        practice of profiling a known-clean historical window, then scoring
        later events against it — and prevents threat events from contaminating
        the very baseline meant to detect them.
        """
        summary = {"profiled": 0, "sparse": 0, "users": {}}
        for user_id in self.db.all_user_ids():
            profile = self.build_for_user(user_id, cutoff=cutoff)
            summary["users"][user_id] = profile
            if profile["sparse"]:
                summary["sparse"] += 1
            else:
                summary["profiled"] += 1
        return summary

    def build_for_user(self, user_id, cutoff: str | None = None) -> dict:
        logs = self.db.get_logs_for_user(user_id)
        if cutoff:
            logs = [l for l in logs if l["timestamp"] < cutoff]
        successes = [l for l in logs if l["auth_outcome"] == "success"]

        # Parse timestamps once.
        times = [datetime.fromisoformat(l["timestamp"]) for l in successes]
        days = {t.date() for t in times}
        span_days = (max(days) - min(days)).days + 1 if days else 0
        sparse = span_days < MIN_BASELINE_DAYS or len(successes) < MIN_BASELINE_DAYS

        # --- active hours: percentile band over successful-login hours -----
        hours = sorted(t.hour for t in times)
        if hours:
            active_hours = [self._percentile(hours, LOWER_PCTL),
                            self._percentile(hours, UPPER_PCTL)]
        else:
            active_hours = None

        # --- common IPs ----------------------------------------------------
        ip_counts = Counter(l["source_ip"] for l in successes)
        total = sum(ip_counts.values()) or 1
        common_ips = [ip for ip, c in ip_counts.items()
                      if c / total >= IP_COMMON_THRESHOLD]

        # --- average daily login frequency ---------------------------------
        avg_freq = round(len(successes) / len(days), 2) if days else 0.0

        # --- known privilege levels (from ALL logs, not just successes) ----
        known_privileges = sorted({l["privilege_level"] for l in logs})

        profile = {
            "user_id": user_id,
            "active_hours": active_hours,
            "common_ips": common_ips,
            "avg_login_frequency": avg_freq,
            "known_privileges": known_privileges,
            "span_days": span_days,
            "login_count": len(successes),
            "sparse": sparse,
        }

        # Persist via gateway. Sparse users still get a baseline written, but the
        # 'sparse' flag lets the dashboard mark them and the scorer treat them
        # cautiously.
        self.db.save_baseline(
            user_id=user_id,
            active_hours=active_hours,
            common_ips=common_ips,
            avg_login_frequency=avg_freq,
            known_privileges=known_privileges,
        )
        return profile

    @staticmethod
    def _percentile(sorted_vals: list, pct: float):
        """Simple nearest-rank percentile on a pre-sorted list of ints."""
        if not sorted_vals:
            return None
        k = (len(sorted_vals) - 1) * (pct / 100.0)
        lo = int(k)
        hi = min(lo + 1, len(sorted_vals) - 1)
        # linear interpolation, then round to a whole hour
        val = sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)
        return int(round(val))


if __name__ == "__main__":
    from db import DatabaseManager

    db = DatabaseManager()
    engine = BaselineEngine(db)
    summary = engine.build_all()
    print(f"Profiled: {summary['profiled']}   Sparse: {summary['sparse']}\n")
    for uid, p in sorted(summary["users"].items()):
        flag = " [SPARSE]" if p["sparse"] else ""
        print(f"user_id {uid}: hours={p['active_hours']} "
              f"freq={p['avg_login_frequency']}/day "
              f"IPs={len(p['common_ips'])} "
              f"privs={p['known_privileges']} "
              f"({p['login_count']} logins / {p['span_days']}d){flag}")
