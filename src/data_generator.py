"""
Synthetic log data generator.

Produces a labelled CSV: normal authentication activity plus deliberately
injected insider-threat events. Every row carries a ground-truth label so the
evaluation harness can compute detection rate and false-positive rate against
the targets in Section 1.4 (>80% detection, <20% FPR).

Threat types injected map 1:1 to the four detectors (FR-04..FR-07):
  - time      : login outside the user's normal hours
  - count     : burst of failed logins (brute-force-like)
  - pattern   : failures then success from a never-seen IP
  - privilege : standard user attempting admin-level access

Behaviour is grounded in CERT-style insider patterns (mitigates Risk R2).
Output columns: username, timestamp, source_ip, auth_outcome, privilege_level, label
  label = "normal" for benign rows, otherwise the threat type.

Reproducible: a fixed seed makes the dataset byte-identical across runs,
supporting NFR-09.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 42
USERS = [f"user_{i:03d}" for i in range(1, 13)]   # 12 users
BASELINE_DAYS = 21                                # >14 days, satisfies FR-03 / R7
WORK_START, WORK_END = 9, 17                       # normal active hours


def _user_home_ips(rng):
    """Give each user 1-2 stable 'home' IPs they normally log in from."""
    home = {}
    for u in USERS:
        n = rng.choice([1, 2])
        home[u] = [f"10.0.{rng.randint(0,50)}.{rng.randint(1,254)}" for _ in range(n)]
    return home


def generate(out_path: str, seed: int = SEED) -> dict:
    rng = random.Random(seed)
    home_ips = _user_home_ips(rng)
    start_day = datetime(2026, 1, 1)
    rows = []

    # ---- 1. NORMAL ACTIVITY: baseline-building period -------------------
    for day in range(BASELINE_DAYS):
        date = start_day + timedelta(days=day)
        if date.weekday() >= 5:        # lighter weekend activity
            active_users = rng.sample(USERS, k=3)
        else:
            active_users = USERS
        for u in active_users:
            logins = rng.randint(1, 4)
            for _ in range(logins):
                hour = rng.randint(WORK_START, WORK_END - 1)
                minute = rng.randint(0, 59)
                ts = date.replace(hour=hour, minute=minute)
                ip = rng.choice(home_ips[u])
                # occasional benign failure (mistyped password) -> still normal
                outcome = "failure" if rng.random() < 0.05 else "success"
                rows.append([u, ts, ip, outcome, "standard", "normal"])

    # Track counts of injected threats for the manifest
    injected = {"time": 0, "count": 0, "pattern": 0, "privilege": 0}
    threat_day = start_day + timedelta(days=BASELINE_DAYS)  # threats land after baseline

    # ---- 2. TIME ANOMALIES (FR-04) -------------------------------------
    for u in rng.sample(USERS, k=4):
        ts = threat_day.replace(hour=rng.choice([2, 3, 4]), minute=rng.randint(0, 59))
        rows.append([u, ts, rng.choice(home_ips[u]), "success", "standard", "time"])
        injected["time"] += 1

    # ---- 3. COUNT ANOMALIES (FR-05): failed-login burst ----------------
    for u in rng.sample(USERS, k=3):
        base = threat_day.replace(hour=11, minute=rng.randint(0, 30))
        for k in range(6):             # 6 failures within minutes
            ts = base + timedelta(minutes=k)
            rows.append([u, ts, rng.choice(home_ips[u]), "failure", "standard", "count"])
            injected["count"] += 1

    # ---- 4. PATTERN ANOMALIES (FR-06): fails then success from new IP --
    for u in rng.sample(USERS, k=3):
        new_ip = f"203.0.{rng.randint(1,254)}.{rng.randint(1,254)}"  # never-seen range
        base = threat_day.replace(hour=14, minute=rng.randint(0, 30))
        for k in range(3):
            rows.append([u, base + timedelta(minutes=k), new_ip, "failure", "standard", "pattern"])
            injected["pattern"] += 1
        # the successful breach from the same new IP
        rows.append([u, base + timedelta(minutes=4), new_ip, "success", "standard", "pattern"])
        injected["pattern"] += 1

    # ---- 5. PRIVILEGE ANOMALIES (FR-07) --------------------------------
    for u in rng.sample(USERS, k=3):
        ts = threat_day.replace(hour=15, minute=rng.randint(0, 59))
        rows.append([u, ts, rng.choice(home_ips[u]), "success", "admin", "privilege"])
        injected["privilege"] += 1

    # ---- 5b. COMBINED ANOMALY (FR-08 / FR-09 High band) ----------------
    # A single event that trips TWO detectors at once: an off-hours login
    # that is ALSO a privilege escalation. Time (30) + privilege (45) = 75,
    # which classifies High and proves multi-anomaly events score strictly
    # higher than single-anomaly ones.
    injected["combined"] = 0
    for u in rng.sample(USERS, k=2):
        ts = threat_day.replace(hour=3, minute=rng.randint(0, 59))   # off-hours
        rows.append([u, ts, rng.choice(home_ips[u]), "success", "admin", "combined"])
        injected["combined"] += 1

    # ---- 6. A few malformed rows to exercise validation (FR-02) --------
    malformed = [
        ["user_001", "not-a-date", "10.0.1.1", "success", "standard", "MALFORMED"],
        ["", datetime(2026,1,22,10,0), "10.0.1.2", "success", "standard", "MALFORMED"],
        ["user_002", datetime(2026,1,22,10,5), "10.0.1.3", "banana", "standard", "MALFORMED"],
    ]

    # Sort the valid rows chronologically, then append malformed at the end.
    rows.sort(key=lambda r: r[1])
    all_rows = rows + malformed

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "timestamp", "source_ip", "auth_outcome",
                    "privilege_level", "label"])
        for r in all_rows:
            ts = r[1].isoformat() if isinstance(r[1], datetime) else r[1]
            w.writerow([r[0], ts, r[2], r[3], r[4], r[5]])

    manifest = {
        "total_rows": len(all_rows),
        "normal_rows": sum(1 for r in rows if r[5] == "normal"),
        "malformed_rows": len(malformed),
        "injected_threats": injected,
        "total_injected": sum(injected.values()),
    }
    return manifest


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"
    m = generate(str(out))
    print(f"Wrote {out}")
    for k, v in m.items():
        print(f"  {k}: {v}")
