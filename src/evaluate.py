"""
Evaluation harness (Section 1.4 success criteria).

Measures the system honestly:
  - Detection rate = true positives / total injected threats   (target > 80%)
  - False positive rate = false positives / total normal events (target < 20%)

Crucially, evaluation runs on a HELD-OUT dataset generated with a different
random seed from the one the detectors were tuned against. Testing on unseen
data prevents the circular "tuned and tested on the same file" result and shows
the system generalises rather than memorises. This directly addresses the
simulation-validity concern in Risk R2.

Method:
  1. Generate held-out labelled data (seed != tuning seed).
  2. Run the full pipeline (parse -> baseline -> score) on it.
  3. For each generated alert, look up the ground-truth label of its log record.
     - alert on a threat row  -> true positive
     - alert on a normal row  -> false positive
  4. A threat is "detected" if at least one alert fired on any of its rows.
"""

import sys
import csv
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import DatabaseManager
from data_generator import generate
from log_parser import LogParser
from baseline_engine import BaselineEngine
from risk_scorer import RiskScorer

HELDOUT_SEED = 2026          # different from the tuning seed (42)
BASELINE_CUTOFF = "2026-01-22"

# Each injected-threat label and how many log rows make up one "threat instance".
# time/privilege/combined = 1 row each. count = a burst of 6 rows = 1 instance.
# pattern = 4 rows (3 fails + 1 success) = 1 instance.
THREAT_ROWS_PER_INSTANCE = {
    "time": 1, "privilege": 1, "combined": 1, "count": 6, "pattern": 4,
}


def _load_labels(csv_path):
    """Map (username, timestamp) -> ground-truth label."""
    labels = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[(row["username"], row["timestamp"])] = row["label"]
    return labels


def evaluate():
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "data" / "heldout_logs.csv"

    # 1. Held-out data with a DIFFERENT seed.
    manifest = generate(str(csv_path), seed=HELDOUT_SEED)

    # 2. Full pipeline on a clean DB.
    db = DatabaseManager()
    db.reset()
    LogParser(db).parse_csv(str(csv_path))
    BaselineEngine(db).build_all(cutoff=BASELINE_CUTOFF)
    RiskScorer(db).score_all()

    # 3. Ground-truth labels and alerts.
    labels = _load_labels(csv_path)
    alerts = db.get_alerts()

    # Count normal vs threat rows from the labels (exclude malformed).
    total_normal = sum(1 for lbl in labels.values() if lbl == "normal")

    # Total injected threat INSTANCES (not rows).
    threat_rows = defaultdict(int)
    for lbl in labels.values():
        if lbl in THREAT_ROWS_PER_INSTANCE:
            threat_rows[lbl] += 1
    total_threats = sum(
        threat_rows[t] // THREAT_ROWS_PER_INSTANCE[t] for t in threat_rows
    )

    # 4. Classify each alert as TP or FP via its log record's label.
    true_positives = 0
    false_positives = 0
    detected_threat_keys = set()

    for a in alerts:
        key = (a["username"], a["timestamp"])
        label = labels.get(key, "unknown")
        if label in THREAT_ROWS_PER_INSTANCE:
            true_positives += 1
            detected_threat_keys.add((a["username"], label, a["timestamp"][:10]))
        elif label == "normal":
            false_positives += 1
        # malformed/unknown shouldn't appear (they were rejected); ignore.

    # Detection rate: fraction of injected threat instances that produced
    # at least one alert. Approximate instance-detection by counting distinct
    # (user, threat-type) detections, capped at the number injected.
    detected_instances = min(len(detected_threat_keys), total_threats)
    detection_rate = (detected_instances / total_threats * 100) if total_threats else 0
    fpr = (false_positives / total_normal * 100) if total_normal else 0

    # ---- report ----------------------------------------------------------
    print("=" * 60)
    print("EVALUATION — held-out dataset (seed =", HELDOUT_SEED, ")")
    print("=" * 60)
    print(f"Normal events:           {total_normal}")
    print(f"Injected threats:        {total_threats}")
    print(f"Alerts generated:        {len(alerts)}")
    print("-" * 60)
    print(f"True positives:          {true_positives}")
    print(f"False positives:         {false_positives}")
    print(f"Threats detected:        {detected_instances}/{total_threats}")
    print("-" * 60)
    print(f"Detection rate:          {detection_rate:.1f}%   (target > 80%)  "
          f"{'PASS' if detection_rate > 80 else 'FAIL'}")
    print(f"False positive rate:     {fpr:.1f}%   (target < 20%)  "
          f"{'PASS' if fpr < 20 else 'FAIL'}")
    print("=" * 60)

    return {
        "total_normal": total_normal,
        "total_threats": total_threats,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "detection_rate": round(detection_rate, 1),
        "false_positive_rate": round(fpr, 1),
    }


if __name__ == "__main__":
    evaluate()
