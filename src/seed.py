"""
seed.py - one-shot setup.

Generates synthetic labelled logs, then runs the full pipeline:
  generate -> parse/validate -> build baselines -> score -> store alerts.

Run this once before starting the dashboard:
    python src/seed.py
    python src/app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import DatabaseManager
from data_generator import generate
from log_parser import LogParser
from baseline_engine import BaselineEngine
from risk_scorer import RiskScorer

# Threats are injected after this date in the synthetic data; the baseline
# learns only from the clean period before it. Sourced from the same env var
# the dashboard upload uses, so both paths apply an identical cutoff (FR-13).
import os
BASELINE_CUTOFF = os.environ.get("ITDS_BASELINE_CUTOFF", "2026-01-22")


def main():
    root = Path(__file__).resolve().parent.parent
    csv_path = root / "data" / "sample_logs.csv"

    db = DatabaseManager()
    db.reset()

    print("Generating synthetic log data...")
    manifest = generate(str(csv_path))
    print(f"  {manifest['total_rows']} rows "
          f"({manifest['total_injected']} injected threats, "
          f"{manifest['malformed_rows']} malformed)")

    print("Parsing and validating...")
    parse = LogParser(db).parse_csv(str(csv_path))
    print(f"  {parse['valid_rows']} valid, {parse['rejected_rows']} rejected")

    print("Building baselines...")
    BaselineEngine(db).build_all(cutoff=BASELINE_CUTOFF)

    print("Scoring...")
    score = RiskScorer(db).score_all()
    counts = db.alert_counts_by_level()
    print(f"  {score['alerts']} alerts — "
          f"High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}")

    print("\nDone. Now run:  python src/app.py")
    print("Then open:      http://127.0.0.1:5000")


if __name__ == "__main__":
    main()
