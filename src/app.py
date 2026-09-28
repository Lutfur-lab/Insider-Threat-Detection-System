"""
Flask SOC dashboard - multi-page enterprise UI (FR-10..FR-14).

Pages:
  /          Dashboard - overview, metric cards, activity timeline (FR-10)
  /alerts    Alerts    - full filterable alert table + detail (FR-11, FR-14)
  /users     Users     - per-user behavioural baselines (FR-03 made visible)
  /upload    Upload    - ingest a new log file, runs the pipeline (FR-13)

All data is read through the DatabaseManager gateway (NFR-10). Secrets come
from environment variables (NFR-07).
"""

import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import (Flask, render_template, request, redirect, url_for, flash)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db import DatabaseManager
from log_parser import LogParser
from baseline_engine import BaselineEngine
from risk_scorer import RiskScorer

_ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__,
            template_folder=str(_ROOT / "templates"),
            static_folder=str(_ROOT / "static"))
app.secret_key = os.environ.get("ITDS_SECRET_KEY", "dev-only-not-for-release")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024   # 10 MB upload limit

db = DatabaseManager()


def _usernames():
    return sorted({a["username"] for a in db.get_alerts()})


def _timeline_buckets(alerts):
    buckets = defaultdict(int)
    for a in alerts:
        try:
            buckets[datetime.fromisoformat(a["timestamp"]).hour] += 1
        except (ValueError, KeyError):
            continue
    return {h: buckets.get(h, 0) for h in range(24)}


@app.route("/")
def dashboard():
    alerts = db.get_alerts()
    counts = db.alert_counts_by_level()
    timeline = _timeline_buckets(alerts)
    # type breakdown for the dashboard
    type_counts = defaultdict(int)
    for a in alerts:
        for t in a["anomaly_type"].split(","):
            type_counts[t] += 1
    return render_template("dashboard.html", active="dashboard",
                           alerts=alerts[:6], counts=counts, timeline=timeline,
                           type_counts=dict(type_counts),
                           total_users=len(db.all_user_ids()))


@app.route("/alerts")
def alerts_page():
    user = request.args.get("user") or None
    risk_level = request.args.get("risk_level") or None
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    alerts = db.get_alerts(user=user, risk_level=risk_level,
                           date_from=date_from, date_to=date_to)
    return render_template("alerts.html", active="alerts",
                           alerts=alerts, usernames=_usernames(),
                           counts=db.alert_counts_by_level(),
                           filters={"user": user, "risk_level": risk_level,
                                    "date_from": date_from, "date_to": date_to})


@app.route("/users")
def users_page():
    return render_template("users.html", active="users",
                           baselines=db.all_baselines_with_usernames(),
                           counts=db.alert_counts_by_level())


@app.route("/upload", methods=["GET", "POST"])
def upload_page():
    if request.method == "GET":
        return render_template("upload.html", active="upload",
                               counts=db.alert_counts_by_level())

    file = request.files.get("logfile")
    if not file or file.filename == "":
        flash("Choose a CSV file to analyse.", "error")
        return redirect(url_for("upload_page"))
    if not file.filename.lower().endswith(".csv"):
        flash("That file isn't a CSV. Upload a .csv log file.", "error")
        return redirect(url_for("upload_page"))

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name
    try:
        parse = LogParser(db).parse_csv(tmp_path)
        # Use the SAME baseline cutoff as the backend seed path so an uploaded
        # CSV produces alerts identical to the backend-loaded file (FR-13).
        # Configurable via env; the default matches seed.py. If unset/empty,
        # the baseline is built over all history.
        cutoff = os.environ.get("ITDS_BASELINE_CUTOFF", "2026-01-22") or None
        BaselineEngine(db).build_all(cutoff=cutoff)
        score = RiskScorer(db).score_all()
        flash(f"Analysed {parse['valid_rows']} records "
              f"({parse['rejected_rows']} rejected). "
              f"{score['alerts']} alerts generated.", "success")
    except Exception as e:
        flash(f"Couldn't analyse that file: {e}", "error")
    finally:
        os.unlink(tmp_path)
    return redirect(url_for("alerts_page"))


if __name__ == "__main__":
    port = int(os.environ.get("ITDS_PORT", 5000))
    app.run(host="127.0.0.1", port=port,
            debug=os.environ.get("FLASK_DEBUG", "0") == "1")
