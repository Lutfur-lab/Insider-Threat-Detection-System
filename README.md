# Behaviour-Based Insider Threat Detection System (ITDS)

A lightweight, rule-based insider threat detection prototype that ingests
authentication logs, builds per-user behavioural baselines, scores anomalous
activity, and presents alerts on a web-based SOC dashboard.

Built as my BSc Computing Project at Ulster University (COM668).

> **Why this matters for SOC work:** the four detection rules map directly to
> MITRE ATT&CK techniques that Tier 1 analysts triage every day. Building the
> engine from scratch taught me what fires inside a SIEM correlation rule, how
> false-positive rates are managed, and why explainable scoring matters more
> than raw detection rate.

---

## MITRE ATT&CK mapping

| Detection rule | ATT&CK technique | ID | What it catches |
|---|---|---|---|
| Failed-login burst | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | >5 failures in 10 min for one account |
| Off-hours login | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Successful login outside the user's normal hours |
| New IP after failures | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Success from an unseen IP after repeated failures |
| Privilege anomaly | Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Privilege level never seen for this account |

---

## What it does

1. **Ingests** a CSV of authentication logs (username, timestamp, source IP,
   auth outcome, privilege level) and validates every row.
2. **Builds a behavioural baseline** per user — active hours (5th–95th
   percentile), common IPs, login frequency, known privilege levels.
3. **Applies four rule-based detectors** (see ATT&CK table above).
4. **Scores and classifies** each event as Low / Medium / High with a
   plain-English explanation listing every contributing indicator.
5. **Serves a dark SOC dashboard** with metric cards, alert table, detail
   panel, activity timeline, filters, and CSV upload.

---

## Evaluation results (held-out data)

Tuned on seed 42, evaluated on a **separate** dataset (seed 2026) the system
was never trained against. See [EVALUATION.md](EVALUATION.md) for full method.

| Metric | Result | Target |
|---|---|---|
| Detection rate | 100% | > 80% |
| False positive rate | 0% | < 20% |
| Unit tests | 33 passing | — |

**Known limitation:** a slow brute force (5 failures spread over 30 minutes)
evades the time-window rule. This is the defining property of rule-based
detection — it catches what it's configured to catch. A production SIEM
layers multiple detection methods to cover this gap.

---

## Quick start

```bash
# 1. Set up
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Generate data and populate the database
python src/seed.py

# 3. Start the dashboard
python src/app.py
# Open http://127.0.0.1:5000
```

---

## Run evaluation and tests

```bash
python src/evaluate.py           # detection rate + false positive rate
python -m pytest tests/ -v       # 33 unit tests (one set per module)
```

---

## Project structure

```
itds/
├── README.md
├── EVALUATION.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── log_parser.py         LogParser — ingestion + validation (FR-01, FR-02)
│   ├── baseline_engine.py    BaselineEngine — per-user profiles (FR-03)
│   ├── risk_scorer.py        RiskScorer — detect/score/classify (FR-04..FR-09, FR-14)
│   ├── db.py                 DatabaseManager — single persistence gateway
│   ├── schema.sql            SQLite schema (matches the ERD)
│   ├── data_generator.py     Synthetic labelled log generator
│   ├── evaluate.py           Held-out evaluation harness
│   ├── seed.py               One-shot: generate → parse → baseline → score
│   └── app.py                Flask SOC dashboard (FR-10..FR-14)
├── templates/
│   ├── base.html             Shared dark-theme layout
│   ├── dashboard.html        Overview, metric cards, activity timeline
│   ├── alerts.html           Filterable alert table + detail panel
│   ├── users.html            Per-user baseline viewer
│   └── upload.html           CSV upload and analysis
├── tests/
│   ├── test_log_parser.py
│   ├── test_baseline_engine.py
│   ├── test_risk_scorer.py
│   └── test_db.py
└── data/                     Generated at runtime by seed.py
```

---

## Security hardening applied

| Risk | Mitigation |
|---|---|
| Stored XSS via crafted CSV | Username regex whitelist + privilege level whitelist in parser; HTML escaping in dashboard JS |
| Upload wipes existing data | Upload appends and re-scores instead of resetting |
| Debug mode in production | Debug disabled by default; set `FLASK_DEBUG=1` explicitly for development |
| Oversized uploads | 10 MB limit enforced by Flask |
| Hardcoded secrets | Secret key and DB path read from environment variables (NFR-07) |

---

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `ITDS_DB_PATH` | `data/itds.db` | SQLite database location |
| `ITDS_SECRET_KEY` | `dev-only-not-for-release` | Flask session secret (set this for any real deployment) |
| `ITDS_PORT` | `5000` | Dashboard port |
| `FLASK_DEBUG` | `0` | Set to `1` for development only |
| `ITDS_BASELINE_CUTOFF` | `2026-01-22` | Baseline learns only from logs before this date |

---

## Tech stack

Python 3.10+, Flask, Pandas, SQLite. No database server, no admin rights,
no specialist infrastructure — deployable on a standard laptop (NFR-04).
