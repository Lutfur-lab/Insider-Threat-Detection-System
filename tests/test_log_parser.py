"""
Tests for LogParser (FR-01, FR-02).

Validation is tested in isolation by passing the parser a fresh temp-backed
DatabaseManager and small purpose-built CSVs. We assert on which rows are
accepted and rejected, and on the rejection reasons.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from db import DatabaseManager
from log_parser import LogParser

HEADER = "username,timestamp,source_ip,auth_outcome,privilege_level\n"


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



def _write_csv(rows: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    tmp.write(HEADER + rows)
    tmp.close()
    return tmp.name


def test_valid_rows_are_stored(db):
    csv = _write_csv(
        "alice,2026-01-01T09:00:00,10.0.0.1,success,standard\n"
        "bob,2026-01-01T10:30:00,10.0.0.2,failure,standard\n"
    )
    res = LogParser(db).parse_csv(csv)
    assert res["valid_rows"] == 2
    assert res["rejected_rows"] == 0


def test_rejects_bad_timestamp(db):
    csv = _write_csv("alice,not-a-date,10.0.0.1,success,standard\n")
    res = LogParser(db).parse_csv(csv)
    assert res["rejected_rows"] == 1
    assert "timestamp" in res["rejections"][0]["reason"]


def test_rejects_empty_username(db):
    csv = _write_csv(",2026-01-01T09:00:00,10.0.0.1,success,standard\n")
    res = LogParser(db).parse_csv(csv)
    assert res["rejected_rows"] == 1
    assert "username" in res["rejections"][0]["reason"]


def test_rejects_invalid_ip(db):
    csv = _write_csv("alice,2026-01-01T09:00:00,999.999.1.1,success,standard\n")
    res = LogParser(db).parse_csv(csv)
    assert res["rejected_rows"] == 1
    assert "source_ip" in res["rejections"][0]["reason"]


def test_rejects_invalid_outcome(db):
    csv = _write_csv("alice,2026-01-01T09:00:00,10.0.0.1,banana,standard\n")
    res = LogParser(db).parse_csv(csv)
    assert res["rejected_rows"] == 1
    assert "auth_outcome" in res["rejections"][0]["reason"]


def test_valid_rows_pass_through_when_mixed_with_invalid(db):
    # FR-02 acceptance: valid rows unchanged, invalid logged per row.
    csv = _write_csv(
        "alice,2026-01-01T09:00:00,10.0.0.1,success,standard\n"
        "bob,bad-date,10.0.0.2,success,standard\n"
        "carol,2026-01-01T11:00:00,10.0.0.3,success,admin\n"
    )
    res = LogParser(db).parse_csv(csv)
    assert res["valid_rows"] == 2
    assert res["rejected_rows"] == 1
    assert res["rejections"][0]["row"] == 3   # bob is on CSV line 3


def test_missing_required_column_raises(db):
    bad = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    bad.write("username,timestamp,source_ip\nalice,2026-01-01T09:00:00,10.0.0.1\n")
    bad.close()
    with pytest.raises(ValueError):
        LogParser(db).parse_csv(bad.name)
