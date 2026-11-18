import sqlite3

import pytest

from blackarch2kali.collectors.blackarch import parse_db
from blackarch2kali.config import load_settings
from blackarch2kali.database.repository import Database
from blackarch2kali.errors import ConfigError, DatabaseError


def test_upsert_history_and_removal(ba_db_bytes, tmp_path):
    db = Database(tmp_path / "t.sqlite")
    pkgs = parse_db(ba_db_bytes, "u").packages
    amass = pkgs["amass"]
    assert db.upsert_package(amass) is True
    assert db.upsert_package(amass) is False  # unchanged, provenance excluded
    newer = amass.model_copy(update={"version": "9-1"})
    assert db.upsert_package(newer) is True
    assert len(db.package_history("amass")) == 1 and db.load_packages()["amass"].version == "9-1"
    db.mark_removed("amass")
    assert "amass" not in db.load_packages() and "amass" in db.removed_packages()
    assert "amass" in db.load_packages(include_removed=True)
    db.upsert_package(newer)  # reappears
    assert "amass" in db.load_packages()


def test_sync_history(tmp_path):
    db = Database(tmp_path / "t.sqlite")
    rid = db.start_run("full")
    db.record_change(rid, "added", "foo", {"v": 1})
    db.finish_run(rid, "success", {"added": 1})
    assert db.last_successful_run()["id"] == rid
    assert db.list_changes(rid)[0]["subject"] == "foo"


def test_corrupted_database(tmp_path):
    p = tmp_path / "bad.sqlite"
    p.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(DatabaseError):
        Database(p)


def test_newer_schema_rejected(tmp_path):
    p = tmp_path / "n.sqlite"
    Database(p).close()
    c = sqlite3.connect(p)
    c.execute("INSERT INTO schema_version VALUES (99)")
    c.commit()
    c.close()
    with pytest.raises(DatabaseError):
        Database(p)


def test_invalid_yaml_and_settings(tmp_path):
    bad = tmp_path / "s.yaml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigError):
        load_settings(bad)
    bad.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError):
        load_settings(bad)
    bad.write_text("http: {timeout_seconds: not-a-number}")
    with pytest.raises(ConfigError):
        load_settings(bad)


def test_token_not_in_repr(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "z" * 36)
    s = load_settings(None)
    assert s.github_token and "ghp_" not in repr(s)
