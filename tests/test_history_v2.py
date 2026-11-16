"""R2: history.db schema 2 - provenance, decisions, migration, case queue.

Frozen contract:
- a schema-1 database keeps working exactly as before; the decision API
  refuses it with MigrationRequired (never quietly "no history");
- migrate() is: backup-FIRST (verified with the SQLite backup API),
  transactional (any error rolls back and the original is untouched),
  idempotent, dry-run-able, and preserves EVERY scan row, finding,
  indicator, label, label_at and note;
- existing phish/legit labels become decision events with provenance
  legacy_unverified - never silently analyst-confirmed, never
  training-eligible until reviewed;
- the training query excludes tool, legacy_unverified, unsure, acknowledged
  and unreviewed cases: only analyst decisions and verified imports are
  ever eligible ("only human labels teach the tool");
- the case queue (`alerts cases`) deduplicates by exact SHA-256 across file
  names and ranks by severity, then score - not by modification time.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import Alert, ScanSubject, write_alert
from arer.cli import main
from arer.disposition import build_disposition, write_disposition
from arer.history.store import (CASE_STATES, KNOWN_SCHEMAS, MigrationRequired, PROVENANCES,
                                STATUS_TO_DISPOSITION, HistoryStore, migrate, read_schema_version)
from arer.models import Level, Verdict

# the EXACT schema-1 DDL, so the fixture is a faithful v1 database
SCHEMA1_DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE scans(
    sha256 TEXT PRIMARY KEY, name TEXT, first_seen TEXT, last_seen TEXT, times INTEGER NOT NULL DEFAULT 1,
    from_domain TEXT, level TEXT, score INTEGER, partial INTEGER NOT NULL DEFAULT 0, logic_hash TEXT,
    label TEXT CHECK(label IN ('phish','legit')), label_at TEXT, note TEXT);
CREATE TABLE findings(
    sha256 TEXT NOT NULL, n INTEGER NOT NULL, id TEXT NOT NULL, category TEXT NOT NULL,
    confidence REAL NOT NULL, source TEXT, summary TEXT, PRIMARY KEY(sha256, n));
CREATE TABLE indicators(
    sha256 TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(sha256, kind, value));
CREATE INDEX ind_lookup ON indicators(kind, value);
"""


def make_schema1(tmp_path: Path) -> Path:
    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA1_DDL)
    conn.execute("INSERT INTO meta VALUES('schema','1')")
    conn.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("a" * 64, "phish1.eml", "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00",
                  2, "evil.example", "MALICIOUS", 92, 0, "h" * 16, "phish", "2026-01-03T00:00:00+00:00",
                  "clearly phishing"))
    conn.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("b" * 64, "legit1.eml", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00",
                  1, "shop.example", "CLEAN", 5, 0, "h" * 16, "legit", None, None))
    conn.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("c" * 64, "unknown.eml", "2026-01-04T00:00:00+00:00", "2026-01-04T00:00:00+00:00",
                  1, "", "CLEAN", 0, 1, "h" * 16, None, None, None))
    conn.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)", ("a" * 64, 0, "url.ip_host", "url", 1.0, "rule", "ip host"))
    conn.execute("INSERT INTO indicators VALUES(?,?,?)", ("a" * 64, "sender_domain", "evil.example"))
    conn.commit()
    conn.close()
    return db


# --------------------------- migration ---------------------------------------- #


def test_migration_preserves_every_v1_value(tmp_path):
    db = make_schema1(tmp_path)
    report = migrate(db)
    assert report["changed"] is True and report["migrated_labels"] == 2
    conn = sqlite3.connect(db)
    # every old value intact
    rows = conn.execute("SELECT * FROM scans ORDER BY sha256").fetchall()
    assert len(rows) == 3
    phish = [r for r in rows if r[0] == "a" * 64][0]
    assert phish[10] == "phish" and phish[11] == "2026-01-03T00:00:00+00:00" and phish[12] == "clearly phishing"
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 1
    assert conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == "2"
    # v2 objects exist and are populated
    assert conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 3
    events = conn.execute("SELECT case_sha256,value,provenance,training_eligible,note FROM case_decisions "
                          "ORDER BY case_sha256").fetchall()
    assert len(events) == 2
    assert all(e[2] == "legacy_unverified" and e[3] == 0 for e in events)
    assert events[0][4] == "clearly phishing"          # the old note survived into the event
    conn.close()


def test_migration_is_idempotent(tmp_path):
    db = make_schema1(tmp_path)
    migrate(db)
    report = migrate(db)
    assert report["changed"] is False and "already schema 2" in report["message"]
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM case_decisions").fetchone()[0] == 2   # no duplicates
    conn.close()


def test_migration_dry_run_writes_nothing(tmp_path):
    db = make_schema1(tmp_path)
    report = migrate(db, dry_run=True)
    assert report["dry_run"] is True and report["before"]["scans"] == 3
    assert read_schema_version(db) == "1"
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='case_decisions'").fetchone()[0] == 0
    conn.close()


def test_migration_makes_a_verified_backup(tmp_path):
    db = make_schema1(tmp_path)
    report = migrate(db)
    backup = Path(report["backup"])
    assert backup.is_file()
    conn = sqlite3.connect(backup)
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 3
    assert conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == "1"
    conn.close()


def test_failed_migration_leaves_the_original_untouched(tmp_path):
    """Simulate a crash MID-transaction: the original database must come out
    exactly as it went in (this is why migrate() runs in one transaction)."""
    db = make_schema1(tmp_path)
    import arer.history.store as store_mod
    orig = store_mod._V2_DDL
    store_mod._V2_DDL = orig + "\nTHIS IS NOT SQL AT ALL;"   # boom after the DDL
    try:
        with pytest.raises(sqlite3.OperationalError):
            migrate(db)
        # original is exactly as before
        assert read_schema_version(db) == "1"
        conn = sqlite3.connect(db)
        assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='case_decisions'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 3
        conn.close()
    finally:
        store_mod._V2_DDL = orig


def test_new_databases_are_schema_2_and_v1_still_readable(tmp_path):
    s = HistoryStore.open(tmp_path / "new.db", create=True)
    assert s.schema_version == "2"
    s.close()
    d = tmp_path / "v1dir"; d.mkdir()
    db = make_schema1(d)
    s1 = HistoryStore.open(db)
    assert s1 is not None and s1.schema_version == "1"
    with pytest.raises(MigrationRequired):
        s1.record_decision("a" * 64, kind="disposition", value="true_positive", provenance="analyst")
    s1.close()


# --------------------------- decisions + training eligibility ------------------ #


@pytest.fixture
def store2(tmp_path):
    s = HistoryStore.open(tmp_path / "h.db", create=True)
    yield s
    s.close()


def test_record_and_read_decisions_append_only(store2):
    store2.record_decision("a" * 64, kind="disposition", value="true_positive", provenance="analyst",
                           analyst="dana", source_ref="alert:x", note="confirmed", created_at="2026-01-01T00:00:00Z",
                           training_eligible=True, eligibility_reason="analyst true_positive")
    store2.record_decision("a" * 64, kind="disposition", value="false_positive", provenance="analyst",
                           analyst="dana", created_at="2026-01-02T00:00:00Z", training_eligible=True,
                           eligibility_reason="analyst false_positive")
    cur = store2.current_decision("a" * 64)
    assert cur["value"] == "false_positive" and cur["id"] == 2
    assert len(store2.decisions_of("a" * 64)) == 2      # the audit trail keeps both
    assert all(PROVENANCES.index(d["provenance"]) >= 0 for d in store2.decisions_of("a" * 64))


def test_training_eligibility_never_includes_tool_or_legacy(store2):
    store2.record_decision("a" * 64, kind="disposition", value="true_positive", provenance="analyst",
                           analyst="dana", training_eligible=True, eligibility_reason="analyst true_positive")
    store2.record_decision("b" * 64, kind="disposition", value="true_positive", provenance="tool",
                           training_eligible=False, eligibility_reason="tool decisions never train")
    store2.record_decision("c" * 64, kind="disposition", value="false_positive", provenance="legacy_unverified",
                           training_eligible=False, eligibility_reason="legacy")
    store2.record_decision("d" * 64, kind="disposition", value="acknowledged", provenance="analyst",
                           analyst="dana", training_eligible=False,
                           eligibility_reason="workflow acknowledgement, never a training disposition")
    rows = store2.training_decisions()
    assert [r["case_sha256"][0] for r in rows] == ["a"]  # ONLY the analyst true/false positives
    assert all(r["provenance"] == "analyst" for r in rows)


def test_status_mapping_is_frozen():
    assert STATUS_TO_DISPOSITION == {"phishing": "true_positive", "benign": "false_positive",
                                     "acknowledged": "acknowledged"}
    assert CASE_STATES == ("new", "triaged", "closed")


# --------------------------- sidecar import ----------------------------------- #


def mk_alert(aid="1" * 32, sha="f" * 64):
    return Alert(alert_id=aid, generated_utc="2026-11-17T10:00:00Z", source_file="mail.eml",
                 logic_hash="h" * 16, scan=ScanSubject(from_="news@example.com"),
                 verdict=Verdict(sha256=sha, level=Level.MALICIOUS, score=80))


def test_import_sidecar_decision_is_legacy_and_dedup(store2):
    r1 = store2.import_sidecar_decision("f" * 64, alert_id="1" * 32, status="phishing",
                                        note="", set_utc="2026-01-01T00:00:00Z", source_ref="x.alert.json")
    r2 = store2.import_sidecar_decision("f" * 64, alert_id="1" * 32, status="phishing",
                                        note="", set_utc="2026-01-01T00:00:00Z", source_ref="x.alert.json")
    assert (r1, r2) == ("imported", "duplicate")
    d = store2.current_decision("f" * 64)
    assert d["value"] == "true_positive" and d["provenance"] == "legacy_unverified"
    assert d["training_eligible"] == 0
    assert store2.training_decisions() == []


def test_history_import_dispositions_cli(tmp_path):
    """End to end: real records + sidecars -> migrate -> import -> report."""
    queue = tmp_path / "q"
    a = mk_alert()
    write_alert(a, queue)
    write_disposition(build_disposition(a.alert_id, "benign", mail_sha256=a.verdict.sha256,
                                        note="looks safe", now=None), queue.path if hasattr(queue, 'path') else queue / f"{a.alert_id}.alert.json")
    db = tmp_path / "history.db"
    cfg_dir = tmp_path / "cfg"
    import shutil
    shutil.copytree("config", cfg_dir)
    (cfg_dir / "history.yaml").write_text(f"db_path: {db}\n", encoding="utf-8")
    # start from a real schema-1 database (a fresh create is already schema 2)
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA1_DDL.replace("CREATE TABLE meta", "CREATE TABLE IF NOT EXISTS meta")
                        .replace("CREATE TABLE scans", "CREATE TABLE IF NOT EXISTS scans")
                        .replace("CREATE TABLE findings", "CREATE TABLE IF NOT EXISTS findings")
                        .replace("CREATE TABLE indicators", "CREATE TABLE IF NOT EXISTS indicators")
                        .replace("CREATE INDEX ind_lookup", "CREATE INDEX IF NOT EXISTS ind_lookup"))
    conn.execute("INSERT OR IGNORE INTO meta VALUES('schema','1')")
    conn.commit(); conn.close()
    r = CliRunner().invoke(main, ["history", "import-dispositions", str(queue), "--config", str(cfg_dir)])
    assert r.exit_code == 1 and "schema 1" in r.output + r.stderr   # refuse pre-migration...
    assert CliRunner().invoke(main, ["history", "migrate", "--config", str(cfg_dir)]).exit_code == 0
    r = CliRunner().invoke(main, ["history", "import-dispositions", str(queue), "--config", str(cfg_dir)])
    assert r.exit_code == 0, r.output
    assert "1 imported" in r.output and "legacy_unverified" in r.output
    store = HistoryStore.open(db)
    try:
        d = store.current_decision(a.verdict.sha256)
        assert d["provenance"] == "legacy_unverified" and d["value"] == "false_positive"
    finally:
        store.close()


# --------------------------- analyst mirroring via alerts set ------------------ #


def test_alerts_set_mirrors_an_analyst_decision(tmp_path):
    queue = tmp_path / "q"
    a = mk_alert()
    write_alert(a, queue)
    db = tmp_path / "history.db"
    cfg_dir = tmp_path / "cfg"
    import shutil
    shutil.copytree("config", cfg_dir)
    (cfg_dir / "history.yaml").write_text(f"db_path: {db}\n", encoding="utf-8")
    r = CliRunner().invoke(main, ["alerts", "set", str(queue), a.alert_id[:8], "phishing",
                                  "--note", "confirmed run", "--config", str(cfg_dir)])
    assert r.exit_code == 0, r.output
    store = HistoryStore.open(db)
    try:
        d = store.current_decision(a.verdict.sha256)
        assert d["provenance"] == "analyst" and d["value"] == "true_positive"
        assert d["analyst"] and d["note"] == "confirmed run"
        assert d["training_eligible"] == 1
    finally:
        store.close()


def test_alerts_set_without_v2_still_writes_the_sidecar(tmp_path):
    """A schema-1 database must never lose the analyst's decision: the
    sidecar is written, the mirroring degrades to a hint."""
    queue = tmp_path / "q"
    a = mk_alert()
    write_alert(a, queue)
    db = tmp_path / "history.db"
    cfg_dir = tmp_path / "cfg"
    import shutil
    shutil.copytree("config", cfg_dir)
    (cfg_dir / "history.yaml").write_text(f"db_path: {db}\n", encoding="utf-8")
    HistoryStore.open(db, create=True).close()          # v2-capable db; force v1:
    conn = sqlite3.connect(db)
    conn.execute("UPDATE meta SET value='1' WHERE key='schema'")
    conn.commit(); conn.close()
    r = CliRunner().invoke(main, ["alerts", "set", str(queue), a.alert_id[:8], "acknowledged",
                                  "--config", str(cfg_dir)])
    assert r.exit_code == 0, r.output
    from arer.alert import read_alerts
    from arer.disposition import read_disposition
    rec = read_alerts(queue)[0]
    assert read_disposition(rec.path, rec.alert).status == "acknowledged"
    assert "arer history migrate" in r.output           # the hint is shown


# --------------------------- the case queue (R2.5) ----------------------------- #


def _write_case(queue: Path, sha: str, aid: str, level: Level, score: int, gen: str):
    a = Alert(alert_id=aid, generated_utc=gen, source_file=f"{aid}.eml", logic_hash="h" * 16,
              scan=ScanSubject(from_="news@example.com"),
              verdict=Verdict(sha256=sha, level=level, score=score))
    write_alert(a, queue)
    return a


def test_cases_dedup_across_filenames_and_rank_by_severity(tmp_path):
    queue = tmp_path / "q"
    # same mail bytes seen twice under different names, older, lower severity
    _write_case(queue, "b" * 64, "2" * 32, Level.LIKELY_PHISHING, 60, "2026-01-01T00:00:00Z")
    _write_case(queue, "b" * 64, "3" * 32, Level.LIKELY_PHISHING, 65, "2026-01-02T00:00:00Z")
    # a MALICIOUS case seen later: must rank FIRST (severity, then score)
    _write_case(queue, "a" * 64, "1" * 32, Level.MALICIOUS, 90, "2026-03-01T00:00:00Z")
    # a lowly SUSPICIOUS case: ranks last
    _write_case(queue, "c" * 64, "4" * 32, Level.SUSPICIOUS, 30, "2026-02-01T00:00:00Z")
    r = CliRunner().invoke(main, ["alerts", "cases", str(queue)])
    assert r.exit_code == 0, r.output
    lines = [ln for ln in r.output.splitlines()[1:]]
    order = [ln[:12] for ln in lines]
    assert order[0] == "a" * 12                         # MALICIOUS first
    assert order[1] == "b" * 12                         # two sightings, ONE case row
    assert order[2] == "c" * 12
    assert sum("b" * 12 in ln for ln in lines) == 1     # deduplicated across filenames
    assert " 2  " in lines[1]                           # seen count of the deduped case


def test_cases_ranks_by_severity_not_by_recency(tmp_path):
    queue = tmp_path / "q"
    _write_case(queue, "n" * 64, "1" * 32, Level.SUSPICIOUS, 50, "2026-12-01T00:00:00Z")   # newest
    _write_case(queue, "o" * 64, "2" * 32, Level.MALICIOUS, 95, "2026-01-01T00:00:00Z")    # oldest
    r = CliRunner().invoke(main, ["alerts", "cases", str(queue)])
    lines = r.output.splitlines()[1:]
    assert lines[0].startswith("o" * 12)                # severity wins over recency
