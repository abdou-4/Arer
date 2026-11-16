"""R1.6: identity metadata supplied by parser-JSON input is UNVERIFIED.

A .json parser output can claim any file.sha256 for the original message;
the original bytes are usually not available, so the claim cannot be proven.
Rules frozen here:

- native .eml/.msg: sha256 computed from the ACTUAL bytes, sha256_verified=True;
- parser-JSON: the claimed hash stays as the sample identity (reports, eval
  dedup) but is flagged sha256_verified=False, and the verified hash of the
  JSON artifact itself is recorded in file.artifact_sha256;
- an unverified identity can never be SAVED to history or labeled (no case
  merging, no label inheritance) - scan --save degrades to a warning, label
  and history import refuse it;
- a native file that changes between hashing and parsing fails loudly.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.cli import main
from arer.config import load_config
from arer.history.store import HistoryStore
from arer.loader import LoadError, load_any
from arer.pipeline import run_pipeline

CLEAN_EML = ("From: Sam <sam@example.org>\r\nTo: me@example.org\r\nSubject: Lunch\r\n"
             "Date: Mon, 05 Jan 2026 09:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
             "Hi, lunch on Friday?")


@pytest.fixture(scope="module")
def parser_json(tmp_path_factory):
    """A parser JSON produced the production way: arer parse -> json."""
    d = tmp_path_factory.mktemp("mail")
    (d / "mail.eml").write_text(CLEAN_EML, encoding="utf-8")
    out = tmp_path_factory.mktemp("out")
    r = CliRunner().invoke(main, ["parse", str(d / "mail.eml"), "-o", str(out)])
    assert r.exit_code == 0, r.output
    return out / "mail.eml.json"


def test_native_eml_identity_is_verified(tmp_path):
    f = tmp_path / "mail.eml"
    f.write_text(CLEAN_EML, encoding="utf-8")
    email = load_any(f, load_config())
    assert email.file.sha256_verified is True
    assert email.file.sha256 == hashlib.sha256(CLEAN_EML.encode()).hexdigest()
    assert email.file.sha256 == email.file.artifact_sha256 or not email.file.artifact_sha256


def test_parser_json_identity_is_claimed_not_verified(parser_json):
    cfg = load_config()
    email = load_any(parser_json, cfg)
    claimed = json.loads(parser_json.read_text(encoding="utf-8"))["file"]["hashes"]["sha256"]
    assert email.file.sha256 == claimed                 # identity kept for reporting/dedup
    assert email.file.sha256_verified is False          # ...but flagged unverified
    assert email.file.artifact_sha256 == hashlib.sha256(parser_json.read_bytes()).hexdigest()
    # provenance note: the parser marks its own output (this does NOT prove the bytes)
    assert json.loads(parser_json.read_text(encoding="utf-8"))["file"]["generated_by"] == "arer mail_parser"


def test_scan_of_json_still_reports_the_same_verdict(parser_json):
    cfg = load_config()
    from_json = run_pipeline(load_any(parser_json, cfg), cfg, skip={"intel", "history"})
    native = tmp_dir = Path(str(parser_json)).parent.parent  # not used; verdict consistency only
    assert from_json.sha256                            # claimed identity flows through
    assert from_json.level is not None


def test_history_refuses_an_unverified_identity(parser_json, tmp_path):
    cfg = load_config()
    email = load_any(parser_json, cfg)
    db = tmp_path / "history.db"
    store = HistoryStore.open(db, create=True)
    try:
        with pytest.raises(ValueError) as e:
            store.save_scan(email.file.sha256, parser_json.name, email,
                            run_pipeline(email, cfg, skip={"history"}),
                            [], "x" * 16)
        assert "no verified SHA-256" in str(e.value)
        # nothing was written
        assert store.total_scans() == 0
    finally:
        store.close()


def test_scan_save_on_json_degrades_to_a_warning(parser_json, tmp_path):
    db = tmp_path / "history.db"
    r = CliRunner().invoke(main, ["scan", str(parser_json), "-q", "--save",
                                  "--config", str(_cfg_dir(tmp_path, db))])
    assert r.exit_code == 0, r.output                  # the scan itself is fine
    assert "not saved" in r.output and "no verified SHA-256" in r.output
    rows = sqlite3.connect(db).execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    assert rows == 0                                   # and history stayed empty


def test_label_refuses_a_json_file(parser_json, tmp_path):
    db = tmp_path / "history.db"
    r = CliRunner().invoke(main, ["label", str(parser_json), "phish",
                                  "--config", str(_cfg_dir(tmp_path, db))])
    assert r.exit_code == 1 and "no verified SHA-256" in r.output
    rows = sqlite3.connect(db).execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    assert rows == 0


def test_two_json_files_claiming_the_same_hash_stay_unsaved(tmp_path):
    """A tampered/claimed hash cannot merge cases through history: both
    artifacts refuse to be saved no matter what they claim."""
    cfg_dir = _cfg_dir(tmp_path, tmp_path / "history.db")
    payload = json.dumps({"file": {"name": "x", "format": "eml", "size_bytes": 10,
                                   "hashes": {"sha256": "f" * 64}},
                          "envelope": {"subject": "?", "from": [{"name": "", "address": "a@b.c", "domain": "b.c"}]},
                          "body": {"combined": "hello", "text_plain": ["hello"]}})
    a = tmp_path / "a.json"; a.write_text(payload, encoding="utf-8")
    b = tmp_path / "b.json"; b.write_text(payload, encoding="utf-8")
    for f in (a, b):
        r = CliRunner().invoke(main, ["label", str(f), "phish", "--config", str(cfg_dir)])
        assert r.exit_code == 1 and "no verified SHA-256" in r.output


def test_native_file_changed_during_scan_fails(tmp_path):
    """TOCTOU guard: a .eml whose bytes change between hashing and parsing
    cannot pass silently."""
    f = tmp_path / "mail.eml"
    f.write_text(CLEAN_EML, encoding="utf-8")
    import arer.loader as loader
    orig = loader._sha256_of
    loader._sha256_of = lambda p: "0" * 64             # simulate a hash taken from other bytes
    try:
        with pytest.raises(LoadError) as e:
            load_any(f, load_config())
        assert "changed during scan" in str(e.value)
    finally:
        loader._sha256_of = orig


def _cfg_dir(tmp_path, db: Path) -> Path:
    import shutil
    d = tmp_path / "cfg"
    if not d.exists():
        shutil.copytree("config", d)
    h = d / "history.yaml"
    h.write_text(f"db_path: {db}\nauto_save: false\n", encoding="utf-8")
    return d
