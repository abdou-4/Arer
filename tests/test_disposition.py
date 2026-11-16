"""Phase 6.2: analyst dispositions on the alert queue (arer.disposition.v1).

A disposition is the analyst's decision about one alert record: acknowledged
(seen, work queued), benign (false alarm) or phishing (true positive). No
sidecar file means the alert is `new`.

The disposition is a SIDECAST file sitting beside the record:

    <alert_id>.alert.json  ->  <alert_id>.disposition.json

keyed by alert_id (R1.1: the RECORD file name is the alert_id too, so a
source filename collision can never mix two mails). The alert record itself
is never mutated, so 6.1a's byte-for-byte golden keeps its meaning and a
disposition can be re-set, moved or deleted without touching
attacker-derived content.

Frozen here:
- test_frozen_key_set / test_golden_disposition_record   the record shape
- test_statuses_are_frozen                               the vocabulary
- test_sidecar_mismatch_is_an_integrity_error ...        the R1.2 linkage rules

Reading rules mirror the alert record (tests/test_alert_store.py): dispatch on
the "schema" marker, unknown schema is an explicit error, unknown extra keys
are ignored, and a corrupt sidecar never stops a list - it is named and the
command exits 1.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import read_alerts
from arer.disposition import (STATUSES, SCHEMA_VERSION, DispositionError,
                              disposition_path, load_disposition, read_disposition,
                              to_json as disposition_to_json)

GOLDEN = Path(__file__).parent / "golden" / "disposition_v1.json"

FIXED_NOW = datetime(2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc)

VALID = {
    "schema": "arer.disposition.v1",
    "alert_id": "a" * 32,
    "mail_sha256": "b" * 64,
    "status": "acknowledged",
    "note": "checked sender domain",
    "set_utc": "2026-11-17T10:00:00Z",
}


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


# --------------------------- the record ------------------------------------- #


def test_frozen_key_set():
    d = json.loads(disposition_to_json(_fixed()))
    assert d["schema"] == SCHEMA_VERSION == "arer.disposition.v1"
    assert set(d) == {"schema", "alert_id", "mail_sha256", "status", "note", "set_utc"}


def test_golden_disposition_record():
    actual = disposition_to_json(_fixed())
    if os.environ.get("UPDATE_GOLDEN"):              # deliberate schema change only
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual, encoding="utf-8")
        pytest.skip("golden regenerated - commit it and review the diff")
    assert actual == GOLDEN.read_text(encoding="utf-8")


def _fixed():
    from arer.disposition import build_disposition
    return build_disposition(alert_id="a" * 32, mail_sha256="b" * 64,
                             status="acknowledged", note="checked sender domain", now=FIXED_NOW)


def test_statuses_are_frozen():
    assert STATUSES == ("acknowledged", "benign", "phishing")


def test_note_is_stored_verbatim():
    """The note is the analyst's own words - pasted IOCs are common and must
    not be mangled by defanging."""
    from arer.disposition import build_disposition
    d = build_disposition(alert_id="a" * 32, status="phishing",
                          note="creds form at hxxps://evil[.]com/login", now=FIXED_NOW)
    assert "evil[.]com/login" in disposition_to_json(d)


def test_invalid_status_rejected(tmp_path):
    from arer.disposition import build_disposition
    with pytest.raises(ValueError):
        build_disposition(alert_id="a" * 32, status="WAT")


# --------------------------- reading rules ---------------------------------- #


def test_read_validates_schema_marker(tmp_path):
    p = tmp_path / "x.disposition.json"
    write_json(p, dict(VALID, schema="arer.disposition.v99"))
    with pytest.raises(DispositionError) as e:
        load_disposition(p)
    assert "arer.disposition.v99" in str(e.value) and p.name in str(e.value)

    write_json(p, {k: v for k, v in VALID.items() if k != "schema"})
    with pytest.raises(DispositionError):
        load_disposition(p)


def test_read_names_bad_fields_and_files(tmp_path):
    p = tmp_path / "x.disposition.json"
    d = json.loads(json.dumps(VALID))
    d["status"] = "WAT"
    write_json(p, d)
    with pytest.raises(DispositionError) as e:
        load_disposition(p)
    assert "status" in str(e.value) and "x.disposition.json" in str(e.value)

    p.write_text("{oops", encoding="utf-8")
    with pytest.raises(DispositionError):
        load_disposition(p)


def test_unknown_extra_keys_are_ignored(tmp_path):
    p = tmp_path / "x.disposition.json"
    write_json(p, dict(VALID, escalated_to="soar-ticket-7"))
    assert load_disposition(p).status == "acknowledged"


# --------------------------- sidecar layout --------------------------------- #


@pytest.fixture(scope="function")
def alert_dir(tmp_path_factory):
    """One real alert record, produced the way production produces it."""
    from arer.cli import main
    src = tmp_path_factory.mktemp("mail")
    SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
             + "<textarea></textarea>" * 25 + "<option>" * 10
             + '<div style="display:none !important;">x</div>' * 22
             + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
               'width:640px;height:1138px"></div></a>')
    (src / "salad.eml").write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD,
        encoding="utf-8")
    alerts = tmp_path_factory.mktemp("out") / "alerts"
    res = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code >= 3, res.output
    return alerts


def test_disposition_path_sits_beside_the_record():
    assert disposition_path(Path("/a/mail.eml.alert.json")) == Path("/a/mail.eml.disposition.json")
    # the fallback never strips anything: the sidecar must stay unique and beside its file
    assert disposition_path(Path("/a/unrelated.json")) == Path("/a/unrelated.json.disposition.json")


def test_missing_sidecar_reads_as_none(alert_dir):
    reads = read_alerts(alert_dir)
    assert len(reads) == 1
    assert read_disposition(reads[0].path) is None


def test_set_then_read_round_trip(alert_dir):
    from arer.cli import main
    rec = read_alerts(alert_dir)[0]
    res = CliRunner().invoke(main, ["alerts", "set", str(alert_dir), rec.alert.alert_id[:8],
                                    "acknowledged", "--note", "seen in triage"])
    assert res.exit_code == 0, res.output
    d = read_disposition(rec.path, rec.alert)
    assert d is not None
    assert d.alert_id == rec.alert.alert_id
    assert d.mail_sha256 == rec.alert.verdict.sha256
    assert d.status == "acknowledged" and d.note == "seen in triage"
    assert d.set_utc.endswith("Z")


def test_sidecar_does_not_confuse_the_alert_reader(alert_dir):
    """read_alerts must still see exactly one alert record after a sidecar exists."""
    from arer.cli import main
    alert = read_alerts(alert_dir)[0].alert
    CliRunner().invoke(main, ["alerts", "set", str(alert_dir), alert.alert_id[:8], "benign"])
    assert len(read_alerts(alert_dir)) == 1


# --------------------------- CLI -------------------------------------------- #


def test_set_requires_a_matching_record(alert_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "set", str(alert_dir), "deadbeef", "benign"])
    assert res.exit_code == 1 and "no alert record matches" in res.output


def test_set_rejects_unknown_status(alert_dir):
    from arer.cli import main
    alert = read_alerts(alert_dir)[0].alert
    res = CliRunner().invoke(main, ["alerts", "set", str(alert_dir), alert.alert_id[:8], "WAT"])
    assert res.exit_code == 2                          # Click usage error


def test_set_updates_in_place(alert_dir):
    from arer.cli import main
    from arer.alert import read_alerts
    rec = read_alerts(alert_dir)[0]
    first = disposition_path(rec.path)
    r1 = CliRunner().invoke(main, ["alerts", "set", str(alert_dir), rec.alert.alert_id[:8], "acknowledged"])
    assert r1.exit_code == 0 and first.is_file()
    r2 = CliRunner().invoke(main, ["alerts", "set", str(alert_dir), rec.alert.alert_id[:8], "phishing",
                                   "--note", "real campaign"])
    assert r2.exit_code == 0
    assert sorted(p.name for p in alert_dir.glob("*.disposition.json")) == [first.name]
    d = load_disposition(first)
    assert d.status == "phishing" and d.note == "real campaign"


def test_list_shows_status_column_and_new(alert_dir):
    from arer.cli import main
    alert = read_alerts(alert_dir)[0].alert
    fresh = CliRunner().invoke(main, ["alerts", "list", str(alert_dir)])
    assert fresh.exit_code == 0 and "  new  " in fresh.output
    CliRunner().invoke(main, ["alerts", "set", str(alert_dir), alert.alert_id[:8], "benign"])
    after = CliRunner().invoke(main, ["alerts", "list", str(alert_dir)])
    # note: match the status cell, not a bare "new" - the sender here is news[@]discord[.]com
    assert after.exit_code == 0 and " benign  " in after.output and "  new  " not in after.output


def test_list_status_filter(alert_dir):
    from arer.cli import main
    alert = read_alerts(alert_dir)[0].alert
    CliRunner().invoke(main, ["alerts", "set", str(alert_dir), alert.alert_id[:8], "acknowledged"])
    hit = CliRunner().invoke(main, ["alerts", "list", str(alert_dir), "--status", "acknowledged"])
    assert hit.exit_code == 0 and "salad" in hit.output
    miss = CliRunner().invoke(main, ["alerts", "list", str(alert_dir), "--status", "new"])
    assert miss.exit_code == 0 and "salad" not in miss.output


def test_list_names_a_corrupt_sidecar(alert_dir):
    from arer.cli import main
    from arer.alert import read_alerts
    rec = read_alerts(alert_dir)[0]
    disposition_path(rec.path).write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "list", str(alert_dir)])
    assert res.exit_code == 1
    assert disposition_path(rec.path).name in res.output
