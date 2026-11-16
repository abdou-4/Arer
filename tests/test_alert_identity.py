"""R1.1 + R1.2: alert identity and disposition linkage (remediation).

R1.1 - immutable alert identity:
- the record file is named `<alert_id>.alert.json`, derived from the event
  ID, never from the source filename: a second mail arriving under the same
  file name can no longer overwrite the first record, and an old sidecar can
  never be inherited by a new message;
- records are written atomically (temp file + os.replace), never silently
  replaced; a same-ID/different-content collision preserves BOTH records and
  raises an integrity error.

R1.2 - disposition linkage validation:
- a sidecar must name exactly the alert_id of the record it sits beside, and
  exactly its mail sha256 when the record has one;
- an orphan/stale/mismatched sidecar is an integrity error: its status is
  never silently applied, never "repaired" onto the new alert. Every queue
  command (list, stats, export, campaigns) goes through the same validation.
"""
import json
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import (Alert, AlertCollisionError, ScanSubject, alert_path,
                        read_alert, read_alerts, write_alert)
from arer.disposition import (DispositionError, build_disposition, disposition_path,
                              read_disposition, write_disposition)
from arer.models import Level, Verdict


def mk_alert(aid="a" * 32, sha="f" * 64, level=Level.MALICIOUS, score=80, source="mail.eml"):
    return Alert(alert_id=aid, generated_utc="2026-11-17T10:00:00Z", source_file=source,
                 logic_hash="h" * 16, scan=ScanSubject(from_="news@example.com"),
                 verdict=Verdict(sha256=sha, level=level, score=score))


# --------------------------- R1.1: identity ---------------------------------- #


def test_alert_file_name_is_the_event_id(tmp_path):
    a = mk_alert(source="whatever the mail was called.eml")
    assert alert_path(a, tmp_path) == tmp_path / "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.alert.json"


def test_same_source_filename_never_overwrites_a_record(tmp_path):
    """Two different mails scanned under the same file name -> TWO records."""
    a1 = mk_alert(aid="1" * 32, sha="a" * 64)
    a2 = mk_alert(aid="2" * 32, sha="b" * 64, source="same.eml")
    write_alert(a1, tmp_path)
    write_alert(a2, tmp_path)                       # same source_file name
    names = {p.name for p in tmp_path.glob("*.alert.json")}
    assert names == {"1" * 32 + ".alert.json", "2" * 32 + ".alert.json"}


def test_write_is_atomic_and_leaves_no_temp_files(tmp_path):
    a = mk_alert()
    write_alert(a, tmp_path)
    assert list(tmp_path.glob(".*.tmp")) == []
    assert read_alert(alert_path(a, tmp_path)).alert_id == a.alert_id


def test_rewriting_the_same_event_is_idempotent(tmp_path):
    a = mk_alert()
    p1 = write_alert(a, tmp_path)
    before = p1.read_text(encoding="utf-8")
    p2 = write_alert(mk_alert(), tmp_path)          # same alert_id, same mail
    assert p2 == p1 and p2.read_text(encoding="utf-8") == before


def test_same_id_other_mail_preserves_both_records(tmp_path):
    existing = mk_alert(aid="c" * 32, sha="a" * 64)
    write_alert(existing, tmp_path)
    intruder = mk_alert(aid="c" * 32, sha="b" * 64)
    with pytest.raises(AlertCollisionError) as e:
        write_alert(intruder, tmp_path)
    assert "a" * 12 in str(e.value)                 # names the EXISTING record's mail
    # the original record is untouched, the new one is preserved beside it
    kept = [p for p in tmp_path.glob("*.alert.json")]
    assert len(kept) == 2
    assert read_alert(tmp_path / f"{'c' * 32}.alert.json").verdict.sha256 == "a" * 64
    assert read_alert(kept[0] if kept[0].name != f"{'c' * 32}.alert.json" else kept[1]).verdict.sha256 == "b" * 64


def test_source_filename_collision_end_to_end(tmp_path):
    """Regression for the reported defect: mail.eml overwritten by a new
    mail.eml. Now both alert records survive with their own identities."""
    from arer.cli import main
    salad = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
             "<!DOCTYPE><!DOCTYPE>"
             + "<textarea></textarea>" * 25 + "<option>" * 10
             + '<div style="display:none !important;">x</div>' * 22
             + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
               'width:640px;height:1138px"></div></a>')
    mails = tmp_path / "mails"
    mails.mkdir()
    (mails / "mail.eml").write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + salad,
        encoding="utf-8")
    alerts = tmp_path / "q"
    r1 = CliRunner().invoke(main, ["scan", str(mails), "--alerts", str(alerts), "-q",
                                   "--skip", "intel", "--skip", "history"])
    first_records = {p.name for p in alerts.glob("*.alert.json")}
    # a DIFFERENT mail, same file name
    (mails / "mail.eml").write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: prize\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + salad,
        encoding="utf-8")
    r2 = CliRunner().invoke(main, ["scan", str(mails), "--alerts", str(alerts), "-q",
                                   "--skip", "intel", "--skip", "history"])
    second_records = {p.name for p in alerts.glob("*.alert.json")}
    assert r1.exit_code >= 3 and r2.exit_code >= 3
    assert len(second_records) == len(first_records) + 1          # never overwritten
    assert first_records < second_records
    shas = {read_alert(alerts / n).verdict.sha256 for n in second_records}
    assert len(shas) == 2                           # two distinct mails, both queued


# --------------------------- R1.2: linkage ----------------------------------- #


def test_valid_sidecar_passes_validation(tmp_path):
    a = mk_alert()
    p = write_alert(a, tmp_path)
    d = build_disposition(a.alert_id, "benign", mail_sha256=a.verdict.sha256)
    write_disposition(d, p)
    assert read_disposition(p, a) is not None


def test_legacy_sidecar_without_sha_still_passes(tmp_path):
    """v1 sidecars from before the sha was always filled in: no sha on the
    sidecar is not a mismatch, only a WRONG sha is."""
    a = mk_alert()
    p = write_alert(a, tmp_path)
    d = build_disposition(a.alert_id, "acknowledged", mail_sha256="")
    write_disposition(d, p)
    assert read_disposition(p, a) is not None


def test_sidecar_mismatch_is_an_integrity_error(tmp_path):
    a = mk_alert(aid="1" * 32)
    p = write_alert(a, tmp_path)
    stale = build_disposition("2" * 32, "benign", mail_sha256=a.verdict.sha256)   # old alert_id
    write_disposition(stale, p)
    with pytest.raises(DispositionError) as e:
        read_disposition(p, a)
    assert "alert_id mismatch" in str(e.value) and "NOT applied" in str(e.value)
    # the old status is never silently applied
    d = read_disposition(p)                        # unvalidated read still possible...
    assert d.status == "benign"                    # ...but every queue command validates


def test_sidecar_sha_mismatch_is_an_integrity_error(tmp_path):
    a = mk_alert()
    p = write_alert(a, tmp_path)
    wrong = build_disposition(a.alert_id, "phishing", mail_sha256="e" * 64)
    write_disposition(wrong, p)
    with pytest.raises(DispositionError) as e:
        read_disposition(p, a)
    assert "sha256 mismatch" in str(e.value) and "NOT applied" in str(e.value)


def test_queue_commands_never_apply_a_mismatched_sidecar(tmp_path):
    """The stale-sidecar-after-overwrite scenario, end to end: an old sidecar
    beside a new record must surface as unreadable (exit 1), and its status
    must not appear as the record's disposition."""
    from arer.cli import main
    a = mk_alert(aid="1" * 32)
    p = write_alert(a, tmp_path)
    write_disposition(build_disposition("2" * 32, "benign", mail_sha256="f" * 64), p)
    for args in (["alerts", "list", str(tmp_path)],
                 ["alerts", "stats", str(tmp_path)],
                 ["alerts", "export", str(tmp_path)],
                 ["alerts", "campaigns", str(tmp_path)]):
        res = CliRunner().invoke(main, args)
        assert res.exit_code == 1, args
        assert "mismatch" in res.output or "mismatch" in (res.stderr or ""), args
        assert " benign " not in res.output and '"disposition_status": "benign"' not in res.output
