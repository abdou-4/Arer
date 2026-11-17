"""Regression tests: a failed alert-record write must never abort the batch,
hide behind a verdict exit code, or break the JSONL output.

Two reported defects:

1. cli.py scan caught only AlertCollisionError around write_alert. Any
   OSError (disk full, permission) or AlertError aborted the whole batch
   with a traceback, lost that mail's alert, and skipped the remaining
   mails. The write is now guarded for all three, the error names the file
   on stderr, and the batch continues.

2. The batch exit code hid the failure: code 1 ranked BELOW the verdict
   codes (3/4/5) in EXIT_SEVERITY, so a batch with a MALICIOUS mail and a
   failed record write exited 5 - the lost record was invisible to scripts.
   Write failures are now tracked separately and surface as the dedicated
   code 8 (RECORD_ERROR, arer.exitcodes), which outranks every verdict and
   is deliberately NOT in VERDICT_EXITS, so the watcher archives such mail
   under failed/.
"""
import json

import pytest
from click.testing import CliRunner

from arer.alert import AlertCollisionError
from arer.cli import main
from arer.exitcodes import RECORD_ERROR_EXIT

# Two alert-level (MALICIOUS) mails with DIFFERENT bodies, so each gets its
# own alert_id and its own record (no collision between them).
SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
         "<!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
           'width:640px;height:1138px"></div></a>')


@pytest.fixture
def mails(tmp_path):
    d = tmp_path / "mails"
    d.mkdir()
    for name, subject in (("one.eml", "win a prize"), ("two.eml", "your account")):
        (d / name).write_text(
            f"From: news@discord.com\r\nTo: v@example.com\r\nSubject: {subject}\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD,
            encoding="utf-8")
    return d


def _scan(mails, tmp_path, jsonl=None):
    args = ["scan", str(mails), "--alerts", str(tmp_path / "q"), "-q",
            "--skip", "intel", "--skip", "history"]
    if jsonl is not None:
        args += ["--jsonl", str(jsonl)]
    return CliRunner().invoke(main, args)


def test_disk_full_alert_write_does_not_abort_the_batch(mails, tmp_path, monkeypatch):
    """OSError(28) from write_alert: both mails are still scanned and
    reported, the error names the file on stderr, no traceback escapes, and
    the batch exits the dedicated RECORD_ERROR code 8."""
    import arer.cli as cli
    attempted = []

    def disk_full(alert, directory, defang=True):
        attempted.append(alert.source_file)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "write_alert", disk_full)
    jsonl = tmp_path / "scan.jsonl"
    r = _scan(mails, tmp_path, jsonl=jsonl)

    assert sorted(attempted) == ["one.eml", "two.eml"], \
        "every alert-level mail must still reach the alert write"
    assert r.exit_code == RECORD_ERROR_EXIT == 8, r.output
    assert "Traceback" not in r.output, "the failure must be handled, not raised"
    for name in ("one.eml", "two.eml"):
        assert name in r.output and "alert record not written" in r.output, r.output

    # both scans completed and were journalled; the JSONL handle is closed
    # (the file can be read back and holds one ok line per mail)
    lines = [json.loads(x) for x in jsonl.read_text(encoding="utf-8").splitlines()]
    assert [x["source_file"] for x in lines] == ["one.eml", "two.eml"]
    assert all(x["ok"] for x in lines), "the scans themselves succeeded"
    assert all(x["exit_code"] >= 3 for x in lines), \
        "both mails are alert-level verdicts: their codes must NOT win the batch"


def test_collision_alert_write_yields_record_error_exit(mails, tmp_path, monkeypatch):
    """The pre-existing AlertCollisionError path now surfaces as exit 8 too:
    a record that could not be queued is never reported as a plain verdict."""
    import arer.cli as cli

    def collide(alert, directory, defang=True):
        raise AlertCollisionError(
            f"record {alert.alert_id}.alert.json already exists with different content")

    monkeypatch.setattr(cli, "write_alert", collide)
    r = _scan(mails, tmp_path)

    assert r.exit_code == RECORD_ERROR_EXIT, r.output
    assert "alert record not written" in r.output and "already exists" in r.output
    assert "Traceback" not in r.output


def test_verdict_code_never_hides_a_failed_record_write(mails, tmp_path, monkeypatch):
    """The exact reported defect shape: alert-level verdicts (exit 3/4/5) in
    the same batch as a failed record write. The verdicts still print, but
    the batch exit is 8 - the lost record is unmistakable to scripts."""
    import arer.cli as cli
    from arer.models import Level

    def disk_full(alert, directory, defang=True):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "write_alert", disk_full)
    r = _scan(mails, tmp_path)

    quiet_lines = [ln for ln in r.output.splitlines()
                   if ln.split() and ln.split()[0] in Level.__members__]
    assert len(quiet_lines) == 2, f"both verdicts must still print: {r.output}"
    level = Level[quiet_lines[0].split()[0]]
    assert level.rank >= Level.SUSPICIOUS.rank, "the fixture mails must be alert-level"
    from arer.exitcodes import EXIT_CODES
    assert r.exit_code == 8, r.output
    assert r.exit_code != EXIT_CODES[level], \
        "a failed record write must not be hidden behind the verdict exit code"


def test_record_error_code_is_watcher_failed_semantics():
    """Code 8 is an operational failure, not a verdict: it must stay outside
    VERDICT_EXITS/ALERT_EXITS so the watcher archives the mail under
    failed/ and scripts using the allowlist never treat it as a scan result."""
    from arer.exitcodes import ALERT_EXITS, VERDICT_EXITS, is_alert_exit

    assert RECORD_ERROR_EXIT not in VERDICT_EXITS
    assert RECORD_ERROR_EXIT not in ALERT_EXITS
    assert not is_alert_exit(RECORD_ERROR_EXIT)
