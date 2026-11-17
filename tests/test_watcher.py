"""Phase 6.5: the mail drop watcher.

A drop folder is how mail reaches a machine unattended (a SOAR drops .eml
files, a mail client saves them, a cron rsyncs them). `arer watch DROPDIR`
polls the folder and, for every mail file that appears, runs a REAL
`arer scan` in a fresh subprocess:

- isolation: a crash or hang in one scan can never kill the watcher itself;
- timeout: one mail may take at most --timeout seconds, then it is killed;
- fail-safe archiving: every processed mail is moved to DROP/handled/ or
  DROP/failed/ (never overwritten - a collision gets a numeric suffix), so
  the same file is never scanned twice and nothing is ever deleted;
- batch discipline inherited from `arer parse`/`scan`: one bad mail never
  stops the pass, failures are named, `watch --once` exits 1 if any failed.

v1 watches the TOP LEVEL of the drop folder only, and only files with a
known mail extension - a half-written file with an unknown extension is
never sniffed or moved mid-transfer.

The unit tests inject a fake runner (no real subprocess); the integration
tests run the real `python -m arer scan` end to end.
"""
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.watcher import (FAILED_DIR, HANDLED_DIR, archive, mail_candidates,
                          poll_once, scan_command, scan_one)


def fake_runner(returncode=0, stdout="", stderr=""):
    def run(argv, timeout):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)
    return run


def timeout_runner():
    def run(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)
    return run


def drop_with(tmp_path: Path, *names: str) -> Path:
    drop = tmp_path / "drop"
    drop.mkdir()
    for n in names:
        (drop / n).write_text("x", encoding="utf-8")
    return drop


# --------------------------- pure helpers ------------------------------------ #


def test_scan_command_builds_the_real_scan_argv(tmp_path):
    mail = tmp_path / "p.eml"
    cmd = scan_command(mail, tmp_path / "queue", ("intel", "history"))
    # R6.4: options first, then an explicit `--` separator before the mail
    assert cmd[:6] == [str(Path(__import__("sys").executable)), "-m", "arer", "scan", "-q",
                       "--alerts"]
    assert cmd[-2:] == ["--", str(mail)]
    assert "-q" in cmd and "--alerts" in cmd and str(tmp_path / "queue") in cmd
    assert cmd[cmd.index("--skip") + 1] == "intel"


def test_mail_candidates_are_top_level_known_suffixes_only(tmp_path):
    drop = drop_with(tmp_path, "b.eml", "a.eml", "note.txt", ".hidden.eml", "x.report.json")
    (drop / "sub").mkdir()
    (drop / "sub" / "inner.eml").write_text("x", encoding="utf-8")
    assert [p.name for p in mail_candidates(drop)] == ["a.eml", "b.eml"]   # sorted, top level only


def test_archive_moves_and_never_overwrites(tmp_path):
    mail = tmp_path / "p.eml"
    mail.write_text("x", encoding="utf-8")
    dest = tmp_path / HANDLED_DIR
    dest.mkdir()
    (dest / "p.eml").write_text("old", encoding="utf-8")
    out = archive(mail, dest)
    assert out == dest / "p.1.eml" and out.read_text(encoding="utf-8") == "x"
    assert not mail.exists()


# --------------------------- outcomes ----------------------------------------- #


def test_clean_scan_is_handled(tmp_path):
    drop = drop_with(tmp_path, "p.eml")
    outs = poll_once(drop, runner=fake_runner(0, stdout="CLEAN                0  p.eml"))
    (o,) = outs
    assert not o.failed and o.dest == drop / HANDLED_DIR / "p.eml" and o.dest.is_file()
    assert "CLEAN" in o.detail and not (drop / "p.eml").exists()


def test_alert_levels_and_no_decision_are_still_handled(tmp_path):
    drop = drop_with(tmp_path, "a.eml", "b.eml")
    outs = poll_once(drop, runner=fake_runner(5, stdout="MALICIOUS           92  a.eml"))
    outs += poll_once(drop, runner=fake_runner(6, stdout="INSUFFICIENT_DATA    0  b.eml"))
    assert all(not o.failed for o in outs)
    assert (drop / HANDLED_DIR / "a.eml").is_file() and (drop / HANDLED_DIR / "b.eml").is_file()


def test_failed_scan_moves_to_failed_and_names_the_reason(tmp_path):
    drop = drop_with(tmp_path, "p.eml")
    (o,) = poll_once(drop, runner=fake_runner(1, stderr="p.eml: cannot read file"))
    assert o.failed and o.dest == drop / FAILED_DIR / "p.eml"
    assert "cannot read file" in o.detail


def test_a_hang_is_killed_and_archived_as_failed(tmp_path):
    drop = drop_with(tmp_path, "p.eml")
    (o,) = poll_once(drop, timeout=30.0, runner=timeout_runner())
    assert o.failed and "timed out" in o.detail and o.dest == drop / FAILED_DIR / "p.eml"


def test_record_error_exit_8_lands_in_failed(tmp_path):
    """Code 8 (RECORD_ERROR - the alert record could not be written) is NOT
    in VERDICT_EXITS: the mail must land in failed/ with Outcome.failed True,
    never be archived as a handled scan result."""
    drop = drop_with(tmp_path, "p.eml")
    o = scan_one(drop / "p.eml", argv=["scan", str(drop / "p.eml")],
                 runner=fake_runner(8, stdout="SUSPICIOUS          20  p.eml"))
    assert o.failed and o.dest == drop / FAILED_DIR / "p.eml"
    assert o.dest.is_file() and not (drop / "p.eml").exists()
    assert "not a valid verdict code" in o.detail or "exit 8" in o.detail


def test_one_failure_never_stops_the_pass(tmp_path):
    drop = drop_with(tmp_path, "a.eml", "b.eml", "c.eml")
    outcomes = {}

    def run(argv, timeout):
        name = Path(argv[-1]).name
        if name == "b.eml":
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, stdout="CLEAN  x", stderr="")

    outs = poll_once(drop, runner=run)
    assert len(outs) == 3 and [o.failed for o in outs] == [False, True, False]
    assert (drop / FAILED_DIR / "b.eml").is_file()
    assert (drop / HANDLED_DIR / "a.eml").is_file() and (drop / HANDLED_DIR / "c.eml").is_file()


def test_non_mail_files_are_untouched(tmp_path):
    drop = drop_with(tmp_path, "p.eml", "note.txt")
    poll_once(drop, runner=fake_runner(0))
    assert (drop / "note.txt").exists()          # never moved, never scanned


# --------------------------- the real command (real subprocesses) ------------- #

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
           'width:640px;height:1138px"></div></a>')
RAW = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD)


def test_watch_once_scans_and_archives_a_real_mail(tmp_path):
    from arer.cli import main
    from arer.alert import read_alerts
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "p.eml").write_text(RAW, encoding="utf-8")
    queue = tmp_path / "queue"
    res = CliRunner().invoke(main, ["watch", str(drop), "--alerts", str(queue), "--once",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code == 0, res.output
    assert "-> handled" in res.output and (drop / HANDLED_DIR / "p.eml").is_file()
    assert len(read_alerts(queue)) == 1              # the subprocess wrote the record itself


def test_watch_once_exits_1_when_a_mail_fails_and_still_handles_the_rest(tmp_path):
    from arer.cli import main
    drop = tmp_path / "drop"
    drop.mkdir()
    (drop / "good.eml").write_text(RAW, encoding="utf-8")
    (drop / "bad.json").write_text("{oops", encoding="utf-8")     # invalid parser output -> LoadError
    res = CliRunner().invoke(main, ["watch", str(drop), "--once", "--skip", "intel", "--skip", "history"])
    assert res.exit_code == 1
    assert (drop / FAILED_DIR / "bad.json").is_file()
    assert (drop / HANDLED_DIR / "good.eml").is_file()
    assert "bad.json" in res.output


def test_watch_requires_an_existing_folder():
    from arer.cli import main
    res = CliRunner().invoke(main, ["watch", "/no/such/drop"])
    assert res.exit_code == 2


# --------------------------- R1.3: the exit allowlist ------------------------ #


@pytest.mark.parametrize("rc", [0, 3, 4, 5, 6])
def test_every_valid_verdict_exit_is_handled(tmp_path, rc):
    drop = drop_with(tmp_path, "p.eml")
    (o,) = poll_once(drop, runner=fake_runner(rc, stdout="verdict line"))
    assert not o.failed and o.dest == drop / HANDLED_DIR / "p.eml"


@pytest.mark.parametrize("rc", [1, 2, 7, -9, -11, 127, 99])
def test_operational_signal_and_unknown_exits_are_failed(tmp_path, rc):
    """R1.3: ONLY the verdict allowlist counts as success. Exit 7 (analysis
    error), signal kills (negative) and unknown/future codes must never be
    archived as successfully handled."""
    drop = drop_with(tmp_path, "p.eml")
    (o,) = poll_once(drop, runner=fake_runner(rc, stdout="some output"))
    assert o.failed and o.dest == drop / FAILED_DIR / "p.eml"
    if rc < 0:
        assert "signal" in o.detail
    elif rc in (1, 2):
        assert "exit" in o.detail
    else:
        assert "not a valid verdict code" in o.detail


@pytest.mark.parametrize("rc", [-9, -11, 7])
def test_watch_once_exits_1_for_nonverdict_exits(tmp_path, rc):
    from arer.cli import main
    drop = drop_with(tmp_path, "p.eml")
    import arer.watcher as w
    orig = w._real_runner
    w._real_runner = fake_runner(rc, stdout="looks plausible")
    try:
        r = CliRunner().invoke(main, ["watch", str(drop), "--once"])
    finally:
        w._real_runner = orig
    assert r.exit_code == 1 and (drop / FAILED_DIR / "p.eml").is_file()


def test_launch_failure_is_a_failed_intake(tmp_path):
    drop = drop_with(tmp_path, "p.eml")

    def run(argv, timeout):
        raise OSError("no such interpreter")

    (o,) = poll_once(drop, runner=run)
    assert o.failed and "could not launch scan" in o.detail and o.dest is None
    assert (drop / "p.eml").is_file()          # nothing was lost


def test_archive_failure_becomes_a_failed_outcome_and_the_pass_continues(tmp_path):
    """R6.5: an OSError during archive (disk full, permissions) must not
    crash the poll loop."""
    drop = drop_with(tmp_path, "a.eml", "b.eml")

    import arer.watcher as w
    orig_archive = w.archive
    def broken_archive(mail, dest_dir):
        if mail.name == "a.eml":
            raise OSError("disk full")
        return orig_archive(mail, dest_dir)
    w.archive = broken_archive
    try:
        outs = poll_once(drop, runner=fake_runner(0, stdout="ok"))
    finally:
        w.archive = orig_archive
    assert [o.failed for o in outs] == [True, False]
    assert "disk full" in outs[0].detail
    assert (drop / "a.eml").is_file()                    # still there, nothing lost
    assert (drop / HANDLED_DIR / "b.eml").is_file()
