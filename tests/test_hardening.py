"""R6: hostile-input and watcher hardening.

What is frozen here:
- `arer parse` and `scan` sit behind the SAME size boundary (max_eml_mb);
- hostile shapes (deep MIME nesting, thousands of headers, a big ZIP
  central directory, many parts) are handled BOUNDED: parsing completes or
  fails safely, in a subprocess with a hard timeout, and the header count
  is capped at the parser boundary;
- the watcher survives dash-leading filenames (`--` separator), FIFOs and
  other non-regular files, half-written files (min-age), a file rewritten
  during its scan, and a second watcher instance (single-instance lock);
  scan subprocess output is bounded and a timeout kills the whole group;
- SIGTERM stops the watcher gracefully after the current pass;
- .msg without the Outlook backend fails with an actionable install message.

Deliberately NOT claimed here (needs a real resource-limited environment):
multi-day soak, cgroup/memory limits, 400k-entry ZIPs - see the remediation
report's "remaining" list.
"""
import os
import signal
import subprocess
import sys
import time
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.cli import main
from arer.watcher import FAILED_DIR, HANDLED_DIR, mail_candidates, poll_once, scan_command


def fake_runner(returncode=0, stdout="", stderr=""):
    def run(argv, timeout):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)
    return run


def drop_with(tmp_path: Path, *names: str) -> Path:
    d = tmp_path / "drop"
    d.mkdir()
    for n in names:
        (d / n).write_text("From: a@b.c\r\nSubject: x\r\n\r\nhi", encoding="utf-8")
    return d


def _cfg_dir(tmp_path, **limits):
    import shutil
    d = tmp_path / "cfg"
    shutil.copytree("config", d, dirs_exist_ok=True)
    rules = d / "rules.yaml"
    text = rules.read_text(encoding="utf-8")
    for k, v in limits.items():
        text = text.replace(f"{k}: 10", f"{k}: {v}").replace(f"{k}: 50", f"{k}: {v}")
    rules.write_text(text, encoding="utf-8")
    return d


# --------------------------- R6.1: the size boundary --------------------------- #


def test_parse_is_behind_the_same_size_boundary(tmp_path):
    """A file over max_eml_mb is refused by `parse` exactly like `scan`."""
    mails = tmp_path / "mails"
    mails.mkdir()
    big = mails / "big.eml"
    big.write_text("From: a@b.c\r\nSubject: big\r\n\r\n" + "x" * 400_000, encoding="utf-8")
    cfg_dir = _cfg_dir(tmp_path, max_eml_mb=1)
    # max_eml_mb minimum is 1 MB; a 0.4 MB file parses fine...
    out = tmp_path / "out"
    r = CliRunner().invoke(main, ["parse", str(mails), "-o", str(out), "--config", str(cfg_dir)])
    assert r.exit_code == 0 and "[ok]" in r.output
    # ...but a config with a 1 MB cap and a >1 MB file is refused BEFORE parsing
    big.write_text("From: a@b.c\r\nSubject: big\r\n\r\n" + "x" * (1024 * 1024 + 100_000), encoding="utf-8")
    out2 = tmp_path / "out2"
    r = CliRunner().invoke(main, ["parse", str(big), "-o", str(out2), "--config", str(cfg_dir)])
    assert r.exit_code == 1 and "[fail]" in r.output and "limit is 1 MB" in r.output
    assert not (out2 / "big.eml.json").exists()         # nothing was parsed


def test_scan_rejects_the_same_overlimit_file(tmp_path):
    big = tmp_path / "big.eml"
    big.write_text("From: a@b.c\r\nSubject: big\r\n\r\n" + "x" * (1024 * 1024 + 100_000), encoding="utf-8")
    cfg_dir = _cfg_dir(tmp_path, max_eml_mb=1)
    r = CliRunner().invoke(main, ["scan", str(big), "-q", "--config", str(cfg_dir)])
    assert r.exit_code == 1 and "limit is 1 MB" in r.output


# --------------------------- R6.3: hostile shapes, bounded --------------------- #


def _deep_mail(depth: int) -> bytes:
    msg = EmailMessage()
    msg.set_content("leaf")
    inner = msg
    for i in range(depth):
        outer = EmailMessage()
        outer.make_mixed()
        outer.attach(inner)                             # type: ignore[attr-defined]
        inner = outer
    return inner.as_bytes()


def _many_headers_mail(n: int) -> bytes:
    m = EmailMessage()
    m["From"] = "a@b.c"; m["Subject"] = "h"; m["To"] = "x@y.z"
    body = m.as_bytes()
    extra = b"".join(f"X-Fuzz-{i}: v{i}\r\n".encode() for i in range(n))
    return extra + body


def _zip_bomb_mail(entries: int) -> bytes:
    m = EmailMessage()
    m["From"] = "a@b.c"; m["Subject"] = "zip"; m["To"] = "x@y.z"
    m.set_content("zip inside")
    buf = __import__("io").BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for i in range(entries):
            z.writestr(f"f{i}.txt", "x")
    m.add_attachment(buf.getvalue(), maintype="application", subtype="zip",
                     filename="many.zip")
    return m.as_bytes()


@pytest.mark.parametrize("name,blob_fn,budget_s", [
    ("deep150.eml", lambda: _deep_mail(150), 60),
    ("headers5000.eml", lambda: _many_headers_mail(5000), 60),
    ("zip1500.eml", lambda: _zip_bomb_mail(1500), 120),
])
def test_hostile_shapes_complete_bounded_in_a_subprocess(tmp_path, name, blob_fn, budget_s):
    """Each hostile case runs as its own `arer scan` subprocess with a hard
    budget: it must TERMINATE (verdict or structured failure), and the
    header flood must be capped at the parser boundary."""
    mails = tmp_path / "mails"
    mails.mkdir()
    (mails / name).write_bytes(blob_fn())
    t0 = time.time()
    proc = subprocess.run([sys.executable, "-m", "arer", "scan", str(mails / name), "-q",
                           "--skip", "intel", "--skip", "history"],
                          capture_output=True, text=True, timeout=budget_s)
    elapsed = time.time() - t0
    assert proc.returncode in (0, 1, 2, 3, 4, 5, 6, 7), proc.stderr[-500:]
    assert elapsed < budget_s


def test_header_count_is_capped_at_the_parser_boundary(tmp_path):
    from arer.loader import load_any
    from arer.config import load_config
    p = tmp_path / "headers5000.eml"
    p.write_bytes(_many_headers_mail(5000))
    email = load_any(p, load_config())
    assert len(email.headers.raw_ordered) <= 2000       # the model's cap holds


# --------------------------- R6.4/R6.5: watcher filesystem + operational ------- #


def test_dash_leading_filename_is_scanned_not_parsed_as_a_flag(tmp_path):
    drop = drop_with(tmp_path)
    mail = drop / "-weird.eml"
    mail.write_text("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
                    "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
                    + "<html><textarea></textarea>" * 25 + "<option>" * 10
                    + '<div style="display:none !important;">x</div>' * 22
                    + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
                      'width:640px;height:1138px"></div></a>', encoding="utf-8")
    outs = poll_once(drop)
    assert len(outs) == 1 and not outs[0].failed
    assert (drop / HANDLED_DIR / "-weird.eml").is_file()


def test_non_regular_files_are_skipped(tmp_path):
    drop = drop_with(tmp_path)
    os.mkfifo(drop / "pipe.fif")                        # a FIFO must never be opened
    (drop / "link.eml").symlink_to(drop / "p.eml")      # symlink skipped too
    assert mail_candidates(drop) == []


def test_min_age_leaves_half_written_files_for_the_next_pass(tmp_path):
    drop = drop_with(tmp_path, "fresh.eml")
    old = time.time() - 120
    (drop / "stale.eml").write_text("From: a@b.c\r\nSubject: x\r\n\r\nhi", encoding="utf-8")
    os.utime(drop / "stale.eml", (old, old))
    # the file written NOW is skipped: maybe still half-written
    assert [p.name for p in mail_candidates(drop, min_age_s=60)] == ["stale.eml"]
    # with min-age off everything is picked (atomic-rename producers)
    assert {p.name for p in mail_candidates(drop)} == {"fresh.eml", "stale.eml"}


def test_file_rewritten_during_scan_is_a_failed_intake(tmp_path):
    """R6.4: if the producer rewrites the file between scan start and archive,
    the bytes are mixed - the outcome must be failed and the file stays."""
    drop = drop_with(tmp_path, "p.eml")

    def run(argv, timeout):
        (drop / "p.eml").write_text("From: someone@else.com\r\nSubject: swapped\r\n\r\nother", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="CLEAN  0  p.eml", stderr="")

    outs = poll_once(drop, runner=run)
    assert len(outs) == 1 and outs[0].failed
    assert "changed during scan" in outs[0].detail
    assert (drop / "p.eml").is_file()                   # left in place, never mis-archived
    assert not (drop / HANDLED_DIR).exists()


def test_second_watcher_instance_is_refused(tmp_path):
    drop = drop_with(tmp_path)
    from arer.cli import _acquire_watch_lock, _release_watch_lock
    lock = _acquire_watch_lock(drop)
    assert lock is not None
    r = CliRunner().invoke(main, ["watch", str(drop), "--once"])
    assert r.exit_code == 1 and "already running" in r.output
    _release_watch_lock(lock)
    r = CliRunner().invoke(main, ["watch", str(drop), "--once"])
    assert r.exit_code != 1 or "already running" not in r.output   # lock released


def test_stale_lock_is_taken_over(tmp_path):
    drop = drop_with(tmp_path)
    lock = drop / ".arer-watch.lock"
    lock.write_text("999999", encoding="utf-8")         # pid that does not exist
    from arer.cli import _acquire_watch_lock, _release_watch_lock
    got = _acquire_watch_lock(drop)
    assert got is not None                              # stale lock taken over
    _release_watch_lock(got)
    assert not lock.exists()


def test_sigterm_stops_the_watcher_gracefully(tmp_path):
    drop = drop_with(tmp_path, "p.eml")
    proc = subprocess.Popen([sys.executable, "-m", "arer", "watch", str(drop), "--every", "0.2",
                             "--skip", "intel", "--skip", "history"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    time.sleep(3)                                       # let it start + scan once
    proc.send_signal(signal.SIGTERM)
    try:
        out, _err = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("watcher ignored SIGTERM")
    assert "stopped" in out


def test_scan_output_capture_is_bounded(tmp_path):
    """A scan subprocess that prints megabytes cannot balloon the watcher's
    memory: the runner reads back at most _MAX_CAPTURE bytes per stream."""
    from arer.watcher import _MAX_CAPTURE, _real_runner
    proc = subprocess.run([sys.executable, "-c", "print('x' * 4_000_000)"],
                          capture_output=True)
    assert len(proc.stdout) > _MAX_CAPTURE              # sanity: the child really printed more
    run = _real_runner([sys.executable, "-c", "print('x' * 4_000_000)"], timeout=30)
    assert 0 < len(run.stdout) <= _MAX_CAPTURE
    assert run.returncode == 0


def test_timeout_kills_the_whole_process_group(tmp_path):
    """A scan subprocess that spawns its own child: on timeout, no descendant
    of the group survives."""
    drop = drop_with(tmp_path, "p.eml")
    # a unique script name so pgrep matches ONLY this test's processes
    hang = tmp_path / f"hang_{os.getpid()}_{int(time.time())}.py"
    marker = hang.stem
    hang.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'], "
        "start_new_session=False)\n"
        "time.sleep(600)\n")
    def run(argv, timeout):
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    outs = poll_once(drop, runner=run)
    assert all(not o.failed for o in outs)              # sanity with the fake runner
    # the real kill path: run the hanging script AS its own session, kill the group
    from arer.watcher import _kill_group
    proc = subprocess.Popen([sys.executable, str(hang)], start_new_session=True)
    try:
        time.sleep(1.5)
        before = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
        assert before.returncode == 0                   # the tree exists
        _kill_group(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(0.5)
        after = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
        assert after.returncode != 0                    # the whole group is gone
    finally:
        _kill_group(proc)                               # never leak sleepers on failure
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


# --------------------------- R6.6: packaging ---------------------------------- #


def test_msg_without_backend_has_an_actionable_message(tmp_path):
    """When extract-msg is missing, .msg input fails with the install hint
    instead of an opaque library error."""
    from arer.loader import LoadError, load_any
    from arer.config import load_config
    msg = tmp_path / "sample.msg"
    msg.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100)   # OLE2 magic
    import arer.mail_parser as mp
    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def fake_import(name, *a, **k):
        if name == "extract_msg":
            raise ImportError("No module named 'extract_msg'")
        return real_import(name, *a, **k)

    builtins_mod = __import__("builtins")
    orig = builtins_mod.__import__
    builtins_mod.__import__ = fake_import
    try:
        with pytest.raises((LoadError, RuntimeError)) as e:
            mp.parse_mail_file(msg)
        assert "arer[outlook]" in str(e.value)
    finally:
        builtins_mod.__import__ = orig


def test_config_discovery_finds_cwd_config(tmp_path, monkeypatch):
    """R6.6: a wheel install finds ./config next to the CWD before falling
    back to the source-tree default."""
    import shutil
    cfg = tmp_path / "config"
    shutil.copytree("config", cfg, dirs_exist_ok=True)
    (cfg / "rules.yaml").write_text(
        (cfg / "rules.yaml").read_text(encoding="utf-8").replace("suspicious: 20", "suspicious: 22"),
        encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PHISHSCOPE_CONFIG", raising=False)
    from arer.config import load_config
    assert load_config().thresholds.suspicious == 22    # CWD config wins
    monkeypatch.chdir(tmp_path / "..")
    assert load_config().thresholds.suspicious == 20    # source-tree default still works
