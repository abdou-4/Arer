"""
watcher.py - Phase 6.5: watch a mail drop folder.

A drop folder is how mail reaches a machine unattended (a SOAR drops .eml
files, a mail client saves them, a cron rsyncs them). For every mail file
that appears, the watcher runs a REAL `arer scan` in a fresh subprocess - it
never scans in its own process, so a crash or a hang in one mail can never
kill the watcher or poison the next mail:

- isolation:  fresh interpreter per mail (`python -m arer scan ... -q`);
- timeout:    one mail gets at most --timeout seconds, then it is killed;
- archiving:  every processed mail moves to DROP/handled/ or DROP/failed/,
              never overwritten (a collision gets a numeric suffix), so
              nothing is scanned twice and nothing is ever deleted;
- discipline: one bad mail never stops the pass; failures are named and
              `watch --once` exits 1 if any mail failed - the same contract
              as `arer parse` and `arer scan`.

R1.3: classification is an ALLOWLIST, never a numeric range. Only the valid
verdict exits (0, 3, 4, 5, 6 - arer.exitcodes.VERDICT_EXITS) count as a
completed scan and land in handled/. Everything else is failed/: operational
errors (1, 2), the analysis-failure code (7), negative return codes (the
child was killed by a signal), and ANY unknown/future code. A crashed or
signal-killed scan can therefore never be archived as successfully handled.

v1 watches the TOP LEVEL of the drop folder only, and only files with a
known mail extension (same list as `arer scan` minus content sniffing): a
half-written file with an unknown extension is never read or moved
mid-transfer. Sub-folders (including the watcher's own handled/ and failed/)
are never entered.
"""
from __future__ import annotations

import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, NamedTuple

from .exitcodes import VERDICT_EXITS
from .loader import SCAN_SUFFIXES

HANDLED_DIR = "handled"     # scan completed with a valid verdict exit (docs/cli-contract.md)
FAILED_DIR = "failed"       # anything else: exit 1/2/7, a signal kill, an unknown code, a timeout,
                            # a launch error, or an archive failure (R1.3 allowlist)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

Runner = Callable[[list[str], float], subprocess.CompletedProcess]

# R6.5: a scan subprocess may print at most this much stdout/stderr; more is
# truncated (subprocess.run(capture_output=True) had no cap and could buffer
# an unbounded hostile output in memory).
_MAX_CAPTURE = 1_000_000


class Outcome(NamedTuple):
    """What happened to one mail in one pass."""
    path: Path          # where the mail was found in the drop folder
    dest: Path | None   # where it was archived (handled/ or failed/), never None after a pass
    failed: bool        # True when scan failed or timed out (NOT when the verdict is alert-level)
    detail: str         # one human-readable line: the verdict line, or the reason


def scan_command(mail: Path, alerts_dir: Path | None = None,
                 skip: tuple[str, ...] = ()) -> list[str]:
    """The exact `arer scan` argv a fresh interpreter runs for one mail.

    R6.4: all options come BEFORE an explicit `--` separator, so a mail file
    named "-weird.eml" (or any dash-leading path) is never parsed as a flag."""
    cmd = [sys.executable, "-m", "arer", "scan", "-q"]
    if alerts_dir:
        cmd += ["--alerts", str(alerts_dir)]
    for name in skip:
        cmd += ["--skip", name]
    cmd += ["--", str(mail)]
    return cmd


def mail_candidates(drop: Path, *, min_age_s: float = 0.0) -> list[Path]:
    """Top-level mail files in the drop folder, sorted by name. Dot files,
    symlinks, non-regular files (FIFOs, sockets, devices - checked via
    lstat, R6.4), *.report.json sidecars and unknown extensions are skipped.

    min_age_s > 0 leaves files that were modified within the last
    min_age_s seconds for the NEXT pass (a half-written file is never
    scanned mid-transfer; producers that rename atomically are safe with
    any value)."""
    drop = Path(drop)
    if not drop.is_dir():
        return []
    now = time.time()
    out = []
    for p in drop.iterdir():
        if p.name.startswith(".") or p.name.endswith(".report.json"):
            continue
        try:
            st = p.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):               # symlinks, FIFOs, sockets, devices
            continue
        if min_age_s > 0 and (now - st.st_mtime) < min_age_s:
            continue                                   # maybe still being written
        if p.suffix.lower() in SCAN_SUFFIXES:
            out.append(p)
    return sorted(out)


def archive(mail: Path, dest_dir: Path) -> Path:
    """Move the mail into dest_dir without ever overwriting: p.eml colliding
    with an existing p.eml lands as p.1.eml. Returns the new location."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / mail.name
    n = 1
    while dest.exists():
        dest = dest_dir / f"{mail.stem}.{n}{mail.suffix}"
        n += 1
    return mail.replace(dest)


def _last_line(text: str | None) -> str:
    lines = [ln.strip() for ln in _ANSI.sub("", text or "").splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def scan_one(mail: Path, *, argv: list[str], timeout: float = 60.0,
             runner: Runner | None = None) -> Outcome:
    """Scan one mail in a fresh subprocess and archive it.

    R1.3 allowlist: only VERDICT_EXITS (0, 3, 4, 5, 6) is a completed scan ->
    handled/. A hang is killed at `timeout` seconds; operational exits (1, 2),
    the analysis-failure code (7), signal kills (negative codes), unknown
    codes, launch errors and archive failures all archive the mail to failed/
    and report the reason - the pass continues.

    R6.4: the mail's size and mtime are compared before and after the scan;
    a file that CHANGED while being scanned (a producer rewrote it) is a
    failed intake, not a verdict over mixed bytes."""
    run = runner or _real_runner
    try:
        st_before = mail.lstat()
    except OSError as e:
        return Outcome(mail, None, True, f"vanished before scan ({e})")
    try:
        proc = run(argv, timeout)
    except subprocess.TimeoutExpired as e:
        dest = archive(mail, mail.parent / FAILED_DIR)
        return Outcome(mail, dest, True, f"timed out after {e.timeout:g}s")
    except OSError as e:                                   # launch failure is a failed intake too
        return Outcome(mail, None, True, f"could not launch scan ({e})")
    try:
        st_after = mail.lstat()
    except OSError:
        st_after = None
    if st_after is None or (st_after.st_size, st_after.st_mtime) != (st_before.st_size, st_before.st_mtime):
        return Outcome(mail, None, True, "file changed during scan - left in place for the next pass")
    rc = proc.returncode
    if rc in VERDICT_EXITS:
        dest = archive(mail, mail.parent / HANDLED_DIR)
        detail = _last_line(getattr(proc, "stdout", "")) or f"exit {rc}"
        return Outcome(mail, dest, False, detail)
    dest = archive(mail, mail.parent / FAILED_DIR)
    if rc < 0:
        detail = f"scan killed by signal {-rc}"
    elif _last_line(getattr(proc, "stderr", "")):
        detail = _last_line(getattr(proc, "stderr", ""))
    else:
        detail = f"scan exited {rc}, not a valid verdict code"
    return Outcome(mail, dest, True, detail)


def _real_runner(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    """Run the scan subprocess in its own SESSION with BOUNDED output capture
    (R6.5): stdout/stderr go to spool files, at most _MAX_CAPTURE bytes each
    are read back, and on timeout the WHOLE process group is killed so no
    descendant survives."""
    with tempfile.TemporaryFile() as out_spool, tempfile.TemporaryFile() as err_spool:
        popen_kwargs: dict = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, stdout=out_spool, stderr=err_spool, **popen_kwargs)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise
        def _read_tail(spool) -> str:
            spool.seek(0, os.SEEK_END)
            size = min(spool.tell(), _MAX_CAPTURE)
            spool.seek(spool.tell() - size)
            return spool.read(size).decode("utf-8", "replace")
        return subprocess.CompletedProcess(argv, proc.returncode,
                                           stdout=_read_tail(out_spool), stderr=_read_tail(err_spool))


def _kill_group(proc: subprocess.Popen) -> None:
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def poll_once(drop: Path, *, alerts_dir: Path | None = None, timeout: float = 60.0,
              skip: tuple[str, ...] = (), runner: Runner | None = None,
              min_age_s: float = 0.0) -> list[Outcome]:
    """One pass over the drop folder: scan every waiting mail, archive it,
    report the outcomes.

    R1.3/R6.5: every candidate is wrapped in its own exception boundary - one
    OSError (a vanished file, a failed archive move, a permission error)
    becomes a failed Outcome for THAT mail; the pass always continues."""
    outcomes = []
    for m in mail_candidates(drop, min_age_s=min_age_s):
        try:
            outcomes.append(scan_one(m, argv=scan_command(m, alerts_dir, skip),
                                     timeout=timeout, runner=runner))
        except Exception as e:                             # noqa: BLE001 - one bad mail never stops the pass
            outcomes.append(Outcome(m, None, True, f"watcher error ({type(e).__name__}): {e}"))
    return outcomes
