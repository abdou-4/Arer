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

v1 watches the TOP LEVEL of the drop folder only, and only files with a
known mail extension (same list as `arer scan` minus content sniffing): a
half-written file with an unknown extension is never read or moved
mid-transfer. Sub-folders (including the watcher's own handled/ and failed/)
are never entered.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, NamedTuple

from .loader import SCAN_SUFFIXES

HANDLED_DIR = "handled"     # scanned without a scan-level failure (verdict may still be alert-level)
FAILED_DIR = "failed"       # scan itself failed (exit 1/2) or the mail timed out

_FAILED_EXITS = {1, 2}      # scan's own failure codes (docs/cli-contract.md); >= 3 is a verdict

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

Runner = Callable[[list[str], float], subprocess.CompletedProcess]


class Outcome(NamedTuple):
    """What happened to one mail in one pass."""
    path: Path          # where the mail was found in the drop folder
    dest: Path | None   # where it was archived (handled/ or failed/), never None after a pass
    failed: bool        # True when scan failed or timed out (NOT when the verdict is alert-level)
    detail: str         # one human-readable line: the verdict line, or the reason


def scan_command(mail: Path, alerts_dir: Path | None = None,
                 skip: tuple[str, ...] = ()) -> list[str]:
    """The exact `arer scan` argv a fresh interpreter runs for one mail."""
    cmd = [sys.executable, "-m", "arer", "scan", str(mail), "-q"]
    if alerts_dir:
        cmd += ["--alerts", str(alerts_dir)]
    for name in skip:
        cmd += ["--skip", name]
    return cmd


def mail_candidates(drop: Path) -> list[Path]:
    """Top-level mail files in the drop folder, sorted by name. Dot files,
    symlinks, *.report.json sidecars and unknown extensions are skipped."""
    drop = Path(drop)
    if not drop.is_dir():
        return []
    out = []
    for p in drop.iterdir():
        if p.name.startswith(".") or not p.is_file() or p.is_symlink():
            continue
        if p.name.endswith(".report.json"):
            continue
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
    """Scan one mail in a fresh subprocess and archive it. A hang is killed
    at `timeout` seconds; a failed scan (exit 1/2) or a timeout archives the
    mail to failed/ and reports the reason - the pass continues."""
    run = runner or _real_runner
    try:
        proc = run(argv, timeout)
    except subprocess.TimeoutExpired as e:
        dest = archive(mail, mail.parent / FAILED_DIR)
        return Outcome(mail, dest, True, f"timed out after {e.timeout:g}s")
    rc = proc.returncode
    if rc in _FAILED_EXITS:
        dest = archive(mail, mail.parent / FAILED_DIR)
        detail = _last_line(getattr(proc, "stderr", "")) or f"scan failed (exit {rc})"
        return Outcome(mail, dest, True, detail)
    dest = archive(mail, mail.parent / HANDLED_DIR)
    detail = _last_line(getattr(proc, "stdout", "")) or f"exit {rc}"
    return Outcome(mail, dest, False, detail)


def _real_runner(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(argv, timeout=timeout, capture_output=True, text=True, check=False)


def poll_once(drop: Path, *, alerts_dir: Path | None = None, timeout: float = 60.0,
              skip: tuple[str, ...] = (), runner: Runner | None = None) -> list[Outcome]:
    """One pass over the drop folder: scan every waiting mail, archive it,
    report the outcomes. One bad mail never stops the pass."""
    return [scan_one(m, argv=scan_command(m, alerts_dir, skip), timeout=timeout, runner=runner)
            for m in mail_candidates(drop)]
