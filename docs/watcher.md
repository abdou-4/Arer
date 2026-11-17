# The mail drop watcher (Phase 6.5)

A drop folder is how mail reaches a machine unattended: a SOAR drops .eml
files, a mail client saves them, a cron rsyncs them into place.
`arer watch` polls such a folder and triages everything that appears, using
the same `arer scan` you would run by hand - and it feeds the Phase 6 queue
(6.1 alert records, 6.2 dispositions, 6.4 campaigns).

```console
$ arer watch ~/drop --alerts ~/alerts
watching /home/you/drop every 5s (Ctrl-C to stop)
run.eml  MALICIOUS           92  run.eml  -> handled/run.eml
resend.eml  LIKELY_PHISHING  74  resend.eml  -> handled/resend.eml
```

Every mail is scanned by a **fresh subprocess** (`python -m arer scan FILE
-q`), never in the watcher's own process:

- **isolation** - a crash in one mail's scan can never kill the watcher or
  poison the next mail; the watcher reports the failure and moves on;
- **timeout** - one mail gets at most `--timeout` seconds (default 60),
  then the subprocess is killed and the mail is archived as failed. A hung
  parser can never stall the queue;
- **exit codes** - the frozen contract (docs/cli-contract.md) decides what
  happened: a VALID verdict exit (0, 3, 4, 5, 6 - the arer.exitcodes allowlist)
  means handled; exit 1/2, 7 (analysis error), a signal kill (negative code) or
  ANY unknown code is a
  scan failure (the mail is failed). A verdict of MALICIOUS is not a
  failure - it is the watcher doing its job.

## What lands where

The watcher **never deletes anything** and never scans a mail twice:

    DROP/
      run.eml                 a mail that appeared (scanned on the next pass)
      handled/run.eml         scanned, verdict exit 0/3/4/5/6 (allowlist)
      failed/bad.json         scan itself failed (exit 1/2) or it timed out

Archiving never overwrites: a second `run.eml` lands as `handled/run.1.eml`,
so one resend cannot erase the evidence of the first. Rename/move the
handled mail away yourself if you want to keep the drop folder tidy.

Options:

```console
$ arer watch ~/drop --alerts ~/alerts --every 10 --timeout 30 --skip intel
$ arer watch ~/drop --once                # one pass, then exit (cron-friendly)
```

- `--alerts DIR` - the subprocess runs `scan --alerts DIR`, so alert-level
  mail lands in the Phase 6 queue exactly as if you had run the scan
  yourself; review it with `alerts list` / `alerts campaigns`.
- `--every SECONDS` - poll interval in continuous mode (default 5).
- `--skip NAME` - passed through to scan (e.g. `intel`, `history`), same
  semantics as `arer scan --skip`.
- `--once` - one pass, then exit. **Exit code: 1 if any mail failed,
  otherwise 0** - so a cron job can alert you when the drop folder has a
  problem. Without `--once` the watcher loops until Ctrl-C (clean stop).

## What is picked up

- top level of DROP only - sub-folders (including handled/ and failed/) are
  never entered;
- known mail extensions only (`.eml`, `.msg`, `.json`, same list as scan) -
  a half-written file with an unknown extension is never read or moved
  mid-transfer; dot files, symlinks and `*.report.json` sidecars are skipped;
- candidates are processed sorted by name, one subprocess each, in the same
  pass - one bad mail never stops the batch, its failure is printed and
  `--once` exits 1, exactly like `arer parse` and `arer scan`.

## Files

`watch` writes no new record types: the alert records and dispositions it
produces are the Phase 6.1/6.2 records, and the menu ("Watch a mail drop")
runs the same command. `src/arer/__main__.py` (added in this phase) makes
`python -m arer scan ...` the canonical way to spawn an isolated scan.


## Hardening (R6)

- single-instance lock: a second `arer watch` on the same drop refuses to
  start (`.arer-watch.lock` with the holder pid; a stale lock from a dead
  holder is taken over);
- SIGTERM stops the watcher gracefully after the current pass;
- scan subprocess output is BOUNDED (1 MB per stream) and a timeout kills
  the WHOLE process group - no descendant survives;
- non-regular files (FIFOs, sockets, devices, symlinks) are skipped via
  lstat; a file rewritten during its scan is a failed intake, never a
  verdict over mixed bytes (size+mtime compared before/after);
- `--min-age SECONDS` leaves files modified within the last N seconds for
  the next pass (half-written transfers); producers that rename atomically
  can keep it off;
- dash-leading filenames are safe (options first, then an explicit `--`).
