# CLI contract: exit codes

`arer scan` has one exit code per outcome instead of the old single
"2 means bad". This matters to anything that runs Arer automatically —
cron jobs, mail-drop watchers, the Phase 6 intake — and it is the
contract the Phase 6 stable alert record (6.1) builds on.

The table below is frozen in ONE place: `src/arer/exitcodes.py`.
The CLI, the watcher, the docs and the tests all read that module.

| exit code | meaning | verdict level |
|----------:|---------|---------------|
| 0 | nothing suspicious | `CLEAN` |
| 1 | operational error (file unreadable, nothing to scan) | — |
| 2 | usage error (bad flags, missing argument) | — |
| 3 | alert — worth a look | `SUSPICIOUS` |
| 4 | alert — probably phishing | `LIKELY_PHISHING` |
| 5 | alert — high confidence | `MALICIOUS` |
| 6 | no decision (mail parsed but produced no usable signals) | `INSUFFICIENT_DATA` |
| 7 | analysis failure (analyzers crashed/timed out; result is incomplete, never a clean success) | — |
| 8 | record-write failure — `RECORD_ERROR` (an alert record could not be written: collision, disk full, permission) — the batch continues and every verdict still prints, but the lost record is never hidden behind a verdict code | — |

## Rules

- **Match exact codes, or use the explicit allowlist — never `exit >= 3`.**
  Code 6 (`INSUFFICIENT_DATA`) is a no-decision, not an alert, and code 7
  (`ANALYSIS_ERROR`) is an analysis failure, not a verdict at all.
  The allowlist lives in `arer.exitcodes`:
  - `VERDICT_EXITS = {0, 3, 4, 5, 6}` — the only codes a *completed* scan produces;
  - `ALERT_EXITS = {3, 4, 5}` — the subset worth a look;
  - `is_alert_exit(code)` — the predicate to use in scripts.
  Negative exit codes mean the child was killed by a signal; they are never
  verdicts either (the watcher archives such mail under `failed/`).
- 2 keeps Click's long-standing usage-error convention, so shell tooling
  behaves the way it does for any CLI.
- **Scanning several files:** the worst outcome wins, ranked by
  `EXIT_SEVERITY`. A verdict (5 > 4 > 3) outranks a load failure (1), which
  outranks an analysis error (7), which outranks a no-decision (6), which
  outranks clean (0). One unreadable file does not mask a `MALICIOUS`
  verdict on another (exit 5), and a `MALICIOUS` verdict is not hidden by an
  unrelated load failure either. A failed alert-record write (8) outranks
  EVERY verdict: a batch with a `MALICIOUS` mail and a record that could not
  be queued exits 8, not 5 — the verdicts are still on stdout, but the
  missing record must be unmistakable. Code 8 is not in `VERDICT_EXITS`, so
  the watcher archives such mail under `failed/`.
- Every scanned file still gets its full report on stdout/stderr; exit codes
  only summarise the batch.

## Breaking change vs. the old scheme

Earlier versions exited 2 for anything `LIKELY_PHISHING` or worse, so old
scripts checking `exit == 2` were really checking "is this mail bad". After
that change:

- replace `exit == 2` checks with exact codes or `is_alert_exit(code)`
  (the older interim advice "use `exit >= 3`" is now obsolete: code 6 and
  code 7 make a range check lie);
- code 2 now always means "you called the program wrong", never "the mail
  is bad";
- mail that fires only a SUSPICIOUS-weight finding (for example
  `history.known_bad_sender`) now exits 3 where it used to exit 0.

The mapping is frozen alongside the finding IDs
(`tests/test_exit_contract.py::test_exit_code_mapping_is_frozen`); changing
it is a contract change and needs its own measured commit.
