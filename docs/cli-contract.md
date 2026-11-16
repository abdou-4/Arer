# CLI contract: exit codes

`arer scan` has one exit code per verdict level instead of the old single
"2 means bad". This matters to anything that runs Arer automatically —
cron jobs, mail-drop watchers, the future Phase 6 intake — and it is the
contract the Phase 6 stable alert record (6.1) builds on.

| exit code | meaning | verdict level |
|----------:|---------|---------------|
| 0 | nothing suspicious | `CLEAN` |
| 1 | operational error (file unreadable, nothing to scan) | — |
| 2 | usage error (bad flags, missing argument) | — |
| 3 | alert — worth a look | `SUSPICIOUS` |
| 4 | alert — probably phishing | `LIKELY_PHISHING` |
| 5 | alert — high confidence | `MALICIOUS` |
| 6 | no decision (mail parsed but produced no usable signals) | `INSUFFICIENT_DATA` |

Rules:

- **Scripts should treat `exit >= 3` as an alert.** That one check survives
  every future addition to the table.
- 2 keeps Click's long-standing usage-error convention, so shell tooling
  behaves the way it does for any CLI.
- **Scanning several files:** the worst outcome wins. A verdict outranks a
  load failure (1), which outranks clean (0). One unreadable file does not
  mask a `MALICIOUS` verdict on another (exit 5), and a `MALICIOUS` verdict
  is not hidden by an unrelated load failure either.
- Every scanned file still gets its full report on stdout/stderr; exit codes
  only summarise the batch.

## Breaking change vs. the old scheme

Earlier versions exited 2 for anything `LIKELY_PHISHING` or worse, so old
scripts checking `exit == 2` were really checking "is this mail bad". After
this change:

- replace `exit == 2` checks with `exit >= 3`;
- code 2 now always means "you called the program wrong", never "the mail
  is bad";
- mail that fires only a SUSPICIOUS-weight finding (for example
  `history.known_bad_sender`) now exits 3 where it used to exit 0.

The mapping is frozen alongside the finding IDs
(`tests/test_cli.py::test_exit_code_mapping_is_frozen`); changing it is a
contract change and needs its own measured commit.
