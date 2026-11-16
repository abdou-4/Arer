# Dispositions: the analyst's answer to an alert (Phase 6.2)

Phase 6.1 produced the alert queue (`docs/alert-record.md`); Phase 6.2 is the
human loop around it. A **disposition** is the analyst's decision about one
alert record: `acknowledged` (seen, work queued), `benign` (false alarm) or
`phishing` (true positive). The vocabulary is frozen by
`tests/test_disposition.py` — extending it is a contract change like the exit
codes in `docs/cli-contract.md`.

## The sidecar layout

```
alerts/
  3f9c...alert_id....alert.json          <- the record, never modified (arer.alert.v1)
  3f9c...alert_id....disposition.json    <- your decision (arer.disposition.v1)
```

Since R1.1 the record file is named by the alert's immutable `alert_id`, so a
source filename collision can never overwrite a record or re-attach an old
decision to a new mail.

The alert record is the machine's statement about the mail and stays
byte-for-byte frozen (its golden test keeps its meaning). The disposition is
stored **beside** it, keyed by `alert_id`, so it can be re-set, moved with the
folder, or deleted without ever touching attacker-derived content. An alert
without a sidecar is `new` — there is no `new` status to set.

## Commands

```bash
arer alerts list /alerts                      # status column; newest first
arer alerts list /alerts --status new         # the unhandled queue
arer alerts list /alerts --status phishing --level MALICIOUS
arer alerts set /alerts <alert_id> acknowledged --note "seen in triage"
arer alerts set /alerts <alert_id> phishing --note "real campaign, blocked sender"
```

`<alert_id>` accepts 6+ characters (copy it from `alerts list`), and it must
match exactly one record in the folder. Re-setting overwrites the sidecar with
the new status and timestamp; the note is the analyst's own words and is
stored **verbatim** — pasted IOCs are common and must not be defanged or
mangled.

## The record `arer.disposition.v1`

| field | meaning |
|-------|---------|
| `schema` | `"arer.disposition.v1"`. Readers dispatch on this string. |
| `alert_id` | the alert record this decision answers. Never re-minted on re-set. |
| `mail_sha256` | copied from `verdict.sha256` — handy for grepping and for 6.3 export. |
| `status` | `acknowledged` \| `benign` \| `phishing`. |
| `note` | why. Verbatim, may be empty. |
| `set_utc` | when this disposition was set, ISO-8601 UTC with `Z` suffix. |

## Exporting the queue (Phase 6.3)

```bash
arer alerts export /alerts                          # JSONL to the screen
arer alerts export /alerts --format csv -o q.csv    # one row per alert
arer alerts export /alerts --status new             # only the unhandled
arer alerts export /alerts --raw                    # keep real IOCs (default is defanged)
```

One flat line (JSONL) or row (CSV) per alert, dispositions merged in
(`disposition_status` / `disposition_note` / `disposition_set_utc`, empty when
`new`). The flat schema is frozen by `tests/test_export.py`
(`EXPORT_KEYS` == `COLUMNS`); each line carries `record_file`, the queue file
it came from, so an aggregate view can always be traced back to the record.

Export is safe by default: every string is defanged on the way out
(idempotent on records that were already defanged at scan time; the
`schema` marker is never defanged), so an export can be pasted into a ticket
or shipped to a SIEM without leaking live IOCs. The queue folder stays the
source of truth — the export is derived and never written back.

Batch rules are the same as everywhere in the queue: corrupt alert or
disposition files are named on stderr and the command exits 1, while every
healthy record still exports. Library use: `export_row(alert, disposition,
record_file)` + `render(rows, "jsonl" | "csv", defang=True)` in
`src/arer/export.py`.

## Reading rules

Same discipline as the alert reader (6.1b), frozen by
`tests/test_disposition.py`:

- Dispatch on the `schema` marker; unknown schema is an explicit error, never
  a silent mis-read.
- Unknown extra keys are ignored (forward compatibility).
- Errors name the file and the bad field(s).
- One corrupt sidecar never stops a batch: `alerts list` names it on stderr
  and exits 1 while still listing everything healthy.

Library use: `read_disposition(alert_path)` (`None` when absent,
`DispositionError` when unreadable), `load_disposition(path)` for a bare file,
`build_disposition(...)` + `write_disposition(d, alert_path)` to write one.

## Provenance and training eligibility (R2)

A sidecar records WHAT was decided; the history database records WHERE THE
DECISION CAME FROM. Every `alerts set` / `alerts set-group` decision is
mirrored into `data/history.db` as an append-only decision event with
provenance (`analyst` + local analyst id), a timestamp and an explicit
training-eligibility flag:

| sidecar status | case disposition | training eligible |
|---|---|---|
| `phishing` | `true_positive` | yes (analyst decision) |
| `benign` | `false_positive` | yes (analyst decision) |
| `acknowledged` | workflow state only | never |

Rules:

- the decision API needs schema 2; `arer history migrate` upgrades the
  database (verified backup first, one transaction, idempotent);
- sidecars imported from before the remediation
  (`arer history import-dispositions QUEUE_DIR`) carry provenance
  `legacy_unverified`: they are preserved verbatim but are NEVER
  training-eligible until an analyst re-decides them;
- tool verdicts and unreviewed alerts can never become training labels
  ("only human labels teach the tool").

## Provenance in the sidecar (R4, schema v2)

New sidecars are `arer.disposition.v2` and carry `provenance` (analyst) and
`analyst` (local analyst id). The v1 sidecars of an existing queue read back
as `legacy_unverified`. The export gate (`is_analyst_confirmed_phishing`)
accepts ONLY analyst-provenance `phishing` decisions, so an old queue's
records are never exported as confirmed indicators until an analyst
re-decides them with `alerts set`.
