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
  salad.eml.alert.json          <- the record, never modified (arer.alert.v1)
  salad.eml.disposition.json    <- your decision (arer.disposition.v1)
```

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
