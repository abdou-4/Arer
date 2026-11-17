# The scan journal: `arer.scan-jsonl.v1`

`arer scan --jsonl FILE` writes one JSON object per scanned message — the
machine-readable batch journal for SIEM/SOAR plumbing and post-run checks.
One line per message, valid JSON each, written and flushed as the batch
progresses; the file handle is closed even when individual mails fail.

```bash
arer scan /mail/drop -q --jsonl /out/scan.jsonl
```

## Line shape

| field | when | meaning |
|---|---|---|
| `schema` | always | `"arer.scan-jsonl.v1"` — readers dispatch on this marker |
| `source_file` | always | file name that was scanned |
| `ok` | always | `true` = the mail was loaded and scanned; `false` = operational failure |
| `exit_code` | `ok: true` | the per-mail exit code (docs/cli-contract.md) |
| `report` | `ok: true` | the full scan report (same JSON as `--out`, defanged unless `--raw`) |
| `error` | `ok: false` | why the load failed, message names the file |
| `record_written` | optional | `false` when the mail scanned fine but its ALERT RECORD could not be queued (collision, disk full, permission). **Additive key.** |
| `record_error` | optional | the `safe_text` of that write failure. **Additive key.** |

A `record_written: false` line still has `ok: true` (the scan itself
succeeded — the verdict is real and printed) and the batch exits
`RECORD_ERROR` (8, see docs/cli-contract.md).

## Versioning

Within the schema version, existing keys never move, shrink or change type.
The `record_written` / `record_error` keys are ADDITIVE and appear only on
lines whose alert-record write failed — therefore the schema marker stays
`arer.scan-jsonl.v1`, and readers written for the original key set keep
working (unknown keys are ignored, the same forward-compatibility rule as
the alert record). A breaking change would mint a new marker and its own
page here.
