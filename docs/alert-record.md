# The alert record: `arer.alert.v1`

Phase 6.1a. Every alert-worthy e-mail gets a stable, versioned JSON record —
the file Phase 6.2 dispositions, Phase 6.3 export and any external tooling
(SOAR, SIEM, mail-drop watchers) read. Its shape is frozen by
`tests/test_alert.py` and `tests/golden/alert_v1.json`; changing the record is
a contract change like the exit codes in `docs/cli-contract.md`.

## Producing records

```bash
arer scan /mail/drop --alerts /alerts
# one <alert_id>.alert.json per alert-level email; --raw keeps IOCs un-defanged
```

"Alert-worthy" follows the exit-code contract: `SUSPICIOUS`,
`LIKELY_PHISHING` and `MALICIOUS` (the `ALERT_EXITS` allowlist in
`arer.exitcodes`). `CLEAN` is not an alert, and `INSUFFICIENT_DATA` (exit 6)
is a no-decision, not an alert — no record is written for either.

### Record file names are the alert ID (R1.1)

Since the Phase 6 remediation, every record is written as
`<alert_id>.alert.json` — the immutable event ID, **not** the source file
name. The source name stays in the record as `source_file` metadata only.
This makes alert identity collision-proof: two different mails that arrive
under the same file name can never overwrite each other's record, and an old
disposition sidecar can never be inherited by a new message. Writes are
atomic (temp file + rename); an existing record is never silently replaced —
a same-ID/different-content collision preserves BOTH records and reports an
integrity error.

## The record

| field | meaning |
|-------|---------|
| `schema` | `"arer.alert.v1"`. Readers dispatch on this string. Never defanged. |
| `alert_id` | uuid4 hex, identifies one alert event (one scan of one e-mail). Two rescans of the same mail produce different ids; the mail itself is identified by `verdict.sha256`. |
| `generated_utc` | when the alert was built, ISO-8601 UTC with `Z` suffix. |
| `source_file` | file name the e-mail was scanned from. Defanged — mail-drop file names can be attacker-crafted. |
| `logic_hash` | 16-hex fingerprint of the analyzer code + word lists (see `docs/evaluations.md`). Lets you tell apart alerts produced by different rules versions. |
| `scan` | what the e-mail claims about itself: `from`, `message_id`, `date`. Attacker-controlled, defanged on output. |
| `verdict` | the full scan result: `sha256`, `subject`, `score`, `level`, `by_category`, `findings` (id, category, summary, evidence, weight, confidence, source), `overridden_by`, `analyzer_errors`. |

Every attacker-controlled string is defanged exactly like the scan report
(`hxxps://evil[.]com`, `user[@]host`, `1[.]2[.]3[.]4`), so records are safe to
paste into tickets and logs. Hex/ISO fields (`sha256`, `alert_id`,
`logic_hash`, `generated_utc`) contain no IOC patterns and pass through
unchanged.

## Reading records (Phase 6.1b)

```bash
arer alerts list /alerts            # newest first; --level MALICIOUS filters
arer alerts show /alerts <alert_id> # 6+ characters of the id; prints the record
```

Reading rules, frozen by `tests/test_alert_store.py`:

- Dispatch on the top-level `schema` marker, never on the file name. An
  unknown schema is an explicit error ("unsupported schema 'arer.alert.v99'"),
  never a silent mis-read.
- Unknown extra keys are ignored, so a record written by a newer arer still
  reads (the forward-compatibility rule above).
- Validation errors always name the file and the bad field(s)
  (`x.alert.json: invalid arer.alert.v1 record (bad field(s): verdict.score)`),
  so one corrupt record in a folder of thousands is one line on stderr.
- One bad file never stops a batch: `arer alerts list` lists the good records
  and exits 1, exactly like `arer parse` handles unreadable mail. Empty or
  missing folder: no records, no crash.
- Library use: `read_alert(path)` (raises `AlertError`) and
  `read_alerts(dir)` -> `list[AlertRead]` where `AlertRead` is
  `(path, alert | None, error | None)`, sorted by file name,
  `*.alert.json` only, symlinks skipped.

## Versioning rules

- Within a schema version, keys never move, shrink, or change type. Consumers
  may rely on the exact key set.
- Adding a field is allowed but deliberate: regenerate the golden
  (`UPDATE_GOLDEN=1 uv run pytest tests/test_alert.py`), commit it, and extend
  this page. Additions must be optional for readers (unknown keys ignored).
- Any incompatible change mints a new marker (`arer.alert.v2`) and a second
  golden file; producers may emit both during a transition.
- A finding id appearing in `verdict.findings` is additionally frozen by
  `tests/test_frozen_findings.py` / `docs/finding-ids.md`.
