# The alert record: `arer.alert.v1`

Phase 6.1a. Every alert-worthy e-mail gets a stable, versioned JSON record —
the file Phase 6.2 dispositions, Phase 6.3 export and any external tooling
(SOAR, SIEM, mail-drop watchers) read. Its shape is frozen by
`tests/test_alert.py` and `tests/golden/alert_v1.json`; changing the record is
a contract change like the exit codes in `docs/cli-contract.md`.

## Producing records

```bash
arer scan /mail/drop --alerts /alerts
# one <name>.alert.json per alert-level email; --raw keeps IOCs un-defanged
```

"Alert-worthy" follows the exit-code contract: `SUSPICIOUS`,
`LIKELY_PHISHING` and `MALICIOUS` (the `exit >= 3` levels). `CLEAN` is not an
alert, and `INSUFFICIENT_DATA` (exit 6) is a no-decision, not an alert — no
record is written for either.

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
