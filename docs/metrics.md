# Queue metrics (Phase 6.6)

`arer alerts stats DIR` answers the analyst's operational questions from the
Phase 6 records alone - the alert records (6.1) and their disposition
sidecars (6.2). It is a read-side view: no new schema, nothing is written,
no detection is involved.

```console
$ arer alerts stats /alerts
records        42 valid
campaigns      17 distinct mails (exact sha256)
by verdict     MALICIOUS 12, LIKELY_PHISHING 21, SUSPICIOUS 9
dispositions   10 new, 8 acknowledged, 9 benign, 15 phishing
decided        24 of 42 (benign 9, false-alarm share 38%)
response time median 1.4h from record to disposition
backlog       oldest unresolved record is 3.2d old
top senders   news[@]discord[.]com 12, hr[@]corp-example[.]com 5
```

## Definitions (frozen)

| line           | meaning                                                                     |
|----------------|-----------------------------------------------------------------------------|
| `records`      | valid alert records in the folder; broken ones are excluded and named       |
| `campaigns`    | distinct mails, by exact `sha256` (the 6.4 view)                            |
| `by verdict`   | records per verdict level, most severe first                                |
| `dispositions` | records per status; no sidecar = `new` (the backlog)                        |
| `decided`      | `benign + phishing` records. `acknowledged` is work queued, **not** a decision, so it does not count towards the false-alarm share |
| `false-alarm share` | `benign / decided`, rounded to a whole percent                         |
| `response time` | median of `set_utc - generated_utc` over records that have a sidecar (robust against one slow outlier); clock skew clamps to 0 |
| `backlog`      | age of the oldest record with no disposition, measured from now             |
| `top senders`  | the 5 senders with the most records (senders are defanged in the records, so they are safe to show) |

## Discipline (inherited from 6.1b/6.2/6.4)

- A broken alert record or corrupt sidecar is excluded from **every**
  number, named on stderr, and makes the command exit 1 - a metric computed
  over a silently incomplete queue would lie. Fix or remove the broken file
  and re-run; the count of excluded records is shown.
- An empty folder prints `no alert records in DIR` and exits 0.
- The alert records and sidecars are never modified.

## Scope

v1 is text-only, over one queue folder. Machine-readable flattening for
SIEM/SOAR already exists (`alerts export`, Phase 6.3); when a dashboard
needs more than `stats` prints, that is where the raw data comes from.
