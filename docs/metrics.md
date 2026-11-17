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

## Analyst feedback metrics (R7)

`alerts stats` also reports:

- **alerts per week** — alert CASES per ISO week (deduplicated by sha256);
  the separate `events` column counts every record. Five copies of one
  phishing run are one case and five events — never mixed.
- **noisy rules** — per finding ID: the false-alarm rate over CLASSIFIED
  cases containing the finding (analyst `benign` / `analyst `phishing``),
  the reviewed count and the unresolved count. DENOMINATORS ARE ANALYST
  DECISIONS ONLY: tool decisions, legacy v1 sidecars (legacy_unverified),
  imports and unreviewed records never enter a rate. A rate over fewer than
  5 reviewed cases is flagged `low-confidence`, never presented as proof.

Case class: a case counts as phishing if ANY of its records carries an
analyst `phishing` decision, else benign if any carries an analyst `benign`;
acknowledged-only cases are reviewed but unclassified and stay outside every
rate denominator.

## Markdown case summary (R7.3)

`alerts show DIR ALERT_ID --markdown` renders one durable, paste-ready
document: case id, verdict/score/categories, analysis completeness, top
reasons with points, evidence, indicators (defanged; `--raw` shows live
values), campaign membership with the linking-key evidence and the analyst
state, workflow + provenance, and the logic/config hashes. All untrusted
text (subject, sender, filename, note, evidence) is Markdown-escaped and
length-limited; no links are ever emitted; the summary lists the evidence
that affected the result and does not claim the rules prove intent.
