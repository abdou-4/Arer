# Campaigns: one row per distinct mail (Phase 6.4)

The same mail often alerts many times: one phishing run arrives as five
copies and lands as five records in the queue. `alerts campaigns` groups the
queue by the mail's **exact sha256** so the analyst sees one row per distinct
mail - how many times it alerted, when it was first/last seen, and the
combined disposition - instead of five identical rows.

**v1 groups by exact hash only.** Mails that merely look similar stay
separate campaigns; fuzzy clustering is deliberately out of scope. When it
arrives later it will be a separate, additive view - it never changes what
`arer.alert.v1` records (docs/alert-record.md) or how dispositions are read.

```console
$ arer alerts campaigns /alerts
sha256         seen  level              score  first                last                 from                      status
a640cdf35b1e      5  MALICIOUS             92  2026-11-17T08:14:02Z 2026-11-17T11:40:19Z news[@]discord[.]com      mixed
71e0a2bb9d4f      1  LIKELY_PHISHING       74  2026-11-17T09:02:51Z 2026-11-17T09:02:51Z hr[@]corp-example[.]com   new
```

Columns:

| column   | meaning                                                                    |
|----------|---------------------------------------------------------------------------|
| `sha256` | first 12 hex characters of the mail's hash (copy it for `set-group`)       |
| `seen`   | how many alert records in the folder carry this hash                       |
| `level`  | the most severe verdict among the group's records                          |
| `score`  | the highest score among the group's records                                |
| `first`  | generated_utc of the oldest record (first sighting)                        |
| `last`   | generated_utc of the newest record (latest sighting)                       |
| `from`   | sender of the newest record (defanged, like every report)                  |
| `status` | combined disposition, see below                                            |

Campaigns are sorted by most recent activity (newest sighting first), so the
freshest run is on top.

## Combined status

Each record has its own disposition sidecar (docs/dispositions.md); the
campaign shows the group's combined answer:

| members' dispositions                | row shows      |
|--------------------------------------|----------------|
| all `new` (no sidecar anywhere)      | `new`          |
| all `acknowledged`                   | `acknowledged` |
| all `benign`                         | `benign`       |
| all `phishing`                       | `phishing`     |
| any disagreement                     | `mixed`        |

The vocabulary of the combined status is frozen: `new | acknowledged |
benign | phishing | mixed`. Filtering follows the same words:

```console
$ arer alerts campaigns /alerts --status new          # runs nobody has looked at
$ arer alerts campaigns /alerts --status mixed        # groups with a pending decision
$ arer alerts campaigns /alerts --status phishing     # confirmed campaigns
$ arer alerts campaigns /alerts --level MALICIOUS     # only the most severe groups
```

## One decision for the whole group

The companion command records the analyst's answer for every record of the
same mail in one step:

```console
$ arer alerts set-group /alerts a640cdf35b1e phishing --note "real run, blocked sender"
a640cdf35b1e  5 alert(s) marked phishing  (real run, blocked sender)
```

- `SHA256` accepts 6 or more hex characters (case-insensitive) and must match
  exactly one campaign; copy it from `alerts campaigns`.
- Each member gets/overwrites its own `<name>.disposition.json` sidecar with
  the chosen status and note - exactly what repeated `alerts set` calls would
  write, so per-record history rules stay intact (re-set any single record
  afterwards without affecting the others).
- The alert records themselves are never modified, as everywhere in Phase 6.

## Reading rules (inherited from 6.1b/6.2)

- Broken alert records are named on stderr and never join a group; the
  command still lists the valid campaigns and exits 1 (`N campaign(s),
  M unreadable`).
- A corrupt sidecar does not hide its group: the group is shown **without**
  that member (`seen` counts only readable members), the file is named, and
  the command exits 1. Fix or delete the broken sidecar and re-run; note that
  `alerts set-group` overwrites a corrupt sidecar, so it doubles as the fix.
- An empty folder prints `no alert records in DIRECTORY` and exits 0.

## Files

`campaigns` reads only; `set-group` writes only disposition sidecars:

    salad.eml.alert.json          alert record (never touched by campaigns)
    salad.eml.disposition.json    sidecar written by set/set-group

No new schema is introduced in Phase 6.4: campaigns are a view over the two
existing records.
