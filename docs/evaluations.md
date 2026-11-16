# Evaluation datasets: manifest and baseline records

Every measurement Arer reports must be reproducible: same samples, same
groups, same logic version. Two things make that possible — a per-dataset
`manifest.csv` (campaign groups and provenance) and recorded baseline runs.

The dataset itself stays local (see `.gitignore`: `/data/samples/*` is not
committed). Only this template and your written records land in git.

---

## 1. `manifest.csv` — campaign groups and provenance

Create one `manifest.csv` at the **root of your dataset folder** (the folder
you pass to `arer eval`, next to the `phish/` and `legit/` folders):

```console
cp docs/manifest-template.csv /path/to/dataset/manifest.csv
```

Columns:

| column           | required | meaning                                                                                     |
|------------------|----------|---------------------------------------------------------------------------------------------|
| `path`           | yes      | relative path of one mail sample, `/`-separated, no `..`. Must match a real file under the dataset root. |
| `group_id`       | no       | campaign identifier. Samples sharing a `group_id` always land in the same dev/test split — the split never separates members of one campaign. |
| `dataset`        | no       | short dataset name (shown in the report's "Dataset provenance" section).                     |
| `license`        | no       | license of the source dataset, if you did not create the samples yourself.                   |
| `reference`      | no       | where the samples came from (paper, corpus, mailbox).                                        |
| `collection_date`| no       | when the samples were collected. Old mail is a stress test, not modern evidence.            |

Rules for `group_id`:

- Fill it in whenever you know several samples belong to one campaign
  (same template, same sender, same link pattern arrived repeatedly).
- Samples without a `group_id` keep the default content-hash split; nothing
  is lost by leaving it empty, only grouping is less faithful.
- Never guess. If you are unsure whether two mails are the same campaign,
  leave both empty.

The manifest is validated fail-closed: an unknown path, a duplicate path, a
path outside the dataset root, or a broken encoding makes `arer eval` stop
with an error instead of silently skipping rows.

---

## 2. Recording a baseline run

The rule-based baseline is the number Phase 7 (text ML) has to beat, so each
run is written down with the logic version that produced it. `arer eval`
prints the `logic_hash` in its first lines — that fingerprint of analyzer
code and word lists is what ties a record to a run.

Procedure (from the roadmap prerequisites):

1. Tune on the dev split as often as you like:

   ```console
   arer eval data/samples --only dev
   ```

2. Then run the held-out test split **once** and save the output:

   ```console
   arer eval data/samples --only test | tee docs/evaluations/2026-11-16-rules-baseline.txt
   ```

3. Write a short record next to the saved output:

```markdown
### 2026-11-16 — rules baseline (test split)
- logic_hash: 1102f7527247c806
- config: main branch, no weights changed since commit <sha>
- dataset: data/samples, manifest.csv with N campaign groups
- samples: X phishing / Y legitimate (Z campaign-grouped)
- result at LIKELY_PHISHING: caught A/X [95% range], legit flagged B/Y, precision P
- notable misses / false alarms: <finding IDs and file names>
```

One record per meaningful change: new rules, weight changes, or a new
dataset revision. If `logic_hash` changed, the old records stay as they are
— never overwrite a recorded run.

`arer eval --from-history` re-scores saved scans with today's rules and
warns when stored scans are stale; it is convenient for a quick check, but
a baseline record should always come from the real files.
