# Arer — Explainable AI for Phishing Email Detection

### A privacy-conscious, evidence-driven email security tool built around static analysis and configurable risk scoring.

Arer is a local-first phishing email triage engine that analyzes `.eml`, `.msg`, and JSON email data using independent security analyzers, local threat-intelligence blocklists, and configurable scoring rules. Each verdict includes traceable findings and supporting evidence, so a scan can be reviewed instead of treated as a black-box decision.

**Current phase:** Rule-based detection, evidence-backed scoring, local threat intelligence, private labeled history, and a repeatable evaluation harness.

**Future work:** Machine learning and Explainable AI (XAI). The XAI layer is planned and is not implemented in the current phase.

> Full command reference: **[USAGE.md](USAGE.md)**

---

## Highlights

- **Eight independent analyzers** (authentication, sender, headers, links, attachments, message text, blocklists, personal history). Each returns *findings*; none of them sets its own score.
- **Explainable by construction.** Every point in a verdict traces back to a named finding with its evidence. Weights, caps, thresholds and word lists live in config files, not code.
- **Offline blocklists.** About 1.2 million phishing domains and URLs from public feeds, held in a 27 MB hash index. Lookups take microseconds and add no measurable scan time.
- **A private, labeled history.** Label an email once and later mail from the same sender, links or attachments is judged by what you decided. Only *your* labels teach it.
- **A measurement harness.** `arer eval` reports detection and false alarms with confidence ranges, per-source breakdowns, an 80/20 dev/test split, and which findings help or hurt.
- **Hostile-input design.** Size limits, per-analyzer timeouts, defanged output, terminal-escape filtering, and no network except one explicit command.
- **About 190 automated tests**, including tests built from real bugs found while measuring.

## Example output

Abridged, with addresses redacted. URLs and IPs in real output are defanged (`hxxps://evil[.]com`).

```
$ arer scan data/samples/phish/sample-107.eml
Subject : YOUR $2.500,000.00
Verdict :  SUSPICIOUS   27/100

  body        15 / 25
  sender      12 / 30

Findings
  [+12] body.prize_lure
        Prize, lottery or giveaway scam language: charity donor, email address has won, has won you, kindly get back
  [+12] sender.reply_to_mismatch
        Replies go to a different mailbox than the sender
  [+3] body.generic_greeting
        Impersonal greeting: dear e mail owner
```

## How it works

```
 .eml / .msg / .json
        │
   loader ─────────── size limits, validation ──► Email object
        │
   pipeline ───────── runs every analyzer in parallel; one crash or timeout never stops the scan
        │
   analyzers ──────► findings (id, confidence, evidence)
        │              auth · sender · headers · urls · attachments · body
        │              intel (blocklists) · history (your labels)
        │
   scoring ────────── points = weight × confidence, each finding id counted once,
        │              per-category caps, level thresholds, forced-level overrides
        │
   report ─────────── defanged terminal output or JSON
```

**Scoring in one paragraph.** Each finding has a weight from `config/rules.yaml` and a confidence between 0 and 1. A finding id counts once per email. Points are summed per category and capped (so one noisy check cannot dominate), added up to 100, and mapped to `CLEAN`, `SUSPICIOUS` (20+), `LIKELY_PHISHING` (45+) or `MALICIOUS` (70+). A few findings force a minimum level regardless of score, for example a listed phishing URL or a known-bad attachment hash. An email with too little data to judge is reported as `INSUFFICIENT_DATA` instead of a false `CLEAN`.

## What it checks

| Analyzer | Examples |
|---|---|
| **auth** | SPF, DKIM and DMARC results read from the receiving server's `Authentication-Results`. Only the topmost stamp (or a server you name) is trusted, because anyone can forge the header inside the email. |
| **sender** | Malformed From, Reply-To pointing elsewhere (on Gmail, a different mailbox counts), display name faking an address or brand, lookalike and punycode domains, shared-hosting senders such as `onmicrosoft.com`. |
| **headers** | Missing Received chain, hop count, bulk-mailer tools, Message-ID and Return-Path oddities, malformed structure. Softer for newsletters and mailing lists. |
| **urls** | Static only: link text vs real target, IP and obfuscated hosts, `user@host` tricks, shorteners, abused TLDs, free hosting, lookalikes, brand-vs-link mismatch. Nothing is ever visited. |
| **attachments** | Executables, double extensions and right-to-left-override names, macro Office files, HTML/SVG, archives holding executables or encrypted, real file type vs claimed type, "see attached" with nothing attached. |
| **body** | Urgency and credential language, prize and lottery lures, callback scams (charge plus a phone number to call), forms asking for passwords, hidden text, dot-spaced subjects. Word lists cover English, French, Portuguese and Spanish, plus a little Arabic. |
| **intel** | Links, sender domain and attachment hashes against local blocklists. |
| **history** | Sender, link domains and hashes seen in phishing *you* labeled; first-time senders (weak, and silent until enough history exists). |

## Quick start

```bash
git clone https://github.com/abdou-4/Arer.git
cd arer
uv sync                                  # developed on Python 3.13

uv run arer scan path/to/mail.eml        # full report for one email
uv run arer scan path/to/folder -q       # one line per email
uv run arer feeds update                 # optional: download blocklists (about 15 s, the only network use)
uv run pytest                            # run the test suite
```

Main commands (details and every option in [USAGE.md](USAGE.md)):

| Command | Purpose |
|---|---|
| `arer parse` | Convert `.eml`/`.msg` into JSON. |
| `arer scan` | Parse, analyze and print a verdict. Accepts files or folders. |
| `arer eval` | Measure detection and false alarms on labeled samples. |
| `arer label` / `arer history` | Label emails and manage your private history. |
| `arer feeds` | Download and inspect the blocklists. |

Exit codes make it scriptable: `scan` returns 2 when anything is `LIKELY_PHISHING` or `MALICIOUS`.

## Configuration

Everything tunable is plain text in `config/`, with no code changes needed.

| File | Controls |
|---|---|
| `rules.yaml` | Weights, per-category caps, level thresholds, forced-level overrides, limits. A typo stops the program with a clear error instead of silently scoring wrong. |
| `feeds.yaml` | Which blocklists to download and their safety limits. |
| `history.yaml` | Where your history lives, auto-save, cold-start threshold. |
| `lists/*.txt` | Brands, legitimate domains, shared-hosting domains, mail platforms, TLDs, shorteners, urgency, credential, lure and greeting phrases. |

## Project structure

```
config/                 rules.yaml, feeds.yaml, history.yaml, lists/*.txt
scripts/
  mbox_to_eml.py        sample your own mailbox into .eml test files
src/arer/
  cli.py                parse | scan | eval | label | history | feeds
  mail_parser.py        .eml/.msg to JSON (mail-parser based)
  loader.py             validated Email objects, size limits
  models.py             Email, Finding, Verdict
  config.py             loads and validates all configuration
  pipeline.py           runs analyzers safely and in parallel
  scoring.py            findings to score, level and overrides
  report.py             defanged terminal and JSON output
  evaluate.py           the measurement harness
  analyzers/            auth, sender, headers, urls, attachments, body, intel, history
  util/                 domains, HTML reading, file sniffing, defanging
  intel/                blocklist index and updater
  history/              private labeled history
  ai/                   (planned)
tests/
data/                   git-ignored: samples, feeds, history.db
```

## Security and privacy design

Treating every input as hostile was a design requirement from the start.

- **Static analysis only.** Attachments are hashed and their first bytes inspected; zip files are only listed. Links are never visited. HTML is parsed, never rendered.
- **Bounded work.** Limits on file size, parts, URLs and HTML tags; a per-analyzer timeout; a crashing analyzer is recorded in the verdict and the scan continues. (Python threads cannot be killed, so a truly stuck analyzer lingers until exit. Subprocess isolation is on the roadmap.)
- **Safe output.** URLs, IPs, domains and addresses are defanged; control characters, ANSI escapes and bidirectional-override characters are made visible instead of interpreted.
- **One network path.** Only `arer feeds update` touches the network: HTTPS only, hard size cap, redirects allowed only to the same host, an update that would shrink a feed below half its size is refused, and each feed is replaced in a single atomic transaction. Domain parsing uses a bundled public-suffix snapshot, so no list is downloaded at scan time.
- **Private history.** It stores hashes, dates, sender domain, verdicts and findings. It never stores bodies, subjects, recipients or attachments, and sender addresses are hashed. Files are created with owner-only permissions.
- **No self-reinforcement.** The tool never learns from its own verdicts, only from labels you set.
- **No unsafe deserialization.** Configuration uses `yaml.safe_load`; there are no pickled models.

## Evaluation

The latest evaluation run contains **1,350 emails**: 690 samples from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) and 660 legitimate emails from a modern personal-mail sample (`legit/mine_modern` in the report).

Phishing Pot is a community-collected phishing feed, and its samples can include spam or other unwanted messages that are not necessarily credential theft or malicious phishing. The evaluation should therefore be read as a test against the available labeled corpus, not as a perfect ground-truth measure of real-world phishing. During manual follow-up, some messages missed by Arer were also not flagged as phishing by commercial `.eml` analyzers. This is useful comparative context, but it does not independently establish that those messages are benign or that the tools are equivalent.

### Results at the current verdict thresholds

| Verdict threshold | Phishing samples flagged | Legitimate emails flagged | Observed precision within this labeled test |
|---|---:|---:|---:|
| `SUSPICIOUS` (20+) | 507 / 690 (73.5%) | 0 / 660 (0.0%) | 100% |
| `LIKELY_PHISHING` (45+) | 31 / 690 (4.5%) | 0 / 660 (0.0%) | 100% |
| `MALICIOUS` (70+) | 3 / 690 (0.4%) | 0 / 660 (0.0%) | 100% |

At the current `SUSPICIOUS` threshold, Arer flags 507 of the 690 samples labeled phishing and leaves 183 below the threshold. No legitimate emails were flagged in this run. The report's 95% range for the legitimate-mail flag rate is approximately 0–1%, so zero observed false positives does **not** establish a zero real-world false-positive rate.

The higher-threshold rows describe how many phishing-labeled samples reached each verdict level; they are not separate model configurations.

### Why the current threshold is 20

The score sweep shows a clear trade-off between catching more phishing-labeled samples and generating false alarms on legitimate mail:

| Minimum score | Phishing samples caught | Legitimate emails flagged |
|---:|---:|---:|
| 5 | 94.8% | 32.4% |
| 10 | 88.0% | 13.8% |
| 15 | 80.0% | 0.3% |
| **20 (current `SUSPICIOUS`)** | **73.5%** | **0.0%** |
| 25 | 64.2% | 0.0% |
| 30 | 50.4% | 0.0% |
| 35 | 45.7% | 0.0% |
| 40 | 17.4% | 0.0% |

**Threshold 20 is the current operating point because it prioritizes avoiding false alarms on legitimate email while retaining useful detection coverage.** In this run, lowering the threshold to 15 increases coverage by 6.5 percentage points, but introduces a measured false-alarm rate of 0.3%; lowering it to 10 raises detection to 88.0% while flagging 13.8% of the legitimate set. At threshold 5, almost one-third of the legitimate set is flagged. Threshold 20 is therefore a deliberate precision-oriented choice for this rule-based phase, not a claim that 20 is universally optimal.

These numbers depend on the composition and labels of the available corpus. Because some Phishing Pot messages may be spam rather than phishing, the measured detection rate is best described as coverage of the phishing-labeled samples in this evaluation, not a definitive estimate of real-world phishing recall.

### What the findings show

The report identifies signals that are useful on this sample and others that are noisy:

- `auth.dmarc_no_policy` fired on 467 / 690 phishing-labeled samples and none of the legitimate emails in this run.
- `sender.shared_domain` fired on 339 / 690 phishing-labeled samples and none of the legitimate emails in this run.
- `body.hidden_text` fired on 458 / 690 phishing-labeled samples, but also on 428 / 660 legitimate emails. It needs context and should not be treated as a decisive signal by itself.
- `headers.returnpath_mismatch` and `headers.msgid_domain_mismatch` also fired frequently on legitimate mail in this evaluation, so their contribution needs to be considered in combination with other evidence.

These are observed firing frequencies, not proof that any individual finding causes a correct or incorrect verdict. Findings interact through weights, confidence values, and category caps.

### Interpretation and next phase

The current results reflect extensive rule tuning within the signals available to a static, rule-based detector. Repeated tuning has kept detection in roughly the 70–75% range at the current conservative operating point. Further weight changes may move the trade-off, but they can also increase false alarms without addressing patterns the current rules do not represent.

The next planned research phase is the machine-learning and Explainable AI (XAI) work. It will be evaluated against the current rule-based baseline to determine whether it improves detection and how its predictions can be interpreted. XAI is planned work and is not part of the current implementation.

The blocklist stage was separately checked against live feeds: 500 of 500 randomly selected listed URLs were detected with the HTTP/HTTPS scheme flipped, and 301 well-known domains in four URL shapes each produced no false positives. These are separate blocklist checks, not additional phishing-detection results from the 1,350-email evaluation above.

## Engineering notes

Things measuring taught me, each fixed and covered by a test:

- **Tuning on old mail cost real detections.** Softening a check because 2002-era ham tripped it lost 4 modern phishing detections and gained nothing on modern mail. Reverted; old archives are now a separate stress-test source.
- **Testing against the live feed found false positives that test feeds hid.** The real feed lists `https://www.amazon.com/` and `bit.ly`. The first design would have marked any mail linking to Amazon as `MALICIOUS`. Root pages of protected sites are now ignored, and protected domains never match at domain level.
- **A domain is not an identity on free mail.** A Reply-To to a different Gmail mailbox looks "same domain". The check now compares the whole address for free-mail providers.
- **One bad sample overfit a rule.** A Message-ID check built from a single sample fired on 4 of 10 modern legitimate emails; its weight was cut.
- **Re-scoring is exact.** Saved scans keep findings, not points, so re-scoring from history matches scanning the files score for score.

## Limitations

- Small modern legitimate set, so false-alarm rates are not yet well estimated.
- Scams with no content signal (for example a lone cloud-storage link from a free-mail address) cannot be caught the first time. The history can catch the sender's next email once you label the first.
- No PDF, QR-code or image-text inspection, and no macro inspection in legacy `.doc`/`.xls`.
- Word lists cover a handful of languages and need curating.
- OpenPhish support is implemented but untested against the live feed, and is off by default (non-commercial use only). `.msg` input is untested.
- `parse --extract-attachments` writes real attachments to disk; use an isolated environment.

## Explainable AI layer

_To be added. This section will describe the XAI design, training data, evaluation and how its explanations are shown._

## Roadmap

- Explainable AI layer (above)
- PDF link extraction, QR-code and image-text analysis, legacy Office macro inspection
- HTML report, folder or mailbox watcher, local API
- Subprocess or container isolation for analyzers, tamper-evident audit log
- MISP or SIEM export
- Optional DNS and domain-age checks, off by default

## Data sources and credits

- Phishing samples: [Phishing Pot](https://github.com/rf-peixoto/phishing_pot)
- Blocklists: [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (MIT); OpenPhish community feed (optional, non-commercial)
- Email parsing: [mail-parser](https://github.com/SpamScope/mail-parser)

## License

See [LICENSE](LICENSE).
