# arer: usage

Local phishing triage. Nothing leaves your machine, and nothing inside an email is ever opened, run or fetched.

## Setup

```bash
uv add pydantic pyyaml click tldextract rapidfuzz     # once (HTML and zip reading use the standard library)
uv add --dev pytest
```

`pyproject.toml` must expose the command (it already does if `uv run arer` worked before):

```toml
[project.scripts]
arer = "arer.cli:main"
```

## The commands

```bash
arer parse <file-or-folder>     # .eml/.msg  ->  JSON files        (your original tool)
arer scan  <file-or-folder>...  # .eml/.msg/.json  ->  verdict     (parse + analyze in one step)
arer eval  [data/samples]       # score ALL labeled samples, report detection and false alarms
```

`scan` parses in memory, so for daily use you only need `scan`. Use `parse` when you want the JSON on disk.

### Everyday examples

```bash
arer scan data/samples/phish/phish_sample.eml        # full report for one email
arer scan data/samples/phish                         # every .eml/.msg in a folder (your phish samples)
arer scan data/samples/phish -q                      # one line per email
arer scan output/sample-1.eml.json             # scan already-parsed JSON
arer scan data/samples/phish --out reports           # also save one report per email
arer scan mail.eml --json report.json          # save the report for one email
arer scan data/samples/phish -r                      # include sub-folders
```

### `scan` options

| Option | What it does |
|---|---|
| `-q`, `--quiet` | One line per email: level, score, name. |
| `-r`, `--recursive` | Search sub-folders too. |
| `--out DIR` | Save `<name>.report.json` for every email. |
| `--json FILE` | Save the report for a single email. |
| `--raw` | Keep real URLs and IPs in saved JSON. By default they are defanged. |
| `--skip NAME` | Turn off an analyzer, for example `--skip demo`. Repeatable. |
| `--trust TEXT` | Your own mail server's name, so the parser can find `sender_ip`. |
| `--config DIR` | Use a different config folder. |
| `-v` (before the command) | Debug logging: `arer -v scan x.eml`. |

### `parse` options (unchanged from the old CLI)

| Option | What it does |
|---|---|
| `-o`, `--output DIR` | Where JSON goes (default `output`). `mail.eml` becomes `mail.eml.json`. |
| `-r`, `--recursive` | Search sub-folders. |
| `--trust TEXT` | Trusted server string for `sender_ip`. |
| `--include-payload` | Embed attachment content (base64) in the JSON. |
| `--extract-attachments` | Write attachments to `<output>/attachments/`. This puts real malware on disk, so use a VM or sandbox. |
| `--full` | Add mail-parser's own `mail` and `mail_partial` views. |
| `--compact` | Single-line JSON. |

## Reading a result

```
Verdict :  SUSPICIOUS  27/100
  sender      12 / 30        <- points in this category / its cap
Findings
  [+12] sender.reply_to_mismatch     <- points, then finding id
        Reply-To domain evil[.]example differs from ...
```

| Level | Meaning |
|---|---|
| `CLEAN` | Nothing significant found. Not proof of safety. |
| `SUSPICIOUS` | Worth a look. |
| `LIKELY_PHISHING` | Treat as phishing unless proven otherwise. |
| `MALICIOUS` | Strong evidence, or a decisive finding such as a blocklisted URL. |
| `INSUFFICIENT_DATA` | Too little to judge (stripped headers or an empty message). |

`Level forced by: ...` means an override in `rules.yaml` raised the level regardless of score.
`Analyzer problems` means a check crashed or timed out, so the result may be incomplete.

### Exit codes (for scripts)

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `scan` | all CLEAN, SUSPICIOUS or INSUFFICIENT_DATA | a file could not be processed | at least one LIKELY_PHISHING or MALICIOUS |
| `parse` | all parsed | some files failed | input path missing |

```bash
arer scan data/samples/phish -q || echo "phishing found or error"
```

## Measuring: `arer eval`

Tuning weights by feel does not work. `arer eval` scores every sample and tells you what the numbers are.

```bash
arer eval                      # everything under data/samples
arer eval --details            # also list every sample with its score
arer eval --skip-dir archive   # ignore folders named 'archive' (old mail kept only as a stress test)
arer eval --only dev           # tune on 80% of samples ...
arer eval --only test          # ... and check on the other 20% now and then
arer eval --skip body          # what happens if an analyzer is turned off?
arer eval --config /tmp/cfg    # try a copy of config/ with different weights
```

Labels come from folders: files under `phish/` are phishing, files under `legit/` are legitimate. To override one file, add `data/samples/labels.csv`:

```
filename,label
sample-9.eml,legit
```

What it shows:

| Section | Use it to |
|---|---|
| Detection by level | How many phishing emails reach SUSPICIOUS / LIKELY_PHISHING / MALICIOUS and how many legit emails are wrongly flagged at each level. Each rate has a 95% range in brackets. With 10 legit emails, 0 false alarms still allows about 28%, so do not read 0/10 as "solved". 60 emails brings the ceiling to about 6%, 100 to about 4%. |
| By source | The same numbers per folder (`legit/modern`, `legit/archive`, `phish`), so you can judge false alarms on modern mail without separate runs. |
| Phishing MISSED / Legit FLAGGED | Open the exact emails that need work. |
| Score sweep | Pick thresholds: choose the T that catches the most phishing before legit mail starts getting flagged. |
| Findings table | See which findings help (fire on phishing) and which are noisy (marked `<- noisy`, fire on legit mail). Lower the weight of noisy ones in `rules.yaml`. |

The workflow: run `arer eval`, change one thing in `rules.yaml` or a list, run it again, and keep the change only if detection went up without more false alarms. Below about 30 samples per class the numbers are only a rough guide. Public sets (Phishing Pot, SpamAssassin) are in the earlier notes.

## Building a trustworthy test set

`arer eval` is only as honest as its samples. Four traps to avoid:

1. **Spam is not legitimate mail, and spam is not phishing.** From the SpamAssassin corpus use only `easy_ham`, `easy_ham_2` and `hard_ham` as `legit/`. Put the `spam` folders in `data/samples/spam/`. Eval ignores that folder.
2. **Era bias.** SpamAssassin mail is from 2002-2003 and has no SPF/DKIM/DMARC results, while modern phishing has them. Findings like `auth.results_missing` then separate your classes by *year*, not by phishing. The fix is modern legitimate mail (next section). Until you have it, compare with `arer eval --skip auth --skip headers` to see the content checks without era effects.
3. **Near-duplicates.** Consecutive Phishing Pot numbers are often the same campaign. 100 samples may be 30 campaigns, so one fix can move many samples, and the dev/test split can leak. Judge by campaigns, not by counts.
4. **Too little modern legit mail.** Aim for 40 or more of your own recent emails, including newsletters, receipts, notifications and mailing lists.

### Suggested folder layout

```
data/samples/phish/            Phishing Pot samples
data/samples/legit/modern/     your own recent mail  <- the numbers that matter
data/samples/legit/archive/    SpamAssassin ham: old and anonymised, stress test only
data/samples/spam/             ignored
```

Old SpamAssassin mail contains `user@localhost` addresses, no authentication results and plain-HTTP links. Those are artefacts of the corpus and the year, so do not tune on them.

### Getting your own legitimate mail

```bash
# 1. Gmail: takeout.google.com -> deselect all -> Mail -> only the Inbox label -> export (an .mbox file)
# 2. Sample it:
python scripts/mbox_to_eml.py "Inbox.mbox" -o data/samples/legit/modern --count 60 --prefix mine
```

It picks random Inbox messages, skips Spam, Trash, Drafts and Sent (sent mail has no receiving-server stamp), writes `mine_0001.eml` and so on, and never exports the same message twice, so you can run it again to add more. Your real mail is private: add `data/samples/legit/mine_*` to `.gitignore`.

### The workflow that keeps tuning honest

```bash
uv run arer eval > docs/eval-baseline.txt     # 1. record where you are
# 2. change ONE thing (a weight, a list entry, a rule)
uv run arer eval > docs/eval-after.txt        # 3. run it again
diff docs/eval-baseline.txt docs/eval-after.txt
```

Keep a change only if detection rose without more false alarms. Tune against `--only dev`, and look at `--only test` only now and then. `scan` and `eval` also read mail files without an `.eml` extension, such as `00001.7c53...`, if the first line looks like a mail header.

## Tuning: `config/rules.yaml`

Everything adjustable is here. No code changes are needed.

| Section | Purpose |
|---|---|
| `weights` | Points per finding id (`auth.dmarc_fail: 10`). |
| `caps` | Maximum points one category can add. |
| `thresholds` | Score cutoffs for SUSPICIOUS, LIKELY_PHISHING and MALICIOUS. |
| `overrides` | Findings that force a minimum level. |
| `limits` | Maximum file sizes and analyzer timeout. |
| `auth` | Which mail server's Authentication-Results to believe (see below). |

A typo in this file stops the program with a clear error instead of silently scoring wrong.

## Lists: `config/lists/*.txt`

One entry per line, lowercase, `#` for comments. Put the source and date at the top of each file.

| File | Used for | Maintain by |
|---|---|---|
| `brands.txt` | Display-name spoofing and lookalike domains | One lowercase word per brand. Add brands impersonated in your region and organization. Avoid generic words ("outlook") because they cause false alarms. |
| `shared_domains.txt` | Domains where anyone can register a free name (`onmicrosoft.com`, `pages.dev`, `github.io`...) | Add more as you see them abused. |
| `mail_platforms.txt` | Big mail platforms (Google, Microsoft, Amazon SES, Mailchimp...) whose Message-ID and Return-Path are normal | Add senders' ESPs when you see false mismatches. |
| `callback_words.txt` | Phrases for the callback-scam check. It needs a phone number AND an amount AND one of these | Add phrases in your languages. |
| `urgency_words.txt`, `credential_words.txt`, `generic_greetings.txt` | Phrase lists for the body check (accents and punctuation ignored) | Add phrases in your languages. Inflected forms need their own line (`expira hoje`, `expiram hoje`). |
| `legit_domains.txt` | Exempts known-good domains from brand and lookalike checks | Add your own company domain, bank and providers. **When a legit email gets flagged, fix it here first.** |
| `suspicious_tlds.txt` | Links on heavily abused TLDs | Refresh from Spamhaus or Interisle reports. |
| `executable_ext.txt` | Dangerous attachment types | Start from Microsoft's blocked-attachments list. |
| `macro_ext.txt`, `archive_ext.txt` | Macro-capable Office files and archives | Rarely changes. |
| `shorteners.txt` | Hidden link destinations | Community lists on GitHub. |
| `free_mail.txt` | A "bank" writing from gmail.com | Community freemail lists. |
| `bad_mailers.txt` | Mass-mailer tools in `X-Mailer` | Build from your own phishing samples. Weakest list. |

## What the checks look at

| Analyzer | Finds |
|---|---|
| `auth` | SPF fail/softfail, DKIM fail or unsigned, DMARC fail or no policy, or no auth results at all. |
| `sender` | Malformed From, Reply-To pointing elsewhere, display name showing a different address or claiming a brand, free-mail claiming a brand, lookalike domains (`paypa1-secure.com`), punycode domains, senders on shared domains such as `onmicrosoft.com`, and free-mail addresses (Gmail etc.) with an official-sounding name like "Security Team" or a brand like "Geek Squad". |
| `headers` | Missing Received headers, more than 8 hops, bulk-mailer tools in X-Mailer, odd Message-ID or Return-Path domains, missing Date, malformed structure. |

| `urls` | Static link checks only (nothing is ever fetched): link text vs real destination, bare/obfuscated IP hosts, `user@host` tricks, shorteners, abused TLDs, free-hosting domains, lookalikes and brand-as-subdomain, login keywords, plain HTTP, and **message talks about a brand but every link goes to an unrelated domain**. |
| `attachments` | A message that says "see attached" but has no attachment, executables and scripts, double extensions and right-to-left-override names, macro Office files (also detects `vbaProject.bin` inside a renamed file), HTML/SVG attachments, zips holding executables or password-protected, and files whose real bytes contradict their name (a `.pdf` that is really a program). Content is never opened or run; zips are only listed. |
| `body` | Callback scams (a charge you "did not authorize" plus a phone number to call, no links needed), pressure language, requests for credentials/payment data, impersonal greetings (English, French, Portuguese, Spanish, a little Arabic), forms asking for passwords or card data, hidden or zero-width text, image-only messages. |

Some checks are deliberately softer for newsletters (mail with a List-Unsubscribe header), because legitimate bulk senders often use other domains. In the report, a finding's points are its weight multiplied by its confidence.

### Which Authentication-Results to trust

Anyone can forge an `Authentication-Results` line inside an email. Only the stamp added by your own receiving server is believable. By default `arer` trusts only the topmost one, which your server added last. To be stricter, name your server in `config/rules.yaml`:

```yaml
auth:
  trusted_authserv_ids: ["mx.google.com"]    # Gmail. Microsoft stamps have no server name, so leave it empty.
```

If a server is named but no matching stamp exists, the result is `auth.results_missing` instead of a forged "pass". `temperror` and `permerror` mean "could not check" and are not counted as failures.

## Adding a check

Create `src/arer/analyzers/<name>.py`. It is picked up automatically.

```python
from ..models import Email
from .base import Analyzer, register

@register
class Example(Analyzer):
    name = "example"
    def run(self, email: Email, cfg):
        out = []
        if email.hop_count > 8:
            out.append(self.finding("headers.high_hop_count",
                                    f"{email.hop_count} hops", hops=email.hop_count))
        return out
```

Then make sure the finding id has a weight in `rules.yaml`. Keep one check per signal, because two analyzers reporting the same thing would double-count it.

## Safety notes

- Output is defanged (`hxxps://evil[.]com`) and stripped of terminal escape codes and right-to-left override characters.
- Attachments are hashed and read for their first 16 bytes only. They are never opened or executed.
- No network access during `scan`.
- Do not paste real IOCs from raw reports into chat tools or clickable ticket fields.

## Tests

```bash
uv run pytest
```

## Troubleshooting

| Message | Fix |
|---|---|
| `rules.yaml not found` | Run from the project root, or set `PHISHSCOPE_CONFIG=/path/to/config`. |
| `parser failed (...)` | The file is malformed or not an email. Try `arer parse` on it and check the error. |
| Hundreds of `WARNING mailparser.core: ... 'calendar'` lines | Harmless calendar invites. They are now hidden unless you use `-v`. |
| `.msg` files fail | Install the extra: `uv add "mail-parser[outlook]"`. |
| `does not look like parser output` | You pointed `scan` at a JSON that is not from `arer parse` (a report, for example). |
| Legit email flagged as brand spoof or lookalike | Add its domain to `legit_domains.txt`. |
| `finding id ... has no weight` (warning) | A finding id is missing or misspelled in `rules.yaml`. |
| `INSUFFICIENT_DATA` on a real email | The sender or the whole body is missing from the parsed output. |
