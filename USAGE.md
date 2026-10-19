# arer: usage

Local phishing triage. Nothing leaves your machine, and nothing inside an email is ever opened, run or fetched.

## Setup

```bash
uv add pydantic pyyaml click        # once
uv add --dev pytest
```

`pyproject.toml` must expose the command (it already does if `uv run arer` worked before):

```toml
[project.scripts]
arer = "arer.cli:main"
```

## The two commands

```bash
arer parse <file-or-folder>     # .eml/.msg  ->  JSON files        (your original tool)
arer scan  <file-or-folder>...  # .eml/.msg/.json  ->  verdict     (parse + analyze in one step)
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

## Tuning: `config/rules.yaml`

Everything adjustable is here. No code changes are needed.

| Section | Purpose |
|---|---|
| `weights` | Points per finding id (`auth.dmarc_fail: 10`). |
| `caps` | Maximum points one category can add. |
| `thresholds` | Score cutoffs for SUSPICIOUS, LIKELY_PHISHING and MALICIOUS. |
| `overrides` | Findings that force a minimum level. |
| `limits` | Maximum file sizes and analyzer timeout. |

A typo in this file stops the program with a clear error instead of silently scoring wrong.

## Lists: `config/lists/*.txt`

One entry per line, lowercase, `#` for comments. Put the source and date at the top of each file.

| File | Used for | Maintain by |
|---|---|---|
| `brands.txt` | Display-name spoofing and lookalike domains | Add brands impersonated in your region and organization. Most important list. |
| `suspicious_tlds.txt` | Links on heavily abused TLDs | Refresh from Spamhaus or Interisle reports. |
| `executable_ext.txt` | Dangerous attachment types | Start from Microsoft's blocked-attachments list. |
| `macro_ext.txt`, `archive_ext.txt` | Macro-capable Office files and archives | Rarely changes. |
| `shorteners.txt` | Hidden link destinations | Community lists on GitHub. |
| `free_mail.txt` | A "bank" writing from gmail.com | Community freemail lists. |
| `bad_mailers.txt` | Mass-mailer tools in `X-Mailer` | Build from your own phishing samples. Weakest list. |

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

Then make sure the finding id has a weight in `rules.yaml`. When you write real `auth.py`, `sender.py` and `headers.py`, delete the matching checks in `analyzers/demo.py` so signals are not counted twice.

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
| `.msg` files fail | Install the extra: `uv add "mail-parser[outlook]"`. |
| `does not look like parser output` | You pointed `scan` at a JSON that is not from `arer parse` (a report, for example). |
| `finding id ... has no weight` (warning) | A finding id is missing or misspelled in `rules.yaml`. |
| `INSUFFICIENT_DATA` on a real email | The sender or the whole body is missing from the parsed output. |
