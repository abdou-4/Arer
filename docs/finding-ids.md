# Finding ID registry (frozen)

Every piece of evidence Arer reports has a finding ID (`auth.spf_fail`,
`url.ip_host`, ...). These names are **frozen as of the Phase 6
prerequisites**: dispositions, metrics, blocklist exports and later ML
explanations all reference them, and saved history rows keep them forever.

The rules:

- **Never rename** an existing ID. Old data would silently lose its meaning.
- **Never add one casually.** A new ID needs: the analyzer code, a `weights`
  entry (or an explicit decision to be unweighted), a row here, and an entry
  in the frozen registry in `tests/test_frozen_findings.py` — that test
  fails on any unregistered ID, so all four touchpoints move together.
- Each ID's weight lives in `config/rules.yaml` under `weights:`; the table
  below shows the value at freeze time. Weights are tuning, not contract —
  they can change with a measurement; the IDs cannot.

The same list lives in machine-checkable form in
`tests/test_frozen_findings.py`. If this file and that test disagree, the
test wins.

## Attachments (`attachment.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `attachment.executable` | 15 | Windows executable or script attached |
| `attachment.double_extension` | 10 | Name hides its real type (`invoice.pdf.exe`) |
| `attachment.macro_office` | 12 | Office document carrying a VBA macro |
| `attachment.archive_with_exe` | 12 | Archive containing an executable |
| `attachment.encrypted_archive` | 8 | Password-protected archive (AV cannot look inside) |
| `attachment.html_or_svg` | 10 | HTML/SVG attachment (can hide phishing content) |
| `attachment.magic_mismatch` | 10 | File contents do not match its extension |
| `attachment.promised_missing` | 8 | Message refers to an attachment that is not there |
| `attachment.known_malicious_hash` | 40 | Attachment hash is on your known-bad list |

## Sender (`sender.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `sender.invalid_format` | 10 | From address missing or unreadable |
| `sender.reply_to_mismatch` | 12 | Reply-To goes somewhere other than the sender |
| `sender.display_name_spoof` | 15 | Display name claims a brand the real domain has nothing to do with |
| `sender.freemail_brand` | 8 | Free-mail address wearing an official-sounding name |
| `sender.obfuscated_name` | 8 | Display name uses obfuscated Unicode to imitate a brand |
| `sender.shared_domain` | 8 | Sender domain is a shared/free-hosting domain |
| `sender.lookalike_domain` | 15 | Domain imitates a known brand (typosquat/homoglyph) |
| `sender.mixed_script_domain` | 8 | Sender domain mixes scripts (e.g. Cyrillic inside Latin) |
| `sender.punycode_domain` | 8 | Internationalised (`xn--`) sender domain |

## Authentication (`auth.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `auth.spf_fail` | 15 | SPF failed: sender IP not authorised |
| `auth.spf_softfail` | 8 | SPF softfail: sender IP probably not authorised |
| `auth.dkim_fail` | 10 | DKIM signature failed verification |
| `auth.dkim_none` | 3 | Message is not DKIM-signed |
| `auth.dkim_misaligned` | 6 | DKIM signed by a domain other than the sender's |
| `auth.dmarc_fail` | 10 | DMARC failed for the From domain |
| `auth.dmarc_no_policy` | 5 | From domain publishes no DMARC policy |
| `auth.results_missing` | 5 | Authentication-Results missing or unreadable |

## URLs (`url.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `url.on_blocklist` | 40 | Exact link on a phishing blocklist |
| `url.domain_on_blocklist` | 25 | Link host domain on a phishing blocklist |
| `url.text_href_mismatch` | 20 | Link text says one place, href goes elsewhere |
| `url.userinfo_at` | 8 | `user@host` trick in the URL |
| `url.ip_host` | 10 | Link host is a bare IP address |
| `url.invisible_chars` | 5 | Invisible characters inside the URL |
| `url.punycode` | 8 | `xn--` (internationalised) link domain |
| `url.suspicious_tld` | 5 | Link ends in a frequently abused TLD |
| `url.shortener` | 5 | Link shortener hides the destination |
| `url.free_hosting` | 6 | Hosted on free web hosting |
| `url.many_subdomains` | 8 | Excessive subdomains (brand padded with dots) |
| `url.lookalike_domain` | 15 | Link domain imitates a known brand |
| `url.mixed_script_domain` | 8 | Link domain mixes scripts |
| `url.not_https` | 3 | Login page served over plain HTTP |
| `url.login_keywords` | 2 | URL path built to look like a login page |
| `url.brand_mismatch` | 10 | URL brand token does not match the actual domain |

## Body and Unicode tricks (`body.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `body.urgency_words` | 3 | Pressure language in subject/body |
| `body.credential_words` | 4 | Asks for credentials or payment data |
| `body.prize_lure` | 12 | Prize/lottery/giveaway scam language |
| `body.callback_lure` | 15 | Fake charge/alert plus a phone number (callback scam) |
| `body.password_form` | 12 | Embedded form asking for password or card data |
| `body.obfuscated_subject` | 6 | Subject uses dots instead of spaces |
| `body.generic_greeting` | 3 | Impersonal greeting |
| `body.hidden_text` | 4 | Huge block of hidden text (spam-filter evasion) |
| `body.hidden_preheader` | 0 | Short hidden preheader text — **no weight in rules.yaml; open tuning item** |
| `body.html_obfuscation` | 8 | HTML padded with junk to evade filters |
| `body.image_only` | 2 | Message is just images, almost no text |
| `body.invisible_chars` | 5 | Invisible characters inserted inside words |
| `body.bidi_control` | 7 | Directional override/embedding controls in the body |
| `body.homoglyph_text` | 8 | Brand name written with visually confusable characters |

## Headers (`headers.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `headers.missing_received` | 5 | No Received headers (route cannot be traced) |
| `headers.high_hop_count` | 3 | Unusually many mail hops |
| `headers.suspicious_mailer` | 5 | Sent with a bulk-mailer tool |
| `headers.missing_date` | 2 | No (or unreadable) Date header |
| `headers.msgid_bare_host` | 2 | Message-ID uses a bare host, not a domain |
| `headers.msgid_domain_mismatch` | 2 | Message-ID domain differs from From domain |
| `headers.returnpath_mismatch` | 2 | Return-Path domain differs from From domain |
| `headers.parser_defects` | 3 | Message structure is malformed |

## History (your own labels) (`history.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `history.known_bad_hash` | 40 | Attachment matches one you labelled phishing |
| `history.known_bad_sender` | 30 | Exact sender address sent phishing you labelled |
| `history.known_bad_link_domain` | 20 | Link to a domain from phishing you labelled |
| `history.new_sender` | 3 | First e-mail ever from this sender |

## Intel (feeds notices, weight 0 by design) (`intel.`)

| ID | weight | what it means |
|----|-------:|---------------|
| `intel.feeds_missing` | 0 | No blocklist data downloaded; blocklist checks are off |
| `intel.feeds_stale` | 0 | Blocklist data out of date; run `arer feeds update` |

## Reserved (in rules.yaml, not emitted yet)

| ID | weight | reserved for |
|----|-------:|--------------|
| `ai.text_classifier` | 10 | Phase 7 text model |
| `ai.urgency_model` | 5 | Phase 7 text model |
| `sender.no_mx` | 5 | Candidate rule, not implemented |

## Open tuning items

- `body.hidden_preheader` is emitted with confidence 0.2 (bulk mail —
  newsletters legitimately hide a preheader) or 0.8 (otherwise) but has no
  `weights:` entry, so it scores 0 and logs a one-time warning. Decide a
  weight on the dev split, or keep it informational and leave it in the
  `UNWEIGHTED` allowlist in the freeze test.
