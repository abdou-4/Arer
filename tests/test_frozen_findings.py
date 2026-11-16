"""Freeze the finding ID registry.

The roadmap freezes finding ID names before Phase 6: dispositions, metrics and
the ML explanations all reference these IDs, and old history.db rows keep them
forever. Renaming or casually adding a finding ID must be a conscious act --
this test fails until the registry and docs/finding-ids.md are updated.
"""
import re
import yaml
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "arer" / "analyzers"
RULES = Path(__file__).resolve().parents[1] / "config" / "rules.yaml"

# The frozen registry: every finding ID any analyzer may emit, ever.
# Grouped by analyzer. Add an entry here AND a row in docs/finding-ids.md
# when you introduce a new finding; never rename an existing one.
FROZEN = {
    # attachments.py
    "attachment.promised_missing",
    "attachment.executable",
    "attachment.double_extension",
    "attachment.macro_office",
    "attachment.html_or_svg",
    "attachment.archive_with_exe",
    "attachment.encrypted_archive",
    "attachment.magic_mismatch",
    # auth.py
    "auth.results_missing",
    "auth.spf_fail",
    "auth.spf_softfail",
    "auth.dkim_fail",
    "auth.dkim_none",
    "auth.dkim_misaligned",
    "auth.dmarc_fail",
    "auth.dmarc_no_policy",
    # body.py
    "body.urgency_words",
    "body.credential_words",
    "body.prize_lure",
    "body.obfuscated_subject",
    "body.generic_greeting",
    "body.callback_lure",
    "body.password_form",
    "body.hidden_text",
    "body.hidden_preheader",
    "body.html_obfuscation",
    "body.image_only",
    # headers.py
    "headers.missing_received",
    "headers.high_hop_count",
    "headers.suspicious_mailer",
    "headers.missing_date",
    "headers.msgid_bare_host",
    "headers.msgid_domain_mismatch",
    "headers.returnpath_mismatch",
    "headers.parser_defects",
    # history.py
    "history.known_bad_hash",
    "history.known_bad_sender",
    "history.known_bad_link_domain",
    "history.new_sender",
    # intel.py
    "intel.feeds_missing",
    "intel.feeds_stale",
    "url.on_blocklist",
    "url.domain_on_blocklist",
    "sender.on_blocklist",
    "attachment.known_malicious_hash",
    # sender.py
    "sender.invalid_format",
    "sender.reply_to_mismatch",
    "sender.display_name_spoof",
    "sender.freemail_brand",
    "sender.obfuscated_name",
    "sender.shared_domain",
    "sender.lookalike_domain",
    "sender.mixed_script_domain",
    "sender.punycode_domain",
    # unicode_tricks.py
    "body.invisible_chars",
    "body.bidi_control",
    "body.homoglyph_text",
    # urls.py
    "url.text_href_mismatch",
    "url.userinfo_at",
    "url.ip_host",
    "url.invisible_chars",
    "url.punycode",
    "url.suspicious_tld",
    "url.shortener",
    "url.free_hosting",
    "url.many_subdomains",
    "url.lookalike_domain",
    "url.mixed_script_domain",
    "url.not_https",
    "url.login_keywords",
    "url.brand_mismatch",
}

# IDs emitted by analyzers but intentionally carrying no weight in rules.yaml
# (scored as 0, with a one-time warning). Tuning them is a roadmap "tune on
# dev" task -- decide a weight and move them out of this set, or keep them as
# informational notices.
UNWEIGHTED = {
    "body.hidden_preheader",   # open tuning item, see docs/finding-ids.md
}

# Weight keys reserved in rules.yaml for future use; no analyzer emits them yet.
RESERVED_IN_RULES = {
    "ai.text_classifier",      # Phase 7 text ML
    "ai.urgency_model",        # Phase 7 text ML
    "sender.no_mx",            # candidate, not implemented
}


def _emitted_ids() -> set[str]:
    pat = re.compile(r'"((?:attachment|auth|body|headers|history|intel|sender|url)\.[a-z0-9_]+)"')
    found: set[str] = set()
    for f in sorted(SRC.glob("*.py")):
        found |= set(pat.findall(f.read_text(encoding="utf-8")))
    return found


def _weight_keys() -> set[str]:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    return {k for k in rules.get("weights", {}) if "." in k}


def test_emitted_ids_match_frozen_registry():
    emitted = _emitted_ids()
    assert emitted == FROZEN, (
        "finding IDs changed:\n"
        f"  new, not in the frozen registry: {sorted(emitted - FROZEN)}\n"
        f"  registered but no longer emitted: {sorted(FROZEN - emitted)}\n"
        "Update FROZEN here and docs/finding-ids.md together, and never rename."
    )


def test_every_emitted_id_has_a_weight_or_is_allowlisted():
    unaccounted = _emitted_ids() - _weight_keys() - UNWEIGHTED
    assert not unaccounted, f"IDs with no weight and not allowlisted: {sorted(unaccounted)}"


def test_rules_yaml_has_no_orphaned_weight_keys():
    orphans = _weight_keys() - _emitted_ids() - RESERVED_IN_RULES
    assert not orphans, f"weights in rules.yaml that no analyzer emits: {sorted(orphans)}"
