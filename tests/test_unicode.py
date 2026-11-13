"""Regression tests for Arer's bounded, context-aware Unicode handling."""
from __future__ import annotations

from arer.analyzers.base import get_analyzers
from arer.pipeline import run_pipeline
from arer.analyzers.body import Body
from arer.analyzers.sender import Sender
from arer.analyzers.urls import SHOWN_HOST, Urls
from arer.analyzers.unicode_tricks import UnicodeTricks
from arer.config import load_config
from arer.models import Email
from arer.util.defang import safe_text
from arer.util.domains import lookalike, mixed_script
from arer.util.unicode_text import (
    MAX_TEXT_CHARS,
    bidi_control_records,
    codepoint_descriptions,
    comparison_skeleton,
    fold_for_matching,
    invisible_char_records,
    mixed_script_text,
    obfuscated_brand_matches,
    word_tokens,
)

CFG = load_config()


def mk(*, name="Bob", addr="bob@example.com", subject="", html="", text="", bulk=False):
    security = {"list-unsubscribe": ["<mailto:unsubscribe@example.com>"]} if bulk else {}
    return Email.from_parser_json({
        "envelope": {
            "subject": subject,
            "from": [{"name": name, "address": addr, "domain": addr.rsplit("@", 1)[-1]}],
            "date": "2025-01-01T00:00:00",
            "message_id": "<unicode-test@example.com>",
        },
        "headers": {"security": security},
        "routing": {"received": [{"hop": 1}]},
        "body": {
            "text_plain": [text] if text else [],
            "text_html": [html] if html else [],
            "combined": text or html,
        },
        "indicators": {"urls": [], "href_text_mismatches": []},
    })


def findings(analyzer, email):
    return {finding.id: finding for finding in analyzer.run(email, CFG)}


# ---------------------------- comparison helpers --------------------------- #

def test_confusable_comparison_maps_cyrillic_and_greek_but_not_digits():
    assert comparison_skeleton("PаyPal") == "paypal"  # Cyrillic small a
    assert comparison_skeleton("ΡΑΥΡΑL").startswith("paypal")  # Greek lookalikes
    assert comparison_skeleton("1l0") == "1l0"              # no digit-to-letter mapping
    assert comparison_skeleton("ı") == "ı"                  # Turkish dotless i stays distinct


def test_nfkc_handles_fullwidth_and_mathematical_alphabet():
    assert fold_for_matching("ｖｅｒｉｆｙ your account") == "verify your account"
    assert fold_for_matching("𝐯𝐞𝐫𝐢𝐟𝐲 your account") == "verify your account"


def test_script_detection_is_per_word_and_allows_japanese_korean_combinations():
    assert not mixed_script_text("Русский текст")
    assert not mixed_script_text("Ελληνικά κείμενα")
    assert not mixed_script_text("みずほ銀行")
    assert not mixed_script_text("日本語とカタカナ")
    assert not mixed_script_text("대한민국")
    assert not mixed_script_text("日本語 PayPal")
    assert mixed_script_text("PаyPal")
    assert mixed_script_text("bаnk-of-xyz")
    assert not mixed_script("みずほ銀行.jp")
    assert not mixed_script("日本語.com")
    assert mixed_script("bаnk-of-xyz.com")
    # A whole-script spoof is not mixed-script, but is still matched against a known brand.
    assert lookalike("раураӏ.com", CFG.lists["brands"], CFG.lists["legit_domains"], CFG.lists["suspicious_tlds"])


def test_invisible_character_rules_are_contextual():
    assert invisible_char_records("Pay\u200bPal")
    assert invisible_char_records("veri\u200bfy")
    consecutive = invisible_char_records("veri\u200b\u200bfy")
    assert len(consecutive) == 2
    assert all(item["token"] == "veri\u200b\u200bfy" for item in consecutive)
    assert invisible_char_records("word\u2060joiner")
    assert invisible_char_records("ab\u2061CD")
    assert invisible_char_records("ab\U000e0061CD")
    assert invisible_char_records("ab\u200cCD")  # ZWNJ between ASCII letters
    assert invisible_char_records("ab\u200dCD")  # ZWJ between ASCII letters
    assert invisible_char_records("veri\u00adfy", {"verify"})
    assert not invisible_char_records("In\u00adformation", {"verify"})
    assert not invisible_char_records("می\u200cخواهم و می\u200cروم")
    assert not invisible_char_records("عربي\u200e text")
    assert not invisible_char_records("👨‍👩‍👧‍👦")
    assert not invisible_char_records("a \u200b b")  # padding between spaces is not inside a word


def test_bidi_detection_ignores_lrm_rlm_and_finds_override_and_isolate():
    assert not bidi_control_records("Arabic \u200e text \u200f")
    assert bidi_control_records("invoice\u202ename.exe")
    assert bidi_control_records("text \u2066hidden\u2069")


def test_bidi_detection_ignores_balanced_rle_pdf_around_rtl_only_text():
    assert not bidi_control_records("\u202bمرحبا بالعالم\u202c")
    # A mixed LTR/RTL segment remains suspicious.
    # A nested balanced RLE/PDF pair must not be partially suppressed.
    nested = "\u202bouter \u202bمرحبا\u202c outer\u202c"
    assert len(bidi_control_records(nested)) == 4
    assert bidi_control_records("\u202bPayPal مرحبا\u202c")
    # An unmatched embedding opener remains suspicious.
    assert bidi_control_records("مرحبا \u202b")


def test_word_tokens_preserve_original_and_report_codepoint_names():
    token = word_tokens("Please PаyPal now")[1]
    assert token.original == "PаyPal"
    assert token.skeleton == "paypal"
    assert token.obfuscated
    assert "U+0430 CYRILLIC SMALL LETTER A" in codepoint_descriptions(token.original)


def test_word_tokens_keep_consecutive_internal_format_controls():
    value = "veri\u200b\u200bfy"
    token = word_tokens(value)[0]
    assert token.original == value
    assert token.skeleton == "verify"
    assert token.obfuscated


def test_uppercase_cyrillic_and_greek_confusables_are_obfuscated():
    for value in ("PАyPal", "ΡΑΥΡΑL"):
        token = word_tokens(value)[0]
        assert token.skeleton == "paypal"
        assert token.obfuscated


def test_obfuscated_brand_match_is_term_specific():
    assert obfuscated_brand_matches("PаyPal Support", {"paypal"})
    assert obfuscated_brand_matches("ＰａｙＰａｌ", {"paypal"})
    assert not obfuscated_brand_matches("𝙋𝙖𝙮𝙋𝙖𝙡", {"paypal"})
    assert not obfuscated_brand_matches("A Russian sentence with PayPal", {"paypal"})
    assert not obfuscated_brand_matches("Pay\u200bPal", {"paypal"})  # invisible finding handles this


def test_unicode_helpers_are_bounded():
    huge = ("ordinary-text " * 20_000) + "PаyPal"
    tokens = word_tokens(huge)
    assert all(token.end <= MAX_TEXT_CHARS for token in tokens)
    assert not any(token.skeleton == "paypal" for token in tokens)  # final marker is beyond the cap
    assert len(invisible_char_records(huge + "Pay\u200bPal")) <= 12


# -------------------------------- body ------------------------------------ #

def test_body_phrase_matching_uses_confusable_skeleton_and_keeps_evidence():
    email = mk(text="Please verіfy your account immediately.")
    before = email.model_dump()
    found = findings(Body(), email)
    assert "body.credential_words" in found
    assert found["body.credential_words"].evidence["unicode_matches"][0]["skeleton"] == "verify"
    assert email.model_dump() == before


def test_body_phrase_matching_reconstructs_internal_invisible_characters():
    for phrase in ("veri\u200bfy your account", "veri\u200b\u200bfy your account", "veri\u00adfy your account"):
        assert "body.credential_words" in findings(Body(), mk(text=phrase))


def test_body_phrase_matching_detects_uppercase_cyrillic_confusable():
    assert "body.credential_words" in findings(Body(), mk(text="Please verІfy your account."))


def test_unicode_analyzer_finds_invisible_character_inside_word():
    found = findings(UnicodeTricks(), mk(text="Please veri\u200bfy your account."))
    assert "body.invisible_chars" in found
    record = found["body.invisible_chars"].evidence["characters"][0]
    assert record["codepoint"] == "U+200B ZERO WIDTH SPACE"
    assert record["token"] == "veri\u200bfy"


def test_soft_hyphen_is_reported_only_inside_known_trigger_word():
    assert "body.invisible_chars" in findings(UnicodeTricks(), mk(text="Please veri\u00adfy your account."))
    assert "body.invisible_chars" not in findings(UnicodeTricks(), mk(text="Our In\u00adformation newsletter is ready."))


def test_unicode_analyzer_detects_body_brand_homoglyph():
    found = findings(UnicodeTricks(), mk(text="Your PаyPal account needs attention."))
    assert "body.homoglyph_text" in found
    assert "U+0430 CYRILLIC SMALL LETTER A" in found["body.homoglyph_text"].evidence["matches"][0]["codepoints"]




def test_unicode_analyzer_detects_consecutive_invisible_characters():
    found = findings(UnicodeTricks(), mk(text="Please veri\u200b\u200bfy your account."))
    assert "body.invisible_chars" in found
    assert found["body.invisible_chars"].evidence["count"] == 2
def test_unicode_analyzer_detects_uppercase_cyrillic_body_brand_homoglyph():
    found = findings(UnicodeTricks(), mk(text="Your PАyPal account needs attention."))
    assert "body.homoglyph_text" in found
    assert "U+0410 CYRILLIC CAPITAL LETTER A" in found["body.homoglyph_text"].evidence["matches"][0]["codepoints"]


def test_unicode_analyzer_matches_whole_script_brand_only_when_known():
    assert "body.homoglyph_text" in findings(UnicodeTricks(), mk(text="Ваш раураӏ аккаунт"))
    assert "body.homoglyph_text" not in findings(UnicodeTricks(), mk(text="Обычное русское письмо"))


def test_mathematical_bold_latin_brand_is_not_reported_as_cross_script_homoglyph():
    found = findings(UnicodeTricks(), mk(text="𝙋𝙖𝙮𝙋𝙖𝙡 Support"))
    assert "body.homoglyph_text" not in found


def test_math_bold_compatibility_normalization_still_matches_body_phrases():
    email = mk(text="Please 𝙫𝙚𝙧𝙞𝙛𝙮 your account immediately.")
    assert "body.credential_words" in findings(Body(), email)


def test_unicode_analyzer_checks_html_visible_text():
    email = mk(html="<p>Please veri&#x200B;fy your account.</p>")
    found = findings(UnicodeTricks(), email)
    assert "body.invisible_chars" in found
    assert found["body.invisible_chars"].evidence["characters"][0]["codepoint"] == "U+200B ZERO WIDTH SPACE"


def test_all_unicode_aware_analyzers_leave_email_unchanged():
    email = mk(name="PаyPal Support", addr="help@bаnk-of-xyz.com",
               text="Please veri​fy your account; https://bаnk-of-xyz.com/login")
    before = email.model_dump()
    for analyzer in (Body(), Sender(), Urls(), UnicodeTricks()):
        analyzer.run(email, CFG)
    assert email.model_dump() == before


def test_body_keywords_do_not_globally_transliterate_ordinary_russian_or_greek():
    for text in ("Срочно отправьте письмо коллегам", "Επείγον μήνυμα προς τους συναδέλφους"):
        found = findings(Body(), mk(text=text))
        assert "body.credential_words" not in found


def test_unicode_analyzer_does_not_flag_pure_script_or_separate_brand():
    for text in (
        "Русский текст для проверки",
        "Ελληνικά κείμενα για δοκιμή",
        "می\u200cخواهم و می\u200cروم",
        "عربي\u200e النص",
        "नमस्ते दुनिया",
        "ภาษาไทย",
        "みずほ銀行",
        "대한민국",
        "Русский текст PayPal",
        "👨‍👩‍👧‍👦",
    ):
        assert findings(UnicodeTricks(), mk(text=text)) == {}, text


def test_html_emoji_zwj_and_persian_zwnj_do_not_create_preheader_false_positive():
    for text in ("Family 👨‍👩‍👧‍👦 update", "می\u200cخواهم و می\u200cروم"):
        email = mk(html=f"<html><body><p>{text}</p></body></html>")
        assert "body.hidden_preheader" not in findings(Body(), email)
        assert findings(UnicodeTricks(), email) == {}


def test_unicode_bidi_body_finding():
    found = findings(UnicodeTricks(), mk(text="Invoice \u202eexe.pdf"))
    assert "body.bidi_control" in found
    assert "U+202E RIGHT-TO-LEFT OVERRIDE" in found["body.bidi_control"].evidence["characters"][0]["codepoint"]


# -------------------------------- sender ---------------------------------- #

def test_sender_obfuscated_brand_uses_one_dedicated_finding():
    for name in ("PаyPal Support", "Pay\u200bPal Support", "Pay\u200b\u200bPal Support", "ＰａｙＰａｌ Support"):
        found = findings(Sender(), mk(name=name, addr="help@evil.example"))
        assert "sender.obfuscated_name" in found, name
        assert "sender.display_name_spoof" not in found, name


def test_sender_detects_uppercase_cyrillic_brand_obfuscation():
    found = findings(Sender(), mk(name="PАyPal Support", addr="help@evil.example"))
    assert "sender.obfuscated_name" in found
    assert "sender.display_name_spoof" not in found


def test_sender_mathematical_bold_brand_is_not_unicode_obfuscation():
    found = findings(Sender(), mk(name="𝙋𝙖𝙮𝙋𝙖𝙡 Support", addr="help@evil.example"))
    assert "sender.obfuscated_name" not in found
    assert "sender.display_name_spoof" in found


def test_sender_russian_text_with_separate_latin_brand_is_not_unicode_obfuscation():
    found = findings(Sender(), mk(name="Русский PayPal", addr="help@evil.example"))
    assert "sender.obfuscated_name" not in found


def test_sender_ascii_brand_behavior_is_preserved():
    found = findings(Sender(), mk(name="PayPal Support", addr="help@evil.example"))
    assert "sender.display_name_spoof" in found
    assert "sender.obfuscated_name" not in found


def test_sender_multiword_brand_requires_adjacent_tokens():
    # The old matcher required phrase adjacency; Unicode tokenization must not
    # accidentally turn unrelated words into a multi-word brand claim.
    found = findings(Sender(), mk(name="Geek spam Squad", addr="help@evil.example"))
    assert "sender.display_name_spoof" not in found
    assert "sender.obfuscated_name" not in found


def test_sender_official_brand_domain_is_not_flagged_for_display_name():
    for name in ("PаyPal Support", "ＰａｙＰａｌ Support", "𝙋𝙖𝙮𝙋𝙖𝙡 Support"):
        found = findings(Sender(), mk(name=name, addr="service@paypal.com"))
        assert "sender.obfuscated_name" not in found
        assert "sender.display_name_spoof" not in found


def test_sender_accepts_valid_unicode_idn_and_detects_mixed_script_label():
    found = findings(Sender(), mk(addr="user@bаnk-of-xyz.com"))
    assert "sender.invalid_format" not in found
    assert "sender.mixed_script_domain" in found


def test_sender_brand_lookalike_enriches_existing_finding_without_double_scoring():
    found = findings(Sender(), mk(addr="user@pаypal.com"))
    assert "sender.lookalike_domain" in found
    assert "sender.mixed_script_domain" not in found
    assert found["sender.lookalike_domain"].evidence["mixed_script_labels"]


def test_sender_legitimate_single_script_idn_is_not_mixed_script():
    found = findings(Sender(), mk(addr="user@みずほ銀行.jp"))
    assert "sender.invalid_format" not in found
    assert "sender.mixed_script_domain" not in found
    # Raw Unicode U-labels must receive the same low-confidence IDN signal as
    # their ASCII xn-- A-label representation, rather than falling through.
    assert found["sender.punycode_domain"].confidence == 0.7


def test_sender_raw_unicode_idn_matches_existing_punycode_behavior():
    u_label = findings(Sender(), mk(addr="user@bücher.de"))
    a_label = findings(Sender(), mk(addr="user@xn--bcher-kva.de"))

    for found in (u_label, a_label):
        assert "sender.invalid_format" not in found
        assert "sender.punycode_domain" in found
        assert found["sender.punycode_domain"].confidence == 0.7


def test_sender_rejects_unicode_idn_with_trailing_dot():
    for addr in (
        "user@bücher.de.",
        "user@bücher.de..",
        "user@bücher.de。",
    ):
        found = findings(Sender(), mk(addr=addr))
        assert "sender.invalid_format" in found, addr


def test_sender_mixed_script_unicode_domain_uses_specific_finding_only():
    found = findings(Sender(), mk(addr="user@bаnk-of-xyz.com"))
    assert "sender.invalid_format" not in found
    assert "sender.mixed_script_domain" in found
    assert "sender.punycode_domain" not in found


# --------------------------------- URLs ----------------------------------- #

def test_url_shown_host_comparison_handles_cyrillic_zero_width_and_fullwidth():
    shown_hosts = ("pаypal.com", "pay\u200bpal.com", "ｐａｙｐａｌ.com")
    for shown in shown_hosts:
        email = mk(html=f'<a href="https://evil.example/login">{shown}</a>')
        found = findings(Urls(), email)
        assert "url.text_href_mismatch" in found, shown
        assert found["url.text_href_mismatch"].evidence["unicode_evidence"], shown


def test_url_same_visual_skeleton_still_detects_confusable_destination():
    email = mk(html='<a href="https://pаypal.com/login">paypal.com</a>')
    found = findings(Urls(), email)
    assert "url.lookalike_domain" in found
    # The displayed and destination hosts have the same comparison skeleton;
    # the dedicated lookalike finding must catch the spoof without duplication.
    assert "url.text_href_mismatch" not in found


def test_shown_host_keeps_legacy_tld_length_and_character_limits():
    assert SHOWN_HOST.match("www.example.com")
    assert SHOWN_HOST.match("www.example.рф")
    assert not SHOWN_HOST.match("www.example.123")
    assert not SHOWN_HOST.match("www.example.a")
    assert not SHOWN_HOST.match("www.example." + "a" * 25)


def test_url_actual_href_with_invisible_character_is_detected():
    email = mk(html='<a href="https://pay\u200bpal.example/login">click here</a>')
    found = findings(Urls(), email)
    assert "url.invisible_chars" in found
    assert found["url.invisible_chars"].evidence["unicode_evidence"][0]["characters"][0]["codepoint"] == "U+200B ZERO WIDTH SPACE"


def test_url_raw_unicode_mixed_script_domain_is_detected():
    email = mk(text="Visit https://bаnk-of-xyz.com/login")
    found = findings(Urls(), email)
    assert "url.mixed_script_domain" in found


def test_url_brand_lookalike_enriches_existing_finding_without_double_scoring():
    email = mk(text="Visit https://pаypal.com/login")
    found = findings(Urls(), email)
    assert "url.lookalike_domain" in found
    assert "url.mixed_script_domain" not in found
    assert found["url.lookalike_domain"].evidence["unicode_evidence"]


def test_url_legitimate_single_script_idn_is_not_mixed_script():
    email = mk(text="Visit https://みずほ銀行.jp/")
    found = findings(Urls(), email)
    assert "url.mixed_script_domain" not in found


def test_safe_text_renders_new_invisible_ranges():
    rendered = safe_text("a\u00adb\u2060c\u2061d\u2062e\u2063f\u2064g\U000e0061")
    for marker in ("<U+00AD>", "<U+2060>", "<U+2061>", "<U+2062>", "<U+2063>", "<U+2064>", "<U+E0061>"):
        assert marker in rendered


def test_unicode_analyzer_registers_and_can_be_skipped():
    assert "unicode" in {analyzer.name for analyzer in get_analyzers()}
    assert "unicode" not in {analyzer.name for analyzer in get_analyzers(skip={"unicode"})}


def test_pipeline_assigns_unicode_weights_and_skip_works():
    email = mk(text="Please veri\u200bfy your account.")
    verdict = run_pipeline(email, CFG, analyzers=[UnicodeTricks()])
    finding = next(item for item in verdict.findings if item.id == "body.invisible_chars")
    assert finding.weight == CFG.weight_for("body.invisible_chars") == 5
    skipped = run_pipeline(email, CFG, analyzers=get_analyzers(skip={"unicode"}))
    assert "body.invisible_chars" not in {item.id for item in skipped.findings}
