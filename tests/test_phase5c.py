"""Phase 5c: own-domain link text, DKIM signer alignment, junk HTML, greetings."""
from arer.analyzers.auth import Auth, parse_auth_results
from arer.analyzers.body import Body
from arer.analyzers.urls import Urls
from arer.config import load_config
from arer.models import Email
from arer.util.html import parse_html

cfg = load_config()


def mk(frm="news@discord.com", html="", text="", auth=None, bulk=False, subject=""):
    sec = {}
    if auth:
        sec["authentication-results"] = [auth]
    if bulk:
        sec["list-unsubscribe"] = ["<x>"]
    return Email.from_parser_json({
        "envelope": {"subject": subject, "date": "2025-01-01", "message_id": "<1@x.com>",
                     "from": [{"name": "", "address": frm, "domain": frm.split("@")[-1]}]},
        "headers": {"security": sec}, "routing": {"received": [{"hop": 1}]},
        "body": {"text_html": [html] if html else [], "text_plain": [text] if text else [], "combined": text or html}})


def ids(analyzer, email):
    return {f.id: f for f in analyzer.run(email, cfg)}


# ------------------------- link text pointing at the sender's own domain ----------------------- #
DISCORD = '<a href="https://click.discord.com/ls/click?upn=u001.AbCdEf123">dis.gd/contact</a>'

def test_discord_pattern_is_softened_not_a_full_alarm():
    f = ids(Urls(), mk(frm="noreply@discord.com", html=DISCORD))["url.text_href_mismatch"]
    assert f.confidence == 0.3 and "own domain" in f.summary

def test_impersonation_of_a_known_site_stays_full_strength_even_on_the_senders_domain():
    html = '<a href="http://evil.example.net/login">www.paypal.com/login</a>'
    assert ids(Urls(), mk(frm="x@evil.example.net", html=html))["url.text_href_mismatch"].confidence == 1.0

def test_brand_word_in_the_shown_domain_also_stays_full_strength():
    html = '<a href="http://secure.example.net/x">paypal-support.com</a>'
    assert ids(Urls(), mk(frm="x@example.net", html=html))["url.text_href_mismatch"].confidence == 1.0

def test_unrelated_target_is_unchanged():
    assert ids(Urls(), mk(frm="a@shop.com", html='<a href="http://evil.example.net/x">dis.gd/contact</a>'))[
        "url.text_href_mismatch"].confidence == 1.0


# --------------------------------- DKIM signer alignment ------------------------------------- #
def ar(signer_part, dkim="pass"):
    return f"mx.corp.test; spf=pass smtp.mailfrom=x.com; dkim={dkim} {signer_part}; dmarc=pass header.from=x.com"

def test_signers_are_parsed_in_microsoft_and_gmail_styles():
    assert parse_auth_results(ar("(signature was verified) header.d=Ste2099.onmicrosoft.com")).dkim_signers == [("pass", "ste2099.onmicrosoft.com")]
    assert parse_auth_results(ar("header.i=@shop.com header.s=sel header.b=abc")).dkim_signers == [("pass", "shop.com")]
    assert parse_auth_results(ar("header.i=news@shop.com")).dkim_signers == [("pass", "shop.com")]

def test_random_signer_is_flagged():
    f = ids(Auth(), mk(frm="news@sprawley.com", auth=ar("header.d=missli.decomexico.com")))["auth.dkim_misaligned"]
    assert f.confidence == 0.7 and f.evidence["signers"] == ["missli.decomexico.com"]

def test_free_tenant_signer_is_flagged():
    assert "auth.dkim_misaligned" in ids(Auth(), mk(frm="a@deck.socialja.com", auth=ar("header.d=ste20995472.onmicrosoft.com")))

def test_signer_on_the_senders_own_domain_is_fine_including_subdomains():
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@cp.shop.com", auth=ar("header.d=shop.com")))
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@shop.com", auth=ar("header.i=@mail.shop.com")))

def test_known_mail_platform_signer_is_fine():
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@shop.com", auth=ar("header.d=sendgrid.net")))

def test_one_aligned_signature_among_several_is_enough():
    both = "mx.corp.test; dkim=pass header.d=random-esp.example; dkim=pass header.d=shop.com; dmarc=pass"
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@shop.com", auth=both))

def test_failed_or_missing_dkim_is_not_this_finding():
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@shop.com", auth=ar("header.d=evil.example", dkim="fail")))
    assert "auth.dkim_misaligned" not in ids(Auth(), mk(frm="a@shop.com", auth="mx.corp.test; spf=pass; dkim=none; dmarc=pass"))

def test_mailing_lists_get_half_confidence():
    assert ids(Auth(), mk(frm="a@shop.com", auth=ar("header.d=list.example"), bulk=True))["auth.dkim_misaligned"].confidence == 0.35

def test_forged_signer_text_inside_a_comment_is_ignored():
    forged = "mx.corp.test; dkim=pass (header.d=shop.com forged) header.d=evil.example; dmarc=pass"
    assert "auth.dkim_misaligned" in ids(Auth(), mk(frm="a@shop.com", auth=forged))


# ------------------------------------------ junk HTML ---------------------------------------- #
SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); width:640px;height:1138px"></div></a>')

def test_tag_salad_is_detected():
    f = ids(Body(), mk(html=SALAD))["body.html_obfuscation"]
    assert f.confidence == 1.0 and len(f.evidence["signs"]) >= 3 and f.evidence["background_images"] == 1

def test_counters():
    i = parse_html(SALAD)
    assert i.unknown_tags == 3 and i.doctypes == 4 and i.filler_tags >= 35 and i.hidden_elements >= 22 and i.bg_images == 1

def test_outlook_generated_html_is_not_junk():
    outlook = ('<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><head><xml><o:OfficeDocumentSettings>'
               '</o:OfficeDocumentSettings></xml></head><body><v:roundrect><v:textbox></v:textbox></v:roundrect><p><o:p>Hello</o:p></p>'
               '<amp-img src="a"></amp-img><my-element>x</my-element></body></html>')
    assert "body.html_obfuscation" not in ids(Body(), mk(html="<!DOCTYPE html>" + outlook))

def test_normal_newsletter_is_not_junk():
    news = ('<!DOCTYPE html><html><body><div style="display:none">preheader text</div><table><tr><td style="background:url(x.png)">'
            'Hello there, here is your weekly digest with plenty of real text in it.</td></tr></table></body></html>')
    assert "body.html_obfuscation" not in ids(Body(), mk(html=news))

def test_a_single_sign_gives_reduced_confidence():
    assert ids(Body(), mk(html="<html>" + "<!DOCTYPE>" * 3 + "<p>real text here</p></html>"))["body.html_obfuscation"].confidence == 0.7

def test_padding_tags_with_real_text_are_not_flagged():
    page = "<html><body><p>" + "a long real message " * 10 + "</p>" + "<option>x</option>" * 25 + "</body></html>"
    assert "body.html_obfuscation" not in ids(Body(), mk(html=page))


# ------------------------------------------- greetings ---------------------------------------- #
def test_dear_reader_and_subscriber():
    assert "body.generic_greeting" in ids(Body(), mk(text="Dear Reader, In the spring of 2024..."))
    assert "body.generic_greeting" in ids(Body(), mk(text="Dear subscriber, news"))


# ---- regressions found by the 704 + 670 evaluation: ordinary newsletters must not look like junk HTML ----
NEWSLETTER = ('<!DOCTYPE html><html><head><style>td{font-family:Arial}</style></head><body>'
              '<div style="display:none;font-size:1px;max-height:0;opacity:0;overflow:hidden">Your weekly digest is here</div><table>'
              + '<tr><td style="font-size:0;line-height:0;height:12px">&nbsp;</td></tr>' * 18
              + '<div style="display:none;max-height:0;mso-hide:all">mobile only</div>' * 6
              + '<tr><td>Hello Sam, here is your weekly digest with plenty of real text about this week.</td></tr>'
              + '<svg width="16" height="16"><g><path d="M0 0h16v16H0z"/><circle cx="8" cy="8" r="4"/></g></svg>' * 3
              + '</table><img src="https://t.example.com/p.gif" width="1" height="1" style="display:none"></body></html>')

def test_marketing_newsletter_with_svg_icons_and_hidden_spacers_is_not_junk():
    i = parse_html(NEWSLETTER)
    assert i.hidden_elements >= 25 and i.unknown_tags == 0                       # still counted, never a sign
    assert "body.html_obfuscation" not in ids(Body(), mk(html=NEWSLETTER, bulk=True))
    assert "body.html_obfuscation" not in ids(Body(), mk(html=NEWSLETTER))

def test_mass_hidden_elements_alone_are_not_junk():
    assert "body.html_obfuscation" not in ids(Body(), mk(html="<p>real text here for the reader</p>" + '<div style="display:none">x</div>' * 60))

def test_made_up_tag_names_still_count():
    assert parse_html("<html><AAAA><BBBB><CCCC>text</html>").unknown_tags == 3

def test_big_hidden_block_is_the_strong_finding():
    big = '<p>Hi</p><div style="display:none">' + "xQ7kP2" * 1500 + "</div>"
    assert ids(Body(), mk(html=big, bulk=True))["body.hidden_text"].confidence == 1.0

def test_mailparser_logger_is_silenced_unless_verbose():
    import logging
    from click.testing import CliRunner
    from arer.cli import main
    CliRunner().invoke(main, ["feeds", "status"], env={"PHISHSCOPE_FEEDS": "/tmp/_none_feeds"})
    assert logging.getLogger("mailparser").level == logging.CRITICAL
    CliRunner().invoke(main, ["-v", "feeds", "status"], env={"PHISHSCOPE_FEEDS": "/tmp/_none_feeds"})
    assert logging.getLogger("mailparser").level == logging.DEBUG


def test_new_findings_use_a_builtin_default_when_rules_yaml_predates_them(caplog):
    from arer.config import DEFAULT_WEIGHTS
    c = cfg.model_copy(deep=True)
    c.weights.pop("body.hidden_preheader", None)                      # an older, hand-tuned rules.yaml
    assert c.weight_for("body.hidden_preheader") == DEFAULT_WEIGHTS["body.hidden_preheader"] == 1
    c.weights["body.hidden_preheader"] = 4                            # the user's own value always wins
    assert c.weight_for("body.hidden_preheader") == 4

def test_unknown_ids_are_warned_only_once(caplog):
    import logging
    c = cfg.model_copy(deep=True)
    with caplog.at_level(logging.WARNING, logger="phishscope.config"):
        for _ in range(5):
            assert c.weight_for("body.totally_new_unlisted_id") == 0
    assert sum("totally_new_unlisted_id" in r.message for r in caplog.records) == 1
