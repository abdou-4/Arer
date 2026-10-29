"""Tests for Phase 3 analyzers (urls, attachments, body) and the Phase 2 fixes."""
import base64
import io
import zipfile

from arer.analyzers.attachments import Attachments
from arer.analyzers.auth import Auth
from arer.analyzers.body import Body
from arer.analyzers.headers import Headers
from arer.analyzers.sender import Sender
from arer.analyzers.urls import Urls
from arer.config import load_config
from arer.models import Email
from arer.util.html import parse_html

cfg = load_config()


def mk(subject="", html="", text="", frm="bob@example.com", name="Bob", atts=None, bulk=False, msgid="<1@example.com>", rp="<bob@example.com>", auth=None):
    sec = {"list-unsubscribe": ["<x>"]} if bulk else {}
    if auth:
        sec["authentication-results"] = [auth]
    return Email.from_parser_json({
        "envelope": {"subject": subject, "from": [{"name": name, "address": frm, "domain": frm.split("@")[-1]}],
                     "date": "2025-01-01", "message_id": msgid, "return_path": rp},
        "headers": {"security": sec}, "routing": {"received": [{"hop": 1}]},
        "body": {"text_html": [html] if html else [], "text_plain": [text] if text else [], "combined": text or html},
        "attachments": atts or [], "indicators": {"urls": [], "href_text_mismatches": []},
    })


def ids(analyzer, email):
    return {f.id: f for f in analyzer.run(email, cfg)}


def att(name, data=b"x" * 50, binary=True, ct="application/octet-stream", payload=True):
    d = {"filename": name, "extension": "." + name.rsplit(".", 1)[-1].lower(), "content_type": ct,
         "is_binary": binary, "size_bytes": len(data), "hashes": {"sha256": "ab" * 32}}
    if payload:
        d["payload"] = base64.b64encode(data).decode() if binary else data.decode()
    return d


def zipped(names, **_):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n in names:
            z.writestr(n, "x")
    return b.getvalue()


# ------------------------- Phase 2 fixes ---------------------------------- #
def test_dmarc_pass_with_policy_none_is_quiet():
    e = mk(auth="mx.google.com; spf=pass; dkim=pass; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=x.com")
    assert Auth().run(e, cfg) == []

def test_google_message_id_is_not_a_mismatch():
    assert "headers.msgid_domain_mismatch" not in ids(Headers(), mk(msgid="<a@mx.google.com>", rp="<b@mail.gmail.com>"))

def test_onmicrosoft_is_shared_not_lookalike():
    r = ids(Sender(), mk(frm="abc123@gamers04.onmicrosoft.com"))
    assert "sender.shared_domain" in r and "sender.lookalike_domain" not in r


# ------------------------------- urls ------------------------------------- #
def test_urls_text_href_mismatch():
    r = ids(Urls(), mk(html='<a href="http://evil.example.net/x">www.paypal.com/login</a>'))
    assert r["url.text_href_mismatch"].confidence == 1.0

def test_urls_text_href_mismatch_weaker_in_newsletters():
    r = ids(Urls(), mk(html='<a href="https://track.esp.net/c">www.shop.com/sale</a>', bulk=True))
    assert r["url.text_href_mismatch"].confidence == 0.4

def test_urls_same_domain_text_is_fine():
    assert "url.text_href_mismatch" not in ids(Urls(), mk(html='<a href="https://www.shop.com/a">shop.com/a</a>'))

def test_urls_ip_and_obfuscated_ip():
    assert "url.ip_host" in ids(Urls(), mk(text="go http://185.1.2.3/login"))
    assert "url.ip_host" in ids(Urls(), mk(text="go http://2130706433/x"))

def test_urls_userinfo_trick():
    assert "url.userinfo_at" in ids(Urls(), mk(text="http://paypal.com@evil.net/"))

def test_urls_shortener_tld_https_keywords():
    r = ids(Urls(), mk(text="http://bit.ly/abc and https://secure-update.example.top/login/verify"))
    assert {"url.shortener", "url.suspicious_tld", "url.not_https", "url.login_keywords"} <= set(r)

def test_urls_lookalike_and_brand_in_subdomain():
    r = ids(Urls(), mk(text="https://paypa1-secure.com/a https://paypal.com.evil-site.net/b"))
    assert "url.lookalike_domain" in r and r["url.lookalike_domain"].evidence["count"] == 2

def test_urls_free_hosting_and_many_subdomains():
    r = ids(Urls(), mk(text="https://a.b.c.d.e.example.org/x https://myphish.pages.dev/z"))
    assert "url.free_hosting" in r and "url.many_subdomains" in r

def test_urls_own_and_legit_domains_are_quiet():
    r = ids(Urls(), mk(frm="news@shop.com", text="https://www.shop.com/login/verify https://www.google.com/account"))
    assert r == {}

def test_urls_never_crash_on_garbage():
    ids(Urls(), mk(text="http://[::1 http://%%% https://" + "a." * 500 + "com"))


# ---------------------------- attachments --------------------------------- #
def test_att_executable_and_double_extension():
    r = ids(Attachments(), mk(atts=[att("invoice.pdf.exe", b"MZ\x90" + b"0" * 50)]))
    assert {"attachment.executable", "attachment.double_extension"} <= set(r)

def test_att_spaced_double_extension():
    assert "attachment.double_extension" in ids(Attachments(), mk(atts=[att("invoice.pdf          .exe")]))

def test_att_rlo_spoof():
    assert "attachment.double_extension" in ids(Attachments(), mk(atts=[att("invoice\u202efdp.exe")]))

def test_att_disguised_program():
    r = ids(Attachments(), mk(atts=[att("report.pdf", b"MZ\x90\x00" + b"0" * 50)]))
    assert {"attachment.executable", "attachment.magic_mismatch"} <= set(r)

def test_att_real_pdf_is_clean():
    assert ids(Attachments(), mk(atts=[att("report.pdf", b"%PDF-1.7\n" + b"0" * 50)])) == {}

def test_att_macro_and_html():
    assert "attachment.macro_office" in ids(Attachments(), mk(atts=[att("budget.xlsm")]))
    assert "attachment.html_or_svg" in ids(Attachments(), mk(atts=[att("login.html", b"<html>", binary=False, ct="text/html")]))

def test_att_zip_with_exe_inside():
    r = ids(Attachments(), mk(atts=[att("docs.zip", zipped(["readme.txt", "invoice.scr"]))]))
    assert r["attachment.archive_with_exe"].evidence["attachments"][0]["inside"] == ["invoice.scr"]

def test_att_docx_with_vba_is_macro():
    r = ids(Attachments(), mk(atts=[att("memo.docx", zipped(["word/document.xml", "word/vbaProject.bin"]))]))
    assert "attachment.macro_office" in r

def test_att_encrypted_zip_flag():
    e = mk(atts=[att("x.zip", zipped(["a.txt"]))])
    e.attachments[0].encrypted = True
    assert "attachment.encrypted_archive" in ids(Attachments(), e)

def test_att_without_payload_still_checks_names():
    assert "attachment.executable" in ids(Attachments(), mk(atts=[att("setup.exe", payload=False)]))


# -------------------------------- body ------------------------------------ #
def test_body_urgency_credentials_greeting():
    r = ids(Body(), mk(text="Dear customer, urgent action required: verify your account and enter your password."))
    assert {"body.urgency_words", "body.credential_words", "body.generic_greeting"} <= set(r)

def test_body_french_accents_folded():
    assert "body.urgency_words" in ids(Body(), mk(text="Action requise immédiatement, dernier rappel"))

def test_body_clean_text():
    assert ids(Body(), mk(text="Hi Sam, lunch on Friday? Bring the slides.")) == {}

def test_body_password_form():
    r = ids(Body(), mk(html='<form action="http://evil.net/p"><input type="password" name="pw"></form>'))
    assert r["body.password_form"].evidence["external_action"] is True

def test_body_hidden_preheader_and_bulk_weakening():
    hidden = '<div style="display:none">' + "preheader " * 30 + "</div><p>Hello there</p>"
    assert ids(Body(), mk(html=hidden))["body.hidden_preheader"].confidence == 0.8
    assert ids(Body(), mk(html=hidden, bulk=True))["body.hidden_preheader"].confidence == 0.2
    assert "body.hidden_text" not in ids(Body(), mk(html=hidden))                  # small hidden text is not the big finding

def test_body_white_text_counts_as_hidden():
    html = '<p style="color:#ffffff">' + "viagra " * 30 + "</p><p>Visible</p>"
    assert "body.hidden_preheader" in ids(Body(), mk(html=html))

def test_body_image_only():
    assert "body.image_only" in ids(Body(), mk(html='<a href="http://x.example.net"><img src="cid:a"></a>'))

def test_html_parser_survives_bombs():
    info = parse_html("<div>" * 50_000 + "text" + "<a href=x>" * 5_000)
    assert len(info.links) <= 500


# --------------------- brand mentioned, links unrelated -------------------- #
def test_brand_mismatch_sample1_pattern():
    e = mk(subject="Seus pontos Bradesco expiram", frm="a@atendimento.com.br", name="Banco Bradesco",
           html='<a href="https://blog1seguiment.me/">Resgatar Agora</a><a href="https://blog1seguiment.me/">Clique aqui</a>')
    r = ids(Urls(), e)
    assert r["url.brand_mismatch"].confidence == 0.8

def test_brand_mismatch_not_when_a_link_goes_to_the_real_brand():
    e = mk(subject="Bradesco news", html='<a href="https://www.bradesco.com.br/">site</a><a href="https://other.me/">x</a>')
    assert "url.brand_mismatch" not in ids(Urls(), e)

def test_brand_mismatch_not_for_sender_own_links():
    e = mk(subject="Amazon web services tips", frm="n@aws-news.com", html='<a href="https://aws-news.com/a">read</a>')
    assert "url.brand_mismatch" not in ids(Urls(), e)

def test_brand_mismatch_weaker_for_newsletters():
    e = mk(subject="Bradesco offers", bulk=True, html='<a href="https://x.example.net/">a</a>')
    assert ids(Urls(), e)["url.brand_mismatch"].confidence == 0.4

def test_googleapis_is_not_a_google_lookalike():
    assert ids(Urls(), mk(text="https://fonts.googleapis.com/css2?family=X https://fonts.gstatic.com")) == {}

def test_body_apostrophes_and_portuguese_inflections():
    assert "body.urgency_words" in ids(Body(), mk(text="Votre offre expire aujourd'hui"))
    assert "body.urgency_words" in ids(Body(), mk(text="Pontos que expiram HOJE, Resgatar Agora"))


# ------------------ sample-5 pattern: callback scam, no links/attachments ---- #
S5 = ("Dear phishing@pot, This is an automated notification. Service Type: Premium Security Plan. Amount: $370.3. "
      "If you did not authorize this activity, please contact our security support team immediately. "
      "24/7 Security Support Hotline (813) 543 3428. Case ID: #33897467193")

def test_callback_lure_fires_on_sample5_pattern():
    r = ids(Body(), mk(html=f"<div>{S5}</div>"))
    assert r["body.callback_lure"].confidence == 0.9
    assert r["body.callback_lure"].evidence["phone"] == "(813) 543 3428"
    assert "body.generic_greeting" in r                              # "Dear <your e-mail address>"

def test_callback_lure_needs_phone_and_amount_and_call_words():
    assert "body.callback_lure" not in ids(Body(), mk(text="Call us at (813) 543 3428 for details."))
    assert "body.callback_lure" not in ids(Body(), mk(text="Amount: $370. Contact our support team."))

def test_plain_case_id_is_not_a_phone_number():
    assert "body.callback_lure" not in ids(Body(), mk(text="Amount $50. Contact our team. Case 33897467193"))

def test_callback_lure_softer_from_legit_sender():
    r = ids(Body(), mk(frm="billing@paypal.com", text=S5))
    assert r["body.callback_lure"].confidence < 0.5

def test_see_attached_but_nothing_attached():
    e = mk(subject="Review Requested: See Attached Transaction Document", text="hello")
    assert ids(Attachments(), e)["attachment.promised_missing"].confidence == 0.8
    assert ids(Attachments(), mk(subject="Re: See attached", text="x"))["attachment.promised_missing"].confidence == 0.4

def test_see_attached_with_real_attachment_is_fine():
    e = mk(subject="See attached", atts=[att("report.pdf", b"%PDF-1.7" + b"0" * 40)])
    assert "attachment.promised_missing" not in ids(Attachments(), e)

def test_freemail_two_word_brand_and_official_name():
    assert ids(Sender(), mk(name="Geek Squad Service", frm="x@gmail.com"))["sender.freemail_brand"].confidence == 1.0
    assert ids(Sender(), mk(name="Security Team", frm="x@gmail.com"))["sender.freemail_brand"].confidence == 0.6
    assert ids(Sender(), mk(name="Sam Support", frm="sam@company.org")) == {}

def test_xml_namespace_is_not_a_link():
    e = mk(html='<html xmlns="http://www.w3.org/1999/xhtml"><p>hello</p></html>')
    e.indicators.urls = ["http://www.w3.org/1999/xhtml"]
    assert ids(Urls(), e) == {}

def test_huge_hidden_gibberish_is_full_confidence_even_in_bulk():
    html = '<p>Hi</p><div style="display:none">' + "xQ7kP2" * 1500 + "</div>"
    assert ids(Body(), mk(html=html, bulk=True))["body.hidden_text"].confidence == 1.0


def test_callback_lure_is_not_softened_for_gmail_senders():
    assert ids(Body(), mk(frm="x@gmail.com", text=S5))["body.callback_lure"].confidence == 0.9
