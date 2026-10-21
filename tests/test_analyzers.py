"""Tests for the Phase 2 analyzers (auth, sender, headers) and util/domains."""
import pytest

from arer.analyzers.auth import Auth, parse_auth_results
from arer.analyzers.headers import Headers
from arer.analyzers.sender import Sender
from arer.config import load_config
from arer.models import Email
from arer.util.domains import lookalike, registrable, normalize_confusables

cfg = load_config()


def mk(name="Bob", addr="bob@example.com", reply_to=None, auth=None, spf=None, date="2025-01-01T00:00:00",
       msgid="<1@example.com>", return_path="<bob@example.com>", hops=2, bulk=False, mailer=""):
    sec = {}
    if auth is not None:
        sec["authentication-results"] = auth if isinstance(auth, list) else [auth]
    if spf:
        sec["received-spf"] = [spf]
    if bulk:
        sec["list-unsubscribe"] = ["<mailto:u@example.com>"]
    raw = {
        "envelope": {"from": [{"name": name, "address": addr, "domain": addr.rsplit("@", 1)[-1]}],
                     "reply_to": [{"name": "", "address": reply_to, "domain": reply_to.rsplit("@", 1)[-1]}] if reply_to else [],
                     "date": date, "message_id": msgid, "return_path": return_path, "x_mailer": mailer},
        "headers": {"security": sec},
        "routing": {"received": [{"hop": i + 1} for i in range(hops)]},
        "body": {"combined": "hello"},
    }
    return Email.from_parser_json(raw)


def ids(analyzer, email, conf_of=None):
    found = analyzer.run(email, cfg)
    return {f.id: f.confidence for f in found}


# ------------------------------- domains ---------------------------------- #
def test_registrable_offline():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    assert registrable("mail.google.com") == "google.com"
    assert registrable("ubuntu-s-1vcpu") == "ubuntu-s-1vcpu"      # bare host stays as is

def test_confusables():
    assert normalize_confusables("paypa1") == "paypal"
    assert normalize_confusables("rnicrosoft") == "microsoft"

@pytest.mark.parametrize("host,kind", [
    ("paypa1.com", "homoglyph"), ("paypal-secure.com", "brand_plus_words"),
    ("paypall.com", "typosquat"), ("securepaypal.com", "contains_brand"),
    ("paypal.top", "brand_wrong_tld"), ("xn--pypal-4ve.com", None)])
def test_lookalike_kinds(host, kind):
    r = lookalike(host, cfg.lists["brands"], cfg.lists["legit_domains"], cfg.lists["suspicious_tlds"])
    assert (r.kind if r else None) == kind or (host.startswith("xn--"))

@pytest.mark.parametrize("host", ["paypal.com", "microsoftonline.com", "mail.google.com", "example.com", "pineapple.com"])
def test_lookalike_clean(host):
    assert lookalike(host, cfg.lists["brands"], cfg.lists["legit_domains"], cfg.lists["suspicious_tlds"]) is None


# -------------------------------- auth ------------------------------------ #
GOOD = "mx.google.com; dkim=pass header.i=@x.com; spf=pass (google.com: ok) smtp.mailfrom=x.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=x.com"

def test_auth_all_pass_is_quiet():
    assert ids(Auth(), mk(auth=GOOD)) == {}

def test_auth_failures():
    r = ids(Auth(), mk(auth="mx.corp.test; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail"))
    assert set(r) == {"auth.spf_fail", "auth.dkim_none", "auth.dmarc_fail"}

def test_auth_temperror_is_unknown_not_fail():
    r = ids(Auth(), mk(auth="spf=temperror (sender IP is 1.2.3.4) smtp.mailfrom=x; dkim=none; dmarc=none"))
    assert "auth.spf_fail" not in r and "auth.dmarc_no_policy" in r

def test_auth_forged_lower_stamp_is_ignored():
    real = "mx.corp.test; spf=fail; dkim=fail; dmarc=fail"
    forged = "attacker.example; spf=pass; dkim=pass; dmarc=pass"
    r = ids(Auth(), mk(auth=[real, forged]))                  # topmost first
    assert {"auth.spf_fail", "auth.dmarc_fail"} <= set(r)

def test_auth_forged_text_inside_comment_is_ignored():
    r = ids(Auth(), mk(auth="mx.corp.test; spf=fail (spf=pass dkim=pass); dkim=none; dmarc=pass"))
    assert "auth.spf_fail" in r

def test_auth_trusted_server_selection():
    c2 = cfg.model_copy(deep=True); c2.auth.trusted_authserv_ids = ["mx.google.com"]
    both = ["attacker.example; spf=pass; dkim=pass; dmarc=pass", "mx.google.com; spf=fail; dkim=pass; dmarc=fail"]
    assert "auth.spf_fail" in {f.id for f in Auth().run(mk(auth=both), c2)}
    only_fake = {f.id for f in Auth().run(mk(auth="attacker.example; spf=pass; dkim=pass; dmarc=pass"), c2)}
    assert only_fake == {"auth.results_missing"}

def test_auth_missing_everything():
    assert set(ids(Auth(), mk())) == {"auth.results_missing"}

def test_auth_received_spf_fallback():
    r = ids(Auth(), mk(spf="Fail (domain does not designate ...)"))
    assert r == {"auth.spf_fail": 0.8}

def test_parse_microsoft_style_has_no_authserv():
    p = parse_auth_results("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.com; dkim=pass; dmarc=pass action=none")
    assert p.authserv == "" and p.spf == "pass" and p.dmarc == "pass"


# ------------------------------- sender ----------------------------------- #
def test_sender_clean():
    assert ids(Sender(), mk()) == {}

def test_sender_reply_to_and_bulk_weakening():
    assert ids(Sender(), mk(reply_to="x@evil.example"))["sender.reply_to_mismatch"] == 1.0
    assert ids(Sender(), mk(reply_to="x@evil.example", bulk=True))["sender.reply_to_mismatch"] == 0.4

def test_sender_reply_to_same_org_subdomain_ok():
    assert "sender.reply_to_mismatch" not in ids(Sender(), mk(reply_to="support@mail.example.com"))

def test_sender_display_name_shows_other_address():
    assert "sender.display_name_spoof" in ids(Sender(), mk(name="support@paypal.com", addr="x@evil.com"))

def test_sender_brand_display_name_spoof():                  # your sample-1 pattern
    r = ids(Sender(), mk(name="BANCO DO BRADESCO LIVELO", addr="banco.bradesco@atendimento.com.br"))
    assert r["sender.display_name_spoof"] == 1.0

def test_sender_legit_brand_not_flagged():
    assert ids(Sender(), mk(name="PayPal Support", addr="service@paypal.com")) == {}
    assert ids(Sender(), mk(name="Google", addr="no-reply@accounts.google.com")) == {}

def test_sender_common_first_name_is_weak():
    r = ids(Sender(), mk(name="Chase Smith", addr="chase@company.org"))
    assert r.get("sender.display_name_spoof") == 0.5

def test_sender_freemail_brand():
    assert "sender.freemail_brand" in ids(Sender(), mk(name="PayPal Support", addr="help123@gmail.com"))

def test_sender_lookalike_and_punycode():
    r = ids(Sender(), mk(name="Billing", addr="billing@paypa1-secure.com"))
    assert r["sender.lookalike_domain"] == 1.0
    assert "sender.punycode_domain" in ids(Sender(), mk(addr="a@xn--pypal-4ve.com"))

def test_sender_invalid_format():
    assert "sender.invalid_format" in ids(Sender(), mk(addr="not an address@x"))


# ------------------------------- headers ---------------------------------- #
def test_headers_clean():
    assert ids(Headers(), mk()) == {}

def test_headers_bare_hostname_message_id():                  # your sample-1 pattern
    r = ids(Headers(), mk(msgid="<abc@ubuntu-s-1vcpu-1gb-35gb>", return_path="<x@ubuntu-s-1vcpu-1gb-35gb>"))
    assert r["headers.msgid_domain_mismatch"] == 0.8 and "headers.returnpath_mismatch" in r

def test_headers_bulk_lowers_confidence():
    r = ids(Headers(), mk(msgid="<1@esp.net>", return_path="<b@esp.net>", bulk=True))
    assert r["headers.msgid_domain_mismatch"] == 0.3 and r["headers.returnpath_mismatch"] == 0.2

def test_headers_hops_mailer_date():
    assert "headers.missing_received" in ids(Headers(), mk(hops=0))
    assert "headers.high_hop_count" in ids(Headers(), mk(hops=9))
    assert "headers.suspicious_mailer" in ids(Headers(), mk(mailer="PHPMailer 6.0"))
    assert "headers.missing_date" in ids(Headers(), mk(date=""))
