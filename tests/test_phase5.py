"""Phase 5a: local blocklists (store, updater, analyzer, CLI) and the content fixes for free-mail scams."""
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from arer.analyzers.body import Body
from arer.analyzers.intel import Intel, domain_candidates
from arer.analyzers.sender import Sender
from arer.cli import main
from arer.config import FeedSource, load_config
from arer.intel import updater
from arer.intel.store import (DB_NAME, IntelStore, domain_key, normalize_domain, normalize_hash, normalize_url, url_key)
from arer.intel.updater import FeedError, parse_feed, update_all
from arer.models import Email
from arer.pipeline import run_pipeline
from arer.report import render_terminal

base_cfg = load_config()


def mk(frm="bob@example.com", name="Bob", subject="", text="", html="", reply_to=None, atts=None, bulk=False):
    sec = {"list-unsubscribe": ["<x>"]} if bulk else {}
    return Email.from_parser_json({
        "envelope": {"subject": subject, "date": "2025-01-01", "message_id": "<1@example.com>",
                     "from": [{"name": name, "address": frm, "domain": frm.split("@")[-1]}],
                     "reply_to": [{"name": "", "address": reply_to, "domain": reply_to.split("@")[-1]}] if reply_to else []},
        "headers": {"security": sec}, "routing": {"received": [{"hop": 1}]},
        "body": {"text_plain": [text] if text else [], "text_html": [html] if html else [], "combined": text or html},
        "attachments": atts or []})


def ids(analyzer, email, cfg=base_cfg):
    return {f.id: f for f in analyzer.run(email, cfg)}


# ------------------------------ normalisation -------------------------------- #
def test_url_normalisation_makes_variants_equal():
    a = normalize_url("HTTPS://Evil.Example.com:443/Login/Verify?id=A#top")
    assert a == "evil.example.com/Login/Verify?id=A"                 # path/query case kept, host lowered
    assert normalize_url("http://evil.example.com/Login/Verify?id=A") == a      # http == https
    assert normalize_url("http://user:pw@evil.example.com/Login/Verify?id=A") == a   # user-info dropped
    assert normalize_url("evil.example.com") == "evil.example.com/"             # feeds sometimes omit the scheme
    assert normalize_url("http://evil.example.com:8080/x") == "evil.example.com:8080/x"
    assert normalize_url("javascript:alert(1)") is None and normalize_url("") is None
    assert normalize_url("http://" + "a" * 5000) is None
    assert normalize_url("not a url ###") is None and normalize_url("<html>503 error</html>") is None

def test_domain_and_hash_normalisation():
    assert normalize_domain("*.Evil-Site.NET.") == "evil-site.net"
    assert normalize_domain("localhost") is None and normalize_domain("bad domain.com") is None
    assert normalize_hash(("AB" * 32)) == "ab" * 32 and normalize_hash("xyz") is None

def test_parse_feed_skips_junk():
    data = b"# comment\n\nhttp://evil.example.net/a\nnot a url ###\nhttps://evil.example.net/a\nftp://x.example.org/f\n"
    assert len(parse_feed(data, "url")) == 2                         # the http/https duplicate collapses


# ------------------------------ end to end ----------------------------------- #
FEEDS = {
    "https://feeds.test/links.txt": b"http://evil-phish.example.net/login/verify?id=7\nhttp://other.example.org/x\n",
    "https://feeds.test/domains.txt": b"evil-domain.example.net\nbad-sender.example.org\nevil.github.io\ngithub.io\ngoogle.com\n",
}

@pytest.fixture
def cfg(tmp_path):
    c = base_cfg.model_copy(deep=True)
    c.feeds.data_dir = tmp_path / "feeds"
    (tmp_path / "hashes.txt").write_text("# my bad files\n" + "ab" * 32 + "  dropper.exe\n")
    c.feeds.sources = {
        "links": FeedSource(url="https://feeds.test/links.txt", kind="url"),
        "doms": FeedSource(url="https://feeds.test/domains.txt", kind="domain"),
        "mine": FeedSource(path=str(tmp_path / "hashes.txt"), kind="hash"),
        "off": FeedSource(url="https://feeds.test/off.txt", kind="url", enabled=False),
    }
    return c

def fake_fetch(url, max_bytes):
    return FEEDS[url]

@pytest.fixture
def built(cfg):
    res = update_all(cfg, fetch=fake_fetch)
    assert all(r.ok for r in res) and {r.name for r in res} == {"links", "doms", "mine"}      # 'off' not touched
    return cfg

def test_exact_url_hit_is_malicious_via_override(built):
    e = mk(text="Please verify: https://EVIL-PHISH.example.net/login/verify?id=7 now")       # https + upper-case host
    f = ids(Intel(), e, built)
    assert "url.on_blocklist" in f and f["url.on_blocklist"].evidence["sources"] == ["links"]
    v = run_pipeline(e, built, analyzers=[Intel()])
    assert v.level.value == "MALICIOUS" and v.overridden_by == "url.on_blocklist"

def test_different_path_on_same_host_is_not_an_exact_hit(built):
    assert "url.on_blocklist" not in ids(Intel(), mk(text="http://evil-phish.example.net/other"), built)

def test_domain_hit_covers_subdomains_but_scores_lower(built):
    f = ids(Intel(), mk(text="http://login.secure.evil-domain.example.net/a"), built)
    assert f["url.domain_on_blocklist"].confidence == 0.9 and "url.on_blocklist" not in f

def test_shared_hosts_match_only_the_exact_listed_subdomain(built):
    assert "url.domain_on_blocklist" in ids(Intel(), mk(text="https://evil.github.io/a"), built)
    assert "url.domain_on_blocklist" not in ids(Intel(), mk(text="https://innocent.github.io/a"), built)   # 'github.io' is listed but protected

def test_legit_domains_are_never_condemned_by_a_bad_entry(built):
    assert "url.domain_on_blocklist" not in ids(Intel(), mk(text="https://www.google.com/maps"), built)

def test_sender_domain_on_blocklist_but_never_free_mail(built):
    assert "sender.on_blocklist" in ids(Intel(), mk(frm="x@bad-sender.example.org"), built)
    assert "sender.on_blocklist" not in ids(Intel(), mk(frm="x@gmail.com"), built)

def test_attachment_hash_list(built):
    atts = [{"filename": "invoice.pdf", "hashes": {"sha256": "AB" * 32}, "size_bytes": 1}]
    e = mk(atts=atts)
    assert "attachment.known_malicious_hash" in ids(Intel(), e, built)
    assert run_pipeline(e, built, analyzers=[Intel()]).level.value == "MALICIOUS"

def test_clean_mail_has_no_findings(built):
    assert ids(Intel(), mk(text="lunch at https://example.com/menu ?"), built) == {}

def test_missing_and_disabled(cfg, tmp_path):
    assert set(ids(Intel(), mk(), cfg)) == {"intel.feeds_missing"}
    c = cfg.model_copy(deep=True); c.feeds.sources = {}
    assert ids(Intel(), mk(), c) == {}

def test_stale_data_is_reported(built):
    conn = sqlite3.connect(str(built.feeds.data_dir / DB_NAME))
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    conn.execute("UPDATE sources SET fetched_at=? WHERE name='links'", (old,)); conn.commit(); conn.close()
    f = ids(Intel(), mk(), built)
    assert "intel.feeds_stale" in f and "links" in f["intel.feeds_stale"].summary and "30 days" in f["intel.feeds_stale"].summary

def test_notices_never_add_points_or_clutter_the_report(cfg):
    e = mk()
    v = run_pipeline(e, cfg, analyzers=[Intel()])
    assert v.score == 0 and any(f.id == "intel.feeds_missing" for f in v.findings)
    assert " intel " not in render_terminal(v, cfg).split("Findings")[0]       # no "intel 0 / 0" row

def test_domain_candidates_walk_parents_unless_protected():
    no = lambda r: False
    assert domain_candidates("a.b.evil.com", no, no) == ["a.b.evil.com", "b.evil.com", "evil.com"]
    assert domain_candidates("a.b.github.io", no, lambda r: r == "github.io") == ["a.b.github.io"]
    assert domain_candidates("github.io", no, lambda r: r == "github.io") == []             # the shared host itself
    assert domain_candidates("www.bit.ly", lambda r: r == "bit.ly", no) == []               # protected: never

# the live feed really lists https://www.amazon.com/ and bit.ly, so these rules are tested explicitly
FEEDS["https://feeds.test/links.txt"] += (b"https://www.amazon.com/\nhttps://www.notion.so/\nhttps://drive.google.com/file/d/ABC123/view\n"
                                          b"http://6.6.6.6/\n")
FEEDS["https://feeds.test/domains.txt"] += b"bit.ly\ndocs.google.com\n"

def test_listed_root_page_of_a_protected_site_is_ignored(built):
    assert ids(Intel(), mk(text="shop at https://www.amazon.com/ today"), built) == {}

def test_listed_root_page_of_an_unprotected_site_is_domain_strength_only(built):
    f = ids(Intel(), mk(text="visit https://www.notion.so/ now"), built)
    assert "url.domain_on_blocklist" in f and "url.on_blocklist" not in f
    v = run_pipeline(mk(text="visit https://www.notion.so/ now"), built, analyzers=[Intel()])
    assert v.level.value != "MALICIOUS" and v.overridden_by is None

def test_listed_root_ip_url_counts_as_a_bad_domain(built):
    assert "url.domain_on_blocklist" in ids(Intel(), mk(text="http://6.6.6.6/"), built)

def test_listed_specific_page_on_a_protected_site_still_hits(built):
    assert "url.on_blocklist" in ids(Intel(), mk(text="https://drive.google.com/file/d/ABC123/view"), built)
    assert "url.on_blocklist" not in ids(Intel(), mk(text="https://drive.google.com/file/d/OTHER/view"), built)

def test_bare_shortener_listed_as_a_domain_is_ignored(built):
    assert ids(Intel(), mk(text="short link https://bit.ly/3abcdef"), built) == {}
    assert "sender.on_blocklist" not in ids(Intel(), mk(frm="x@bit.ly"), built)

def test_listed_platform_hostname_does_not_condemn_all_its_links(built):
    assert ids(Intel(), mk(text="notes https://docs.google.com/document/d/xyz/edit"), built) == {}


# ------------------------------ updater safety -------------------------------- #
def test_shrunken_feed_is_refused_and_old_data_kept(built):
    big = {"https://feeds.test/links.txt": b"\n".join(f"http://evil{i}.example.net/p".encode() for i in range(100)),
           "https://feeds.test/domains.txt": FEEDS["https://feeds.test/domains.txt"]}
    update_all(built, ["links"], fetch=lambda u, m: big[u])
    tiny = lambda u, m: b"http://only-one.example.net/p\n"
    r = update_all(built, ["links"], fetch=tiny)[0]
    assert not r.ok and "REFUSED" in r.message
    store = IntelStore.open(built.feeds.data_dir)
    assert url_key(normalize_url("http://evil7.example.net/p")) in store.lookup([url_key(normalize_url("http://evil7.example.net/p"))])

def test_garbage_feed_is_refused(built):
    r = update_all(built, ["doms"], fetch=lambda u, m: b"<html>503 Service Unavailable</html>")[0]
    assert not r.ok and "no valid entries" in r.message
    assert domain_key("evil-domain.example.net") in IntelStore.open(built.feeds.data_dir).lookup([domain_key("evil-domain.example.net")])

def test_download_errors_do_not_crash(built):
    def boom(u, m): raise FeedError("HTTP 503")
    r = update_all(built, ["links"], fetch=boom)[0]
    assert not r.ok and r.message == "HTTP 503"

def test_unknown_feed_name(built):
    assert not update_all(built, ["nope"], fetch=fake_fetch)[0].ok

def test_fetch_refuses_plain_http():
    with pytest.raises(FeedError):
        updater.default_fetch("http://feeds.test/x.txt", 1000)

def test_redirect_to_another_host_is_refused():
    h = updater._SameHostHttps()
    req = urllib.request.Request("https://feeds.test/a")
    with pytest.raises(FeedError):
        h.redirect_request(req, None, 302, "Found", {}, "https://evil.example.net/a")
    with pytest.raises(FeedError):
        h.redirect_request(req, None, 302, "Found", {}, "http://feeds.test/a")

def test_database_file_is_private(built):
    import os, stat
    assert stat.S_IMODE(os.stat(built.feeds.data_dir / DB_NAME).st_mode) == 0o600


# ------------------------------------ CLI ------------------------------------- #
def test_cli_feeds_status_and_update(tmp_path, monkeypatch):
    env = {"PHISHSCOPE_FEEDS": str(tmp_path / "f")}
    monkeypatch.setattr(updater, "default_fetch", lambda url, max_bytes: b"evil-a.example.net\nevil-b.example.net\n")
    r = CliRunner().invoke(main, ["feeds", "status"], env=env)
    assert r.exit_code == 0 and "never" in r.output and "not built yet" in r.output
    r = CliRunner().invoke(main, ["feeds", "update", "phishing_db_domains"], env=env)
    assert r.exit_code == 0 and "[ok]" in r.output and "2 entries" in r.output
    r = CliRunner().invoke(main, ["feeds", "status"], env=env)
    assert "0d" in r.output and "2" in r.output

def test_cli_openphish_licence_reminder(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "default_fetch", lambda url, max_bytes: b"http://x.example.net/a\n")
    r = CliRunner().invoke(main, ["feeds", "update", "openphish"], env={"PHISHSCOPE_FEEDS": str(tmp_path)})
    assert "NON-COMMERCIAL" in r.output


# --------------------- content fixes for free-mail scams ----------------------- #
def test_reply_to_other_mailbox_on_same_free_provider():
    f = ids(Sender(), mk(frm="edmond@gmail.com", reply_to="mrjeffrey@gmail.com"))["sender.reply_to_mismatch"]
    assert f.confidence == 1.0 and "different mailbox" in f.summary
    assert "sender.reply_to_mismatch" not in ids(Sender(), mk(frm="a@gmail.com", reply_to="A@GMAIL.com"))

def test_same_domain_other_mailbox_is_fine_for_a_company():
    assert "sender.reply_to_mismatch" not in ids(Sender(), mk(frm="sales@company.com", reply_to="support@company.com"))

S107 = ("Dear E-mail Owner, My name is Jeff Bezos, an American, investor, and charity donor. Your email address has "
        "won you( $2.500,000.00 )Kindly get back to me,so I know your email address is valid.")

def test_sample107_pattern_is_caught_end_to_end():
    e = mk(frm="edmond@gmail.com", name="MR. JEFFREY BEZOS", subject="YOUR $2.500,000.00", text=S107, reply_to="mrjeffrey@gmail.com")
    v = run_pipeline(e, base_cfg)
    assert v.level.value in ("SUSPICIOUS", "LIKELY_PHISHING") and v.score >= 20
    assert {"body.prize_lure", "sender.reply_to_mismatch", "body.generic_greeting"} <= {f.id for f in v.findings}

def test_prize_lure_confidence_and_attachment_names():
    assert ids(Body(), mk(text="You have won a free coffee"))["body.prize_lure"].confidence == 0.5
    assert "body.prize_lure" not in ids(Body(), mk(text="Lunch on Friday, please bring the slides."))
    att = [{"filename": "1.BTC.Jackpot.in.a.win-win.lottery-84.pdf", "extension": ".pdf", "is_binary": True, "size_bytes": 5}]
    assert ids(Body(), mk(text="hi", atts=att))["body.prize_lure"].confidence == 1.0

def test_obfuscated_subject():
    assert "body.obfuscated_subject" in ids(Body(), mk(subject="Now.get.up.to.1.BTC"))
    for ok in ("com.example.app.release", "Meeting notes v2.1", "Q3.report.final.pdf", "192.168.1.10.log"):
        assert "body.obfuscated_subject" not in ids(Body(), mk(subject=ok)), ok

def test_dear_email_owner_greeting():
    assert "body.generic_greeting" in ids(Body(), mk(text="Dear E-mail Owner, hello"))


def test_disabled_feed_is_ignored_even_if_downloaded(cfg):
    update_all(cfg, ["links", "doms", "mine", "off"], fetch=lambda u, m: FEEDS.get(u, b"http://only-in-off.example.net/p\n"))
    assert ids(Intel(), mk(text="http://only-in-off.example.net/p"), cfg) == {}                # 'off' is disabled
    cfg.feeds.sources["off"].enabled = True
    assert "url.on_blocklist" in ids(Intel(), mk(text="http://only-in-off.example.net/p"), cfg)

def test_eval_ignores_zero_weight_notices(tmp_path, cfg):
    from arer.evaluate import evaluate, render
    for label in ("phish", "legit"):
        d = tmp_path / label; d.mkdir()
        (d / "a.eml").write_bytes(b"From: A <a@example.org>\nTo: b@example.org\nSubject: " + label.encode() + b"\nDate: Mon, 05 Jan 2026 09:00:00 +0000\n\nhello\n")
    out = render(evaluate(tmp_path, cfg), cfg)
    assert "intel.feeds_missing" not in out
