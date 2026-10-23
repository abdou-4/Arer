"""Tests for the eval-driven fixes (bulk detection, graded invalid_format, trackers, keywords, extension-less files)."""
import subprocess
import sys
from pathlib import Path

from arer.analyzers.headers import Headers
from arer.analyzers.sender import Sender
from arer.analyzers.urls import Urls
from arer.config import load_config
from arer.evaluate import evaluate
from arer.loader import is_mail_candidate, load_any
from arer.models import Email

cfg = load_config()
ROOT = Path(__file__).resolve().parents[1]


def mk(frm="bob@example.com", name="Bob", html="", text="", raw_headers=None, reply_to=None,
       msgid="<1@example.com>", rp="<bob@example.com>"):
    return Email.from_parser_json({
        "envelope": {"from": [{"name": name, "address": frm, "domain": frm.split("@")[-1]}] if frm else [],
                     "reply_to": [{"name": "", "address": reply_to, "domain": reply_to.split("@")[-1]}] if reply_to else [],
                     "date": "2025-01-01", "message_id": msgid, "return_path": rp},
        "headers": {"raw_ordered": raw_headers or [], "security": {}},
        "routing": {"received": [{"hop": 1}]},
        "body": {"text_html": [html] if html else [], "text_plain": [text] if text else [], "combined": text or html},
    })


def ids(analyzer, email):
    return {f.id: f for f in analyzer.run(email, cfg)}


# --- mailing lists are bulk ------------------------------------------------ #
def test_list_id_and_precedence_make_mail_bulk():
    assert mk(raw_headers=[["List-Id", "<satalk.example.org>"]]).is_bulk
    assert mk(raw_headers=[["Precedence", "bulk"]]).is_bulk
    assert mk(raw_headers=[["Precedence", "list"]]).is_bulk
    assert not mk(raw_headers=[["Precedence", "first-class"]]).is_bulk
    assert not mk().is_bulk

def test_mailing_list_softens_reply_to_and_message_id():
    lst = [["List-Id", "<talk.lists.example.org>"]]
    e = mk(reply_to="talk@lists.example.org", msgid="<1@lists.example.org>", rp="<talk-bounces@lists.example.org>", raw_headers=lst)
    assert ids(Sender(), e)["sender.reply_to_mismatch"].confidence == 0.4
    assert ids(Headers(), e)["headers.msgid_domain_mismatch"].confidence == 0.3


# --- graded invalid_format -------------------------------------------------- #
def test_unusual_from_keeps_full_strength():
    r = ids(Sender(), mk(frm="root@localhost"))["sender.invalid_format"]
    assert r.confidence == 1.0 and "unusual" in r.summary
    assert ids(Sender(), mk(frm="a@mail_server.example.com"))["sender.invalid_format"].confidence == 1.0

def test_missing_from_is_strong():
    r = ids(Sender(), mk(frm=None))
    assert r["sender.invalid_format"].confidence == 1.0

def test_normal_from_is_quiet():
    assert "sender.invalid_format" not in ids(Sender(), mk(frm="a@example.com"))


# --- click-trackers and login keywords -------------------------------------- #
def test_tracking_redirect_is_softened_not_ignored():
    html = '<a href="http://click.esp.net/?u=http%3A%2F%2Fwww.shop.com%2Fsale">www.shop.com/sale</a>'
    f = ids(Urls(), mk(html=html))["url.text_href_mismatch"]
    assert f.confidence == 0.3 and "click-tracker" in f.summary

def test_real_mismatch_still_full_strength():
    html = '<a href="http://evil.example.net/x">www.paypal.com/login</a>'
    assert ids(Urls(), mk(html=html))["url.text_href_mismatch"].confidence == 1.0

def test_login_keywords_strong_vs_weak():
    assert "url.login_keywords" in ids(Urls(), mk(text="https://x.example.net/user/login"))
    assert "url.login_keywords" not in ids(Urls(), mk(text="https://x.example.net/account/settings"))
    assert "url.login_keywords" not in ids(Urls(), mk(text="https://x.example.net/mailman/confirm"))
    assert "url.login_keywords" in ids(Urls(), mk(text="https://x.example.net/secure/account"))


# --- files without .eml ------------------------------------------------------ #
RAW = b"From: A <a@example.org>\nTo: b@example.org\nSubject: hi\nDate: Mon, 05 Jan 2026 09:00:00 +0000\n\nbody\n"

def test_extensionless_spamassassin_style_names_are_found(tmp_path):
    f = tmp_path / "legit" / "00001.7c53336b37003a9286aba55d2945844c"
    f.parent.mkdir(); f.write_bytes(RAW)
    (tmp_path / "legit" / "notes.txt").write_text("From: not mail but a text file")
    (tmp_path / "legit" / ".gitkeep").write_text("")
    assert is_mail_candidate(f) and not is_mail_candidate(tmp_path / "legit" / "notes.txt")
    assert not is_mail_candidate(tmp_path / "legit" / ".gitkeep")
    assert load_any(f).from_domain == "example.org"

def test_eval_counts_extensionless_files(tmp_path):
    (tmp_path / "legit").mkdir(); (tmp_path / "phish").mkdir()
    (tmp_path / "legit" / "00001.abc123").write_bytes(RAW)
    (tmp_path / "phish" / "p.eml").write_bytes(RAW.replace(b"hi", b"verify now"))
    assert len(evaluate(tmp_path, cfg).results) == 2


# --- mbox sampling script ---------------------------------------------------- #
def make_mbox(path):
    import mailbox
    mb = mailbox.mbox(str(path))
    for i, labels in enumerate(["Inbox,Important", "Inbox", "Spam", "Sent", "Inbox,Trash", "Inbox", "Inbox"]):
        raw = (f"From: s{i}@example.org\nTo: me@gmail.com\nSubject: m{i}\nX-Gmail-Labels: {labels}\n"
               f"Authentication-Results: mx.google.com; spf=pass\nDate: Mon, 05 Jan 2026 09:00:00 +0000\n\nhello {i}\n")
        mb.add(raw.encode())
    mb.flush(); mb.close()

def test_mbox_script_samples_inbox_only(tmp_path):
    make_mbox(tmp_path / "t.mbox")
    out = tmp_path / "legit"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "mbox_to_eml.py"), str(tmp_path / "t.mbox"),
                        "-o", str(out), "--count", "10"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    files = sorted(out.glob("mine_*.eml"))
    assert len(files) == 4                                   # Inbox only; Spam, Sent and Trash excluded
    assert all(b"Subject: m" in f.read_bytes() for f in files)
    assert not any(b"Subject: m2" in f.read_bytes() or b"Subject: m3" in f.read_bytes() or b"Subject: m4" in f.read_bytes() for f in files)

def test_mbox_script_never_exports_the_same_message_twice(tmp_path):
    make_mbox(tmp_path / "t.mbox"); out = tmp_path / "o"
    cmd = [sys.executable, str(ROOT / "scripts" / "mbox_to_eml.py"), str(tmp_path / "t.mbox"), "-o", str(out), "--count", "2"]
    subprocess.run(cmd, check=True, capture_output=True)
    first = {p.read_bytes() for p in out.glob("*.eml")}
    r = subprocess.run(cmd, check=True, capture_output=True, text=True)
    everything = [p.read_bytes() for p in out.glob("*.eml")]
    assert len(everything) == 4 and len(set(everything)) == 4          # 2 new, 0 duplicates
    assert first < set(everything) and "already exported" in r.stdout
    assert sorted(p.name for p in out.glob("*.eml")) == ["mine_0001.eml", "mine_0002.eml", "mine_0003.eml", "mine_0004.eml"]
