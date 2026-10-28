"""Phase 5b: private history (store, indicators, analyzer, re-scoring, eval, CLI)."""
import os
import shutil
import stat

import pytest
from click.testing import CliRunner

from arer.analyzers.history import History
from arer.analyzers.sender import Sender
from arer.cli import main
from arer.config import load_config
from arer.evaluate import evaluate, evaluate_history, render
from arer.history.indicators import addr_hash, extract_indicators
from arer.history.store import HistoryStore, logic_hash, rescore
from arer.models import Email
from arer.pipeline import run_pipeline

base_cfg = load_config()
N = [0]


def mk(frm="bob@example.com", name="Bob", text="hello", sha=None, atts=None, subject="s"):
    N[0] += 1
    sha = sha or f"{N[0]:064x}"
    return Email.from_parser_json({
        "file": {"hashes": {"sha256": sha}, "name": f"m{N[0]}.eml"},
        "envelope": {"subject": subject, "date": "2025-01-01", "message_id": "<1@example.com>",
                     "from": [{"name": name, "address": frm, "domain": frm.split("@")[-1]}]},
        "headers": {"security": {}}, "routing": {"received": [{"hop": 1}]},
        "body": {"text_plain": [text], "combined": text}, "attachments": atts or []})


@pytest.fixture
def cfg(tmp_path):
    c = base_cfg.model_copy(deep=True)
    c.history.db_path = tmp_path / "h" / "history.db"
    c.history.min_scans = 3
    return c


def save(cfg, email, label=None, analyzers=None):
    v = run_pipeline(email, cfg, analyzers=analyzers if analyzers is not None else [Sender()])
    s = HistoryStore.open(cfg.history.db_path, create=True)
    s.save_scan(v.sha256, email.file.name or "x.eml", email, v, extract_indicators(email, cfg), logic_hash(cfg))
    if label:
        s.set_label(v.sha256, label)
    s.close()
    return v


def findings(email, cfg):
    return {f.id: f for f in History().run(email, cfg)}


# --------------------------------- indicators ---------------------------------- #
def test_indicators_carry_no_content(cfg):
    e = mk(frm="Secret.Person@Example.com", text="see https://login.evil.github.io/a and https://www.shop.example.net/x http://6.6.6.6/p",
           atts=[{"filename": "a.pdf", "hashes": {"sha256": "AB" * 32}}])
    ind = extract_indicators(e, cfg)
    assert ("sender_addr", addr_hash("secret.person@example.com")) in ind
    assert not any("secret" in v.lower() for _, v in ind)                       # the address itself is never stored
    assert ("sender_domain", "example.com") in ind
    assert ("link_domain", "login.evil.github.io") in ind                      # shared host: full name
    assert ("link_domain", "example.net") in ind                               # normal host: registrable domain
    assert not any(v.startswith("6.6.6") for _, v in ind)                      # bare IPs are not domains
    assert ("attachment_sha256", "ab" * 32) in ind


# ------------------------------------ store ------------------------------------ #
def test_save_refresh_label_resolve_forget(cfg):
    e = mk(frm="a@example.org")
    save(cfg, e)
    save(cfg, e)                                                               # same e-mail again
    s = HistoryStore.open(cfg.history.db_path)
    sha = e.file.sha256
    assert s.get(sha).times == 2 and s.total_scans() == 1
    assert s.resolve(sha[:10]) == sha and s.resolve(sha[:3]) is None
    assert s.set_label(sha, "phish", "why") and s.get(sha).label == "phish"
    save(cfg, e)
    assert HistoryStore.open(cfg.history.db_path).get(sha).label == "phish"      # a rescan keeps your label
    with pytest.raises(ValueError):
        s.set_label(sha, "maybe")
    assert s.forget(sha) and s.get(sha) is None
    assert s.conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 0   # nothing left behind

def test_database_is_private_and_versioned(cfg):
    save(cfg, mk())
    assert stat.S_IMODE(os.stat(cfg.history.db_path).st_mode) == 0o600
    assert HistoryStore.open(cfg.history.db_path / "nope") is None
    import sqlite3
    c = sqlite3.connect(cfg.history.db_path); c.execute("UPDATE meta SET value='99'"); c.commit(); c.close()
    assert HistoryStore.open(cfg.history.db_path) is None                      # unknown schema: refuse, don't guess

def test_no_bodies_subjects_or_recipients_are_stored(cfg):
    e = mk(text="SECRET-BODY-TEXT click https://phish.example.net/x", subject="SECRET-SUBJECT")
    save(cfg, e, analyzers=None)
    raw = open(cfg.history.db_path, "rb").read()
    assert b"SECRET-BODY-TEXT" not in raw and b"SECRET-SUBJECT" not in raw


# --------------------------------- the analyzer ---------------------------------- #
def test_no_database_means_no_findings(cfg):
    assert findings(mk(), cfg) == {}

def test_only_your_labels_teach_it(cfg):
    save(cfg, mk(frm="scam@example.org"))                                       # saved, never labelled
    assert "history.known_bad_sender" not in findings(mk(frm="scam@example.org"), cfg)
    save(cfg, mk(frm="scam@example.org"), "legit")                              # labelled legit
    assert "history.known_bad_sender" not in findings(mk(frm="scam@example.org"), cfg)

def test_known_bad_exact_address_and_domain(cfg):
    save(cfg, mk(frm="scam@evil-corp.example"), "phish")
    f = findings(mk(frm="scam@evil-corp.example"), cfg)["history.known_bad_sender"]
    assert f.confidence == 1.0
    f2 = findings(mk(frm="other.person@evil-corp.example"), cfg)["history.known_bad_sender"]
    assert f2.confidence == 0.8                                                 # same domain, other address

def test_gmail_is_never_tainted_by_one_scammer(cfg):
    save(cfg, mk(frm="scam1234@gmail.com"), "phish")
    assert "history.known_bad_sender" in findings(mk(frm="scam1234@gmail.com"), cfg)
    assert findings(mk(frm="someone.else@gmail.com"), cfg).get("history.known_bad_sender") is None

def test_shared_hosting_condemns_only_the_exact_host(cfg):
    save(cfg, mk(text="https://evil.github.io/login"), "phish")
    assert "history.known_bad_link_domain" in findings(mk(text="visit https://evil.github.io/other"), cfg)
    assert "history.known_bad_link_domain" not in findings(mk(text="visit https://innocent.github.io/x"), cfg)

def test_protected_link_domains_are_never_condemned(cfg):
    save(cfg, mk(text="open https://drive.google.com/file/d/ABC/view"), "phish")
    assert "history.known_bad_link_domain" not in findings(mk(text="https://drive.google.com/file/d/OTHER/view"), cfg)

def test_known_bad_link_domain_and_hash(cfg):
    att = [{"filename": "inv.pdf", "hashes": {"sha256": "CD" * 32}}]
    save(cfg, mk(text="pay at https://pay.evil-shop.example.net/x", atts=att), "phish")
    e = mk(text="again https://pay.evil-shop.example.net/y", atts=att)
    f = findings(e, cfg)
    assert {"history.known_bad_link_domain", "history.known_bad_hash"} <= set(f)
    v = run_pipeline(e, cfg, analyzers=[History()])
    assert v.level.value == "MALICIOUS" and v.overridden_by == "history.known_bad_hash"

def test_rescanning_the_same_email_does_not_match_itself(cfg):
    e = mk(frm="scam@example.org", text="https://pay.evil.example.net/x")
    save(cfg, e, "phish")
    assert findings(e, cfg) == {}                                               # excludes its own row

def test_relabelling_removes_the_effect(cfg):
    e = mk(frm="scam@example.org")
    save(cfg, e, "phish")
    assert "history.known_bad_sender" in findings(mk(frm="scam@example.org"), cfg)
    s = HistoryStore.open(cfg.history.db_path); s.set_label(e.file.sha256, None); s.close()
    assert "history.known_bad_sender" not in findings(mk(frm="scam@example.org"), cfg)

def test_new_sender_is_silent_during_cold_start_then_weak(cfg):
    save(cfg, mk(frm="a@example.org")); save(cfg, mk(frm="b@example.org"))        # 2 scans < min_scans 3
    assert "history.new_sender" not in findings(mk(frm="c@example.org"), cfg)
    save(cfg, mk(frm="d@example.org"))                                          # now 3
    assert findings(mk(frm="e@brandnew.example"), cfg)["history.new_sender"].confidence == 1.0
    assert findings(mk(frm="e@example.org"), cfg)["history.new_sender"].confidence == 0.4   # new address, known domain
    assert "history.new_sender" not in findings(mk(frm="a@example.org"), cfg)    # seen before

def test_new_sender_on_a_known_free_mail_domain_is_still_new(cfg):
    for i in range(3):
        save(cfg, mk(frm=f"friend{i}@gmail.com"))
    assert findings(mk(frm="stranger@gmail.com"), cfg)["history.new_sender"].confidence == 1.0


# -------------------------------- re-scoring + eval -------------------------------- #
def test_rescore_equals_the_live_verdict(cfg):
    e = mk(frm="x@paypa1-secure.example", name="PayPal Support", text="verify your account urgently at https://paypa1-secure.example/login")
    live = save(cfg, e, "phish", analyzers=None)
    s = HistoryStore.open(cfg.history.db_path)
    again = rescore(s, s.get(e.file.sha256), cfg)
    assert (again.score, again.level, again.by_category) == (live.score, live.level, live.by_category)
    assert live.score > 0

def test_rescore_follows_new_weights_without_the_email(cfg):
    e = mk(frm="a@gmail.com", name="PayPal Support")
    save(cfg, e, "phish", analyzers=None)
    s = HistoryStore.open(cfg.history.db_path); row = s.get(e.file.sha256)
    before = rescore(s, row, cfg).score
    c2 = cfg.model_copy(deep=True); c2.weights["sender.freemail_brand"] = 30
    assert rescore(s, row, c2).score > before

def test_stale_rows_are_reported(cfg):
    save(cfg, mk(frm="a@example.org"), "phish"); save(cfg, mk(frm="b@example.org"), "legit")
    s = HistoryStore.open(cfg.history.db_path)
    s.conn.execute("UPDATE scans SET logic_hash='old'"); s.conn.commit()
    assert s.stats(logic_hash(cfg))["stale"] == 2
    out = render(evaluate_history(cfg), cfg)
    assert "2 saved scans were made by older analyzer logic" in out

def test_eval_from_history_drops_history_signals_unless_asked(cfg):
    save(cfg, mk(frm="scam@evil-corp.example"), "phish")
    sib = mk(frm="scam@evil-corp.example", text="second mail")
    save(cfg, sib, "phish", analyzers=[Sender(), History()])                     # stored with a history.known_bad_sender finding
    ids = lambda ev: {f.id for r in ev.results for f in r.verdict.findings}
    assert "history.known_bad_sender" not in ids(evaluate_history(cfg))
    assert "history.known_bad_sender" in ids(evaluate_history(cfg, include_history=True))

def test_eval_from_files_does_not_leak_campaign_siblings(cfg, tmp_path):
    save(cfg, mk(frm="scam@evil-corp.example", sha="a" * 64), "phish")           # the sibling is already in your history
    d = tmp_path / "samples" / "phish"; d.mkdir(parents=True)
    (d / "s.eml").write_bytes(b"From: S <scam@evil-corp.example>\nTo: b@example.org\nSubject: hi\nDate: Mon, 05 Jan 2026 09:00:00 +0000\n\nhello\n")
    (tmp_path / "samples" / "legit").mkdir()
    (tmp_path / "samples" / "legit" / "l.eml").write_bytes((d / "s.eml").read_bytes().replace(b"scam@evil-corp.example", b"ok@example.org"))
    ev = evaluate(tmp_path / "samples", cfg)
    assert not any(f.id.startswith("history.") for r in ev.results for f in r.verdict.findings)
    ev2 = evaluate(tmp_path / "samples", cfg, include_history=True)
    assert any(f.id == "history.known_bad_sender" for r in ev2.results for f in r.verdict.findings)


# ------------------------------------- CLI ----------------------------------------- #
MAIL = (b"From: Mary <mary.scam@gmail.com>\nTo: me@example.org\nSubject: file\nDate: Mon, 05 Jan 2026 09:00:00 +0000\n"
        b"Message-ID: <1@gmail.com>\n\nhttps://drive.google.com/file/d/ABC/preview\n")

@pytest.fixture
def env(tmp_path):
    return {"PHISHSCOPE_HISTORY": str(tmp_path / "hist" / "h.db"), "PHISHSCOPE_FEEDS": str(tmp_path / "nofeeds")}

def run(env, *args):
    return CliRunner().invoke(main, list(args), env=env)

def test_scan_saves_only_when_asked(tmp_path, env):
    f = tmp_path / "m.eml"; f.write_bytes(MAIL)
    assert run(env, "scan", str(f), "-q").exit_code == 0
    assert not (tmp_path / "hist" / "h.db").exists()                             # nothing written by default
    r = run(env, "scan", str(f), "--save")
    assert "history: saved (first time)" in r.output and (tmp_path / "hist" / "h.db").exists()
    assert "seen 2 times" in run(env, "scan", str(f), "--save").output

def test_label_a_file_then_catch_its_sibling(tmp_path, env):
    f = tmp_path / "m.eml"; f.write_bytes(MAIL)
    r = run(env, "label", str(f), "phish", "--note", "drive scam")
    assert r.exit_code == 0 and "- -> phish" in r.output and "will be flagged" in r.output
    g = tmp_path / "second.eml"; g.write_bytes(MAIL.replace(b"Subject: file", b"Subject: other").replace(b"/ABC/", b"/XYZ/"))
    r = run(env, "scan", str(g))
    assert r.exit_code == 0 and "history.known_bad_sender" in r.output

def test_label_by_sha_prefix_and_clear(tmp_path, env):
    f = tmp_path / "m.eml"; f.write_bytes(MAIL)
    run(env, "scan", str(f), "--save")
    sha = run(env, "history", "list").output.splitlines()[1].split()[0]
    assert run(env, "label", sha[:8], "phish").exit_code == 0
    assert "phish" in run(env, "history", "list", "--label", "phish").output
    assert "label: phish -> -" in run(env, "label", sha[:8], "none").output
    assert run(env, "label", "zzzzzz", "phish").exit_code != 0                   # unknown prefix

def test_history_import_stats_eval_forget(tmp_path, env):
    root = tmp_path / "s"; (root / "phish").mkdir(parents=True); (root / "legit").mkdir()
    (root / "phish" / "p.eml").write_bytes(MAIL)
    (root / "legit" / "l.eml").write_bytes(MAIL.replace(b"mary.scam@gmail.com", b"sam@example.org").replace(b"/ABC/", b"/Q/").replace(b"Subject: file", b"Subject: lunch"))
    r = run(env, "history", "import", str(root))
    assert "imported and labeled 2" in r.output
    s = run(env, "history", "stats").output
    assert "scans: 2" in s and "labeled phish: 1" in s and "silent until" in s
    e = run(env, "eval", "--from-history", "--details")
    assert e.exit_code == 0 and "1 phishing, 1 legitimate" in e.output and "p.eml" in e.output
    sha = run(env, "history", "list").output.splitlines()[1].split()[0]
    assert run(env, "history", "forget", sha).exit_code == 0
    assert "scans: 1" in run(env, "history", "stats").output

def test_eval_from_history_with_no_database(env):
    r = run(env, "eval", "--from-history")
    assert r.exit_code == 1 and "no history database" in (r.output + (r.stderr if r.stderr_bytes else ""))

def test_auto_save_from_config(tmp_path):
    cfgdir = tmp_path / "config"; shutil.copytree(base_cfg.config_dir, cfgdir)
    (cfgdir / "history.yaml").write_text(f"db_path: {tmp_path / 'auto.db'}\nauto_save: true\nmin_scans: 50\n")
    f = tmp_path / "m.eml"; f.write_bytes(MAIL)
    r = CliRunner().invoke(main, ["scan", str(f), "--config", str(cfgdir)], env={"PHISHSCOPE_FEEDS": str(tmp_path / "nf"), "PHISHSCOPE_HISTORY": ""})
    assert "history: saved" in r.output and (tmp_path / "auto.db").exists()
    r = CliRunner().invoke(main, ["scan", str(f), "--no-save", "--config", str(cfgdir)], env={"PHISHSCOPE_FEEDS": str(tmp_path / "nf"), "PHISHSCOPE_HISTORY": ""})
    assert "history: saved" not in r.output
