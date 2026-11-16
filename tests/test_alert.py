"""Phase 6.1a: versioned JSON alert records (arer.alert.v1).

The record is what Phase 6.2 dispositions, 6.3 export and external tooling
(SOAR/SIEM/watchers) read, so its shape is frozen:

- test_schema_marker_and_key_set_are_frozen  pins the schema marker and key sets
- test_golden_alert_record                   pins the whole record byte-for-byte
                                             against tests/golden/alert_v1.json

A golden failure means the record changed: either fix the code, or make a
deliberate schema change (see docs/alert-record.md) and regenerate the golden
with:  UPDATE_GOLDEN=1 uv run pytest tests/test_alert.py
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import SCHEMA_VERSION, build_alert, is_alert_level, to_json
from arer.config import load_config
from arer.models import Email, Level
from arer.pipeline import run_pipeline

cfg = load_config()
GOLDEN = Path(__file__).parent / "golden" / "alert_v2.json"
GOLDEN_V1 = Path(__file__).parent / "golden" / "alert_v1.json"


def mk(frm="news@discord.com", subject="Your account is locked", text="", html="", auth=None,
       mid="<20261101.1@x.com>", date="Sun, 01 Nov 2026 10:00:00 +0000"):
    sec = {}
    if auth:
        sec["authentication-results"] = [auth]
    return Email.from_parser_json({
        "envelope": {"subject": subject, "date": date, "message_id": mid,
                     "from": [{"name": "", "address": frm, "domain": frm.split("@")[-1]}]},
        "headers": {"security": sec}, "routing": {"received": [{"hop": 1}]},
        "body": {"text_plain": [text] if text else [], "text_html": [html] if html else [],
                 "combined": text or html}})


AUTH_FAIL = "mx.corp.test; spf=fail smtp.mailfrom=x.com; dkim=none; dmarc=fail header.from=x.com"


def hermetic_verdict(email):
    """Verdict without intel/history analyzers: local feeds and history.db are
    machine state and would make the golden non-reproducible."""
    return run_pipeline(email, cfg, skip={"intel", "history"})


def fixed_alert(email, name="alert.eml"):
    """Alert with a frozen clock and id, so the golden is byte-stable."""
    return build_alert(hermetic_verdict(email), email, name, cfg,
                       alert_id="f" * 32,
                       now=datetime(2026, 11, 17, 9, 30, 0, tzinfo=timezone.utc))


def test_schema_marker_and_key_sets_are_frozen():
    a = fixed_alert(mk(auth=AUTH_FAIL))
    d = json.loads(to_json(a))
    assert d["schema"] == SCHEMA_VERSION == "arer.alert.v2"
    assert set(d) == {"schema", "alert_id", "generated_utc", "source_file",
                      "logic_hash", "scan", "verdict",
                      # v2 (R3): config fingerprint, versions, analysis state,
                      # structured reasons/indicators, campaign id, privacy
                      "config_hash", "engine_version", "parser_version",
                      "sha256_verified", "analysis_complete", "analysis_errors",
                      "reasons", "indicators", "body_fingerprint", "campaign_id"}
    assert set(d["scan"]) == {"from", "message_id", "date", "from_domain"}
    assert set(d["verdict"]) == {"sha256", "subject", "score", "level", "by_category",
                                 "findings", "overridden_by", "analyzer_errors"}
    for f in d["verdict"]["findings"]:
        assert set(f) == {"id", "category", "summary", "evidence", "weight", "confidence", "source"}
    for r in d["reasons"]:
        assert set(r) == {"finding", "category", "weight", "confidence", "points"}


def test_golden_alert_record():
    a = fixed_alert(mk(auth=AUTH_FAIL))
    actual = to_json(a)
    if os.environ.get("UPDATE_GOLDEN"):              # deliberate schema change only
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual, encoding="utf-8")
        pytest.skip("golden regenerated - commit it and review the diff")
    assert actual == GOLDEN.read_text(encoding="utf-8")


def test_v1_records_still_read_back():
    """READ compatibility: an old queue's v1 records must keep loading with
    the same fields they always had - v2 additions are optional for readers."""
    from arer.alert import read_alert
    a = read_alert(GOLDEN_V1)
    assert a.schema_ == "arer.alert.v1"
    assert a.alert_id and a.logic_hash and a.verdict.subject
    assert a.config_hash == "" and a.campaign_id == "" and a.indicators == {}


def test_alert_levels_match_the_exit_code_contract():
    # docs/cli-contract.md: exit >= 3 is an alert; INSUFFICIENT_DATA (6) is a
    # no-decision, CLEAN (0) is not an alert either.
    assert is_alert_level(Level.SUSPICIOUS)
    assert is_alert_level(Level.LIKELY_PHISHING)
    assert is_alert_level(Level.MALICIOUS)
    assert not is_alert_level(Level.CLEAN)
    assert not is_alert_level(Level.INSUFFICIENT_DATA)


def test_record_carries_the_logic_hash_and_email_identity():
    a = fixed_alert(mk(auth=AUTH_FAIL, mid="<msg.7@evil.example>"))
    d = json.loads(to_json(a))
    assert 8 <= len(d["logic_hash"]) <= 16 and d["logic_hash"].isalnum()
    # attacker-controlled values come out defanged, like every report string;
    # source_file too - mail-drop file names can be attacker-crafted
    assert d["scan"]["message_id"] == "<msg.7[@]evil[.]example>"
    assert d["scan"]["date"] == "Sun, 01 Nov 2026 10:00:00 +0000"   # no IOC patterns: untouched
    assert d["source_file"] == "alert[.]eml"
    assert d["verdict"]["level"] in {"SUSPICIOUS", "LIKELY_PHISHING", "MALICIOUS"}
    assert any(f["id"].startswith("auth.") for f in d["verdict"]["findings"])


def test_every_string_in_the_record_is_defanged():
    email = mk(frm="attacker@evil-phish-site.example",
               html='<a href="https://evil-phish-site.example/login">www.paypal.com/login</a>',
               auth=AUTH_FAIL)
    raw = to_json(build_alert(hermetic_verdict(email), email, "x.eml", cfg))
    for dangerous in ("https://", "user@", "attacker@", "evil-phish-site.example"):
        assert dangerous not in raw
    assert "hxxps://" in raw          # the url evidence in the finding is still readable
    assert "[@]" in raw and "[.]" in raw


def test_empty_email_is_not_an_alert():
    v = run_pipeline(mk(frm="", text=""), cfg, skip={"intel", "history"})
    assert v.level == Level.INSUFFICIENT_DATA and not is_alert_level(v.level)


# ------------------------------- CLI wiring --------------------------------- #
SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); width:640px;height:1138px"></div></a>')


def test_scan_alerts_dir_writes_records_for_alert_level_emails_only(tmp_path):
    from arer.cli import main
    alert_eml = (tmp_path / "salad.eml")
    alert_eml.write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        + SALAD, encoding="utf-8")
    boring = tmp_path / "boring.eml"
    boring.write_text(
        "From: sam@shop.com\r\nTo: v@example.com\r\nSubject: weekly digest\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Hello Sam, here is your weekly digest with plenty of real text in it.", encoding="utf-8")
    alerts = tmp_path / "alerts"
    res = CliRunner().invoke(main, ["scan", str(tmp_path), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code >= 3, res.output
    written = sorted(p.name for p in alerts.glob("*.alert.json"))
    assert len(written) == 1, f"alert records written: {written}"
    # R1.1: the record file name is the immutable alert_id, NOT the source name
    assert written[0] != "salad.eml.alert.json" and written[0].endswith(".alert.json")
    d = json.loads((alerts / written[0]).read_text(encoding="utf-8"))
    assert d["schema"] == "arer.alert.v2"
    assert written[0] == f"{d['alert_id']}.alert.json"
    assert d["verdict"]["level"] in {"SUSPICIOUS", "LIKELY_PHISHING", "MALICIOUS"}
    assert d["source_file"] == "salad.eml"          # v2 stores the raw representation (defang on output)


def test_scan_alerts_dir_is_created_and_batch_safe(tmp_path):
    from arer.cli import main
    alerts = tmp_path / "nested" / "alerts"
    boring = tmp_path / "boring.eml"
    boring.write_text(
        "From: sam@shop.com\r\nTo: v@example.com\r\nSubject: weekly digest\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Hello Sam, here is your weekly digest with plenty of real text in it.", encoding="utf-8")
    res = CliRunner().invoke(main, ["scan", str(boring), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code in (0, 6), res.output
    assert alerts.is_dir() and list(alerts.glob("*.alert.json")) == []
