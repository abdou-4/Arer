"""R3: reproducibility - config_hash, alert v2, structured reasons/indicators,
JSONL scan output.

Frozen contract:
- config_hash changes when ANY effective scoring setting changes (weight,
  cap, threshold, override, list content) and does NOT change when rules.yaml
  is merely reformatted (whitespace, key order, comments);
- logic_hash (code) and config_hash (tuning) are independent fingerprints and
  both travel with every alert record and evaluation run;
- alert v2 carries both hashes, engine/parser versions, the analysis
  completeness block, top-3 structured reasons that agree with the scoring,
  a structured indicator block, the body fingerprint and the campaign id;
- v1 records keep reading back unchanged;
- `scan --jsonl` writes exactly one valid JSON object per message, and load
  failures become structured error lines (never silent);
- sender privacy: v2 stores the sender DOMAIN; plaintext only with
  --store-sender.
"""
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import SCHEMA_VERSION, build_alert, read_alert, to_json
from arer.config import config_hash, load_config
from arer.models import Email
from arer.pipeline import run_pipeline

FIXED_NOW = datetime(2026, 11, 17, 9, 30, 0, tzinfo=timezone.utc)

EML = ("From: 'PayPal' <support@paypa1-secure.com>\r\n"
       "To: v@example.com\r\nSubject: Verify\r\n"
       "Date: Sun, 01 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@x.com>\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
       "Go to http://1.2.3.4/login now")


# --------------------------- config_hash (R3.2) ------------------------------- #


@pytest.fixture(scope="module")
def base_cfg_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("cfg")
    shutil.copytree("config", d, dirs_exist_ok=True)
    return d


def _rewrite_cfg(cfg_dir: Path, old: str, new: str) -> None:
    rules = cfg_dir / "rules.yaml"
    text = rules.read_text(encoding="utf-8")
    assert old in text, f"rules.yaml is expected to contain {old!r}"
    rules.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_config_hash_is_stable_across_runs():
    assert config_hash(load_config()) == config_hash(load_config())
    assert len(config_hash(load_config())) == 16


def test_reformatting_yaml_does_not_change_config_hash(base_cfg_dir):
    h0 = config_hash(load_config(base_cfg_dir))
    rules = base_cfg_dir / "rules.yaml"
    text = rules.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    rules.write_text("# a comment\n\n" + "".join(lines), encoding="utf-8")   # comments/blank lines
    assert config_hash(load_config(base_cfg_dir)) == h0


def test_every_effective_setting_change_changes_config_hash(base_cfg_dir):
    h0 = config_hash(load_config(base_cfg_dir))
    checks = [
        # a weight
        ("  auth.spf_fail: 15", "  auth.spf_fail: 1"),
        # a cap
        ("  url: 35", "  url: 36"),
        # a threshold
        ("  suspicious: 20", "  suspicious: 21"),
        # a list content
        (None, None),                    # handled separately below
    ]
    seen = []
    for old, new in checks:
        if old is None:
            lst = base_cfg_dir / "lists" / "urgency_words.txt"
            lst.write_text(lst.read_text(encoding="utf-8") + "hurryplease\r\n", encoding="utf-8")
        else:
            _rewrite_cfg(base_cfg_dir, old, new)
        h = config_hash(load_config(base_cfg_dir))
        assert h not in seen, "two different effective configurations hashed the same"
        assert h != h0
        seen.append(h)
        if old is None:                  # restore the list
            lst = base_cfg_dir / "lists" / "urgency_words.txt"
            lst.write_text(lst.read_text(encoding="utf-8").replace("hurryplease\r\n", ""), encoding="utf-8")
        else:
            _rewrite_cfg(base_cfg_dir, new, old)


# --------------------------- alert v2 ------------------------------------------ #


@pytest.fixture(scope="module")
def built_alert(tmp_path_factory):
    cfg = load_config()
    d = tmp_path_factory.mktemp("mail")
    p = d / "alert.eml"
    p.write_text(EML, encoding="utf-8")
    from arer.loader import load_any
    email = load_any(p, cfg)
    v = run_pipeline(email, cfg, skip={"intel", "history"})
    return build_alert(v, email, p.name, cfg, alert_id="f" * 32, now=FIXED_NOW), cfg


def test_v2_record_carries_both_hashes_and_versions(built_alert):
    a, cfg = built_alert
    d = json.loads(to_json(a))
    assert d["schema"] == SCHEMA_VERSION == "arer.alert.v2"
    assert d["config_hash"] == config_hash(cfg) and d["logic_hash"]
    assert d["engine_version"] and d["parser_version"]
    assert d["sha256_verified"] is True               # native .eml input
    assert d["analysis_complete"] is True and d["analysis_errors"] == []
    assert d["campaign_id"] == ""


def test_v2_reasons_agree_with_the_scoring(built_alert):
    a, _ = built_alert
    d = json.loads(to_json(a))
    verdict = json.loads(to_json(a, defang=False))["verdict"]
    assert len(d["reasons"]) == min(3, len(verdict["findings"]))
    for r, f in zip(d["reasons"], verdict["findings"]):
        assert r["finding"] == f["id"]
        assert r["points"] == round(f["weight"] * f["confidence"])


def test_v2_indicators_are_structured_not_scraped(built_alert):
    a, _ = built_alert
    ind = a.indicators
    assert "http://1.2.3.4/login" in ind["urls"]
    assert "1.2.3.4" in ind["url_domains"]             # the URL's host, derived not scraped
    assert a.indicators["sender_domain"] == "paypa1-secure.com"
    assert ind["attachments"] == []


def test_v2_body_fingerprint_is_deterministic(tmp_path_factory):
    cfg = load_config()
    from arer.loader import load_any
    d = tmp_path_factory.mktemp("mail")
    bodies = ["Fast! Visit http://x.example now!", "fast!   visit http://x.example now!"]
    fps = set()
    for i, b in enumerate(bodies):
        email = Email.from_parser_json({
            "envelope": {"subject": "s", "from": [{"name": "", "address": "a@b.c", "domain": "b.c"}]},
            "body": {"text_plain": [b], "combined": b}})
        fps.add(build_alert(run_pipeline(email, cfg, skip={"intel", "history"}),
                            email, "m.eml", cfg, alert_id="f" * 32, now=FIXED_NOW).body_fingerprint)
    assert len(fps) == 1 and "" not in fps            # whitespace/URL noise does not move the fingerprint


def test_v2_analysis_block_mirrors_errors(tmp_path_factory):
    cfg = load_config()
    from arer.loader import load_any
    d = tmp_path_factory.mktemp("mail")
    p = d / "a.eml"; p.write_text(EML, encoding="utf-8")
    email = load_any(p, cfg)
    v = run_pipeline(email, cfg, analyzers=[], skip=None)     # empty analyzer list, no errors
    a = build_alert(v, email, p.name, cfg, alert_id="f" * 32, now=FIXED_NOW)
    assert a.analysis_complete is True
    from arer.models import Finding
    broken = run_pipeline(email, cfg, analyzers=[type("X", (), {"name": "urls",
                                                               "run": lambda s, e, c: (_ for _ in ()).throw(RuntimeError("boom"))})()],
                          skip=None)
    a2 = build_alert(broken, email, p.name, cfg, alert_id="f" * 32, now=FIXED_NOW)
    assert a2.analysis_complete is False and "urls: crashed (RuntimeError)" in a2.analysis_errors


# --------------------------- sender privacy (R4.5 groundwork) ------------------ #


def test_v2_stores_sender_domain_not_plaintext(tmp_path_factory):
    cfg = load_config()
    from arer.loader import load_any
    d = tmp_path_factory.mktemp("mail")
    p = d / "a.eml"; p.write_text(EML, encoding="utf-8")
    email = load_any(p, cfg)
    v = run_pipeline(email, cfg, skip={"intel", "history"})
    a = build_alert(v, email, p.name, cfg, alert_id="f" * 32, now=FIXED_NOW)
    d = json.loads(to_json(a))
    assert d["scan"]["from"] == ""                     # plaintext OFF by default
    assert a.scan.from_domain == "paypa1-secure.com"   # raw value on the model...
    assert d["scan"]["from_domain"] == "paypa1-secure[.]com"   # ...defanged on output
    a2 = build_alert(v, email, p.name, cfg, alert_id="f" * 32, now=FIXED_NOW, store_sender=True)
    d2 = json.loads(to_json(a2))
    assert a2.scan.from_ == "support@paypa1-secure.com"   # explicit opt-in keeps plaintext
    assert "support[@]paypa1-secure[.]com" in d2["scan"]["from"]   # defanged on output


# --------------------------- JSONL scan output (R3.3) -------------------------- #


def test_jsonl_output_one_record_per_message(tmp_path):
    mails = tmp_path / "mails"
    mails.mkdir()
    (mails / "a.eml").write_text(EML, encoding="utf-8")
    (mails / "b.eml").write_text(
        "From: Sam <sam@example.org>\r\nTo: me@example.org\r\nSubject: Lunch\r\n"
        "Date: Mon, 05 Jan 2026 09:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHi, lunch on Friday?",
        encoding="utf-8")
    out = tmp_path / "scan.jsonl"
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails), "-q", "--jsonl", str(out),
                            "--skip", "intel", "--skip", "history"])
    assert r.exit_code >= 3, r.output
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    recs = [json.loads(ln) for ln in lines]            # every line is one valid JSON object
    assert all(rec["schema"] == "arer.scan-jsonl.v1" for rec in recs)
    assert {rec["source_file"] for rec in recs} == {"a.eml", "b.eml"}
    for rec in recs:
        assert rec["ok"] is True and rec["exit_code"] in (0, 3, 4, 5, 6, 7)
        assert rec["report"]["level"] and "score" in rec["report"]


def test_jsonl_output_structured_error_lines(tmp_path):
    mails = tmp_path / "mails"
    mails.mkdir()
    (mails / "bad.json").write_text("{oops", encoding="utf-8")
    out = tmp_path / "scan.jsonl"
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails), "-q", "--jsonl", str(out)])
    assert r.exit_code == 1
    recs = [json.loads(ln) for ln in out.read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 1 and recs[0]["ok"] is False and recs[0]["error"]
    assert "report" not in recs[0]                     # a failed load has no verdict to publish
