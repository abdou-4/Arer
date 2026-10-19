from arer.config import load_config
from arer.models import Category, Email, Finding, Level
from arer.scoring import compute
from arer.util.defang import defang, safe_text

cfg = load_config()


def F(fid, conf=1.0):
    f = Finding(id=fid, category=Category(fid.split(".")[0]), summary="t", confidence=conf)
    f.weight = cfg.weight_for(fid)
    return f


def test_empty_is_clean():
    assert compute([], cfg).level == Level.CLEAN

def test_same_id_counts_once():
    v = compute([F("url.ip_host")] * 5, cfg)
    assert v.score == 10

def test_category_cap():
    v = compute([F("url.text_href_mismatch"), F("url.ip_host"), F("url.lookalike_domain")], cfg)
    assert v.by_category["url"] == 35            # 20+10+15=45 capped to 35

def test_confidence_scales_points():
    assert compute([F("auth.spf_fail", 0.5)], cfg).score == 8   # round(7.5)

def test_override_raises_level_and_score():
    v = compute([F("url.on_blocklist")], cfg)
    assert v.level == Level.MALICIOUS and v.score >= cfg.thresholds.malicious
    assert v.overridden_by == "url.on_blocklist"

def test_thresholds():
    assert compute([F("auth.spf_fail"), F("auth.dkim_fail")], cfg).level == Level.SUSPICIOUS  # 25

def test_partial_email_not_clean():
    assert compute([], cfg, Email()).level == Level.INSUFFICIENT_DATA

def test_defang():
    assert defang("http://evil.com/a?b=1.2.3.4") == "hxxp://evil[.]com/a?b=1[.]2[.]3[.]4"
    assert defang("a@b.com") == "a[@]b[.]com"

def test_safe_text_blocks_escapes():
    s = safe_text("\x1b[31mred\u202eevil")
    assert "\x1b" not in s and "\u202e" not in s and "<U+202E>" in s
