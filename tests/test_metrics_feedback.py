"""R7: analyst feedback metrics and the Markdown case summary.

Frozen contract:
- DENOMINATORS are analyst decisions only: tool, legacy_unverified (v1
  sidecars), import and unreviewed records never enter a rate;
- duplicate scans of one mail are ONE case (sha256) - case-level rates are
  never inflated by event counts (the weekly view keeps them separate);
- the noisy-rule ranking flags rates below MIN_SAMPLES as low-confidence
  instead of presenting a small denominator as proof;
- the Markdown summary is deterministic, escapes untrusted Markdown
  metacharacters and fence/link injection, defangs indicators exactly once,
  carries the required case fields, and never claims the rules prove intent.
"""
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from arer.alert import Alert, ScanSubject, write_alert
from arer.disposition import build_disposition, write_disposition
from arer.metrics import MIN_SAMPLES, finding_metrics, weekly_alerts
from arer.models import Level, Verdict
from arer.util.defang import defang


def mk(aid: str, sha: str, level: Level, score: int, gen: str, findings=(), sender_domain=""):
    a = Alert(alert_id=aid, generated_utc=gen, source_file=f"{aid}.eml", logic_hash="h" * 16,
              scan=ScanSubject(from_="", from_domain=sender_domain),
              verdict=Verdict(sha256=sha, level=level, score=score))
    a.verdict.findings = list(findings)
    a.indicators = {"urls": [], "url_domains": [], "sender_domain": sender_domain, "attachments": []}
    return a


def finding(fid: str):
    from arer.models import Category, Finding
    return Finding(id=fid, category=Category.BODY, summary="s", weight=5, confidence=1.0)


# --------------------------- denominators (R7.1) ------------------------------- #


def test_tool_and_legacy_decisions_never_enter_the_rate():
    a1 = mk("1", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-01T00:00:00Z", [finding("body.urgency_words")])
    tool = build_disposition("1", "benign", provenance="tool")
    legacy = build_disposition("2", "benign", provenance="legacy_unverified")
    a2 = mk("2", "b" * 64, Level.SUSPICIOUS, 30, "2026-01-02T00:00:00Z", [finding("body.urgency_words")])
    legacy2 = legacy.model_copy(update={"alert_id": "2"})
    stats = finding_metrics([(a1, tool), (a2, legacy2)])
    s = next(x for x in stats if x.finding_id == "body.urgency_words")
    assert s.reviewed == 0 and s.unresolved == 2        # nothing counts as reviewed
    assert s.fp_rate is None


def test_duplicate_scans_of_one_sha_are_one_case():
    a1 = mk("1", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-01T00:00:00Z", [finding("body.urgency_words")])
    a2 = mk("2", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-05T00:00:00Z", [finding("body.urgency_words")])
    a3 = mk("3", "b" * 64, Level.SUSPICIOUS, 30, "2026-01-06T00:00:00Z", [finding("body.urgency_words")])
    benign = build_disposition("1", "benign", provenance="analyst")
    phishing = build_disposition("3", "phishing", provenance="analyst")
    ph2 = phishing.model_copy(update={"alert_id": "3"})
    stats = finding_metrics([(a1, benign), (a2, None), (a3, ph2)])
    s = next(x for x in stats if x.finding_id == "body.urgency_words")
    assert s.reviewed == 2                              # one benign case + one phishing case
    assert s.false_alarms == 1 and s.fp_rate == 0.5


def test_acknowledged_only_cases_are_reviewed_but_unclassified():
    a1 = mk("1", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-01T00:00:00Z", [finding("body.urgency_words")])
    ack = build_disposition("1", "acknowledged", provenance="analyst")
    stats = finding_metrics([(a1, ack)])
    s = stats[0]
    assert s.reviewed == 0 and s.unresolved == 1        # no class -> outside every rate


def test_min_samples_flag_is_low_confidence_not_silent():
    pairs = []
    for i in range(MIN_SAMPLES - 1):                    # 4 reviewed benign cases: below threshold
        pairs.append((mk(str(i), format(i, "x") * 16, Level.SUSPICIOUS, 30,
                         "2026-01-01T00:00:00Z", [finding("body.urgency_words")]),
                      build_disposition(str(i), "benign", provenance="analyst")))
    s = finding_metrics(pairs)[0]
    assert s.reviewed == MIN_SAMPLES - 1 and s.fp_rate == 1.0
    assert s.low_confidence is True


def test_weekly_view_separates_cases_from_events():
    a1 = mk("1", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-06T00:00:00Z")   # ISO week 2 of 2026
    a2 = mk("2", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-08T00:00:00Z")   # same case, same week
    a3 = mk("3", "b" * 64, Level.SUSPICIOUS, 30, "2026-01-13T00:00:00Z")   # next week
    rows = weekly_alerts([(a1, None), (a2, None), (a3, None)])
    assert rows[0] == ("2026-W02", 1, 2)                # ONE case, TWO events
    assert rows[1] == ("2026-W03", 1, 1)


# --------------------------- the Markdown summary (R7.3) ----------------------- #


@pytest.fixture
def real_queue(tmp_path):
    from arer.cli import main
    salad = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
             "<!DOCTYPE><!DOCTYPE>" + "<textarea></textarea>" * 25 + "<option>" * 10
             + '<div style="display:none !important;">x</div>' * 22
             + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
               'width:640px;height:1138px"></div></a>')
    src = tmp_path / "mail"
    src.mkdir()
    (src / "m.eml").write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + salad, encoding="utf-8")
    q = tmp_path / "q"
    r = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(q), "-q",
                                  "--skip", "intel", "--skip", "history"])
    assert r.exit_code >= 3, r.output
    from arer.alert import read_alerts
    rec = read_alerts(q)[0]
    return q, rec


def test_markdown_summary_contains_the_required_fields(real_queue):
    from arer.cli import main
    from arer.disposition import read_disposition
    q, rec = real_queue
    note = "# heading\n[click me](http://evil.example)\n```\nfence\n```\n*bold* _u_ <script>"
    CliRunner().invoke(main, ["alerts", "set", str(q), rec.alert.alert_id[:8], "phishing", "--note", note])
    d = read_disposition(rec.path, rec.alert)
    r = CliRunner().invoke(main, ["alerts", "show", str(q), rec.alert.alert_id[:8], "--markdown"])
    assert r.exit_code == 0, r.output
    text = r.output
    for field in ("# Case summary", rec.alert.verdict.sha256, rec.alert.alert_id,
                  "## Top reasons", "## Evidence", "## Indicators", "## Campaign",
                  "## Workflow", "## Reproducibility", "logic_hash", "config_hash",
                  "provenance analyst"):
        assert field in text, f"missing: {field}"
    assert "discord" in text and "discord.com" not in text.replace("discord\\[.\\]com", "")
    assert "does not prove intent" in text
    # the hostile note is escaped: no heading, no link, no fence can render
    assert "click me" in text
    assert "[click me](http://evil.example)" not in text
    assert "](http" not in text and "```" not in text
    assert r"\# heading" in text and r"\*bold\*" in text and r"\<script\>" in text


def test_markdown_summary_is_deterministic_and_escapes_injection(real_queue):
    from arer.cli import main
    q, rec = real_queue
    note = "# heading\n[click me](http://evil.example)\n```\nfence\n```\n*bold* _u_ <script>"
    CliRunner().invoke(main, ["alerts", "set", str(q), rec.alert.alert_id[:8], "phishing", "--note", note])
    r1 = CliRunner().invoke(main, ["alerts", "show", str(q), rec.alert.alert_id[:8], "--markdown"]).output
    r2 = CliRunner().invoke(main, ["alerts", "show", str(q), rec.alert.alert_id[:8], "--markdown"]).output
    assert r1 == r2
    # the hostile subject's Markdown metacharacters are escaped, not rendered
    assert "\\*bold\\*" in r1 and "\\_u\\_" in r1
    assert "<script>" not in r1.replace(r"\<script\>", "")   # raw tags cannot appear
    # no clickable links, no live IOCs by default
    assert "](http" not in r1 and "https://img.example.net/p.jpg" not in r1
    assert "hxxps://" in r1 and "img" in r1


def test_markdown_raw_option_shows_live_iocs(real_queue):
    from arer.cli import main
    q, rec = real_queue
    r = CliRunner().invoke(main, ["alerts", "show", str(q), rec.alert.alert_id[:8],
                                  "--markdown", "--raw"])
    assert "https://img.example.net/p.jpg" in r.output


def test_markdown_summary_shows_campaign_membership(real_queue):
    from arer.cli import main
    # a second mail sharing the strong URL joins the cluster
    q, rec = real_queue
    salad = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
             "<!DOCTYPE><!DOCTYPE>" + "<textarea></textarea>" * 25 + "<option>" * 10
             + '<div style="display:none !important;">x</div>' * 22
             + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
               'width:640px;height:1138px"></div></a>')
    src = q.parent / "mail"
    (src / "m2.eml").write_text(
        "From: other@discord.com\r\nTo: v@example.com\r\nSubject: prize\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + salad, encoding="utf-8")
    r = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(q), "-q",
                                  "--skip", "intel", "--skip", "history"])
    assert r.exit_code >= 3
    from arer.alert import read_alerts
    rec2 = next(x for x in read_alerts(q) if x.alert.source_file == "m2.eml")
    r = CliRunner().invoke(main, ["alerts", "show", str(q), rec2.alert.alert_id[:8], "--markdown"])
    assert "campaign_id:" in r.output and "not reviewed yet" in r.output
    assert "url:img" in r.output and "not reviewed yet" in r.output  # the linking key evidence


def test_cli_stats_report_analyst_feedback(tmp_path):
    from arer.cli import main
    a1 = mk("1", "a" * 64, Level.SUSPICIOUS, 30, "2026-01-06T00:00:00Z", [finding("body.urgency_words")])
    a2 = mk("2", "b" * 64, Level.SUSPICIOUS, 30, "2026-01-07T00:00:00Z", [finding("body.urgency_words")])
    q = tmp_path / "q"
    write_alert(a1, q)
    write_alert(a2, q)
    write_disposition(build_disposition("1", "benign", mail_sha256=a1.verdict.sha256,
                                        provenance="analyst", analyst="dana"), q / f"{a1.alert_id}.alert.json")
    r = CliRunner().invoke(main, ["alerts", "stats", str(q)])
    assert r.exit_code == 0, r.output
    assert "alerts per week" in r.output and "2026-W02" in r.output
    assert "noisy rules" in r.output and "body.urgency_words" in r.output
    assert "low-confidence" in r.output                 # 1 reviewed case: below MIN_SAMPLES
