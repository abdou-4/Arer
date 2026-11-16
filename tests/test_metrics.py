"""Phase 6.6: metrics over the alert queue.

`arer alerts stats DIR` answers the analyst's operational questions from the
Phase 6 records alone - no new schema, purely a read-side view:

- how big is the queue and how much is still `new` (backlog)?
- of the decided records, how many were false alarms (benign share)?
- how fast do dispositions follow alerts (median time-to-disposition)?
- who sends the noise (top senders, defanged)?

Design rules carried over from 6.1b/6.2/6.4:
- read-side only: the alert records and sidecars are never touched;
- one broken record or corrupt sidecar is excluded from every number, named
  on stderr, and makes the command exit 1 - a metric computed over a
  silently incomplete queue would lie;
- time-to-disposition is derived from frozen file content only
  (generated_utc vs set_utc), so tests are byte-deterministic; the backlog
  age needs a clock, and `now` is injectable (same pattern as build_alert).
"""
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from arer.alert import Alert, ScanSubject
from arer.disposition import Disposition
from arer.metrics import queue_stats, render_queue_stats
from arer.models import Level, Verdict

FIXED_NOW = datetime(2026, 12, 1, 12, 0, 0, tzinfo=timezone.utc)


def mk_alert(aid: str, sha: str, level: Level, score: int, gen: str, sender: str = "") -> Alert:
    return Alert(alert_id=aid, generated_utc=gen, source_file=f"{aid}.eml", logic_hash="x" * 16,
                 scan=ScanSubject(from_=sender), verdict=Verdict(sha256=sha, level=level, score=score))


def mk_disp(aid: str, status: str, set_utc: str) -> Disposition:
    return Disposition(alert_id=aid, mail_sha256="", status=status, note="", set_utc=set_utc)


def pairs(*items):
    """items: (alert, disposition-or-None) tuples, passed through."""
    return list(items)


# --------------------------- the numbers -------------------------------------- #


def test_counts_records_campaigns_and_levels():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a2 = mk_alert("a2", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T11:00:00Z")   # same mail again
    a3 = mk_alert("a3", "e" * 64, Level.SUSPICIOUS, 40, "2026-11-28T12:00:00Z")
    s = queue_stats(pairs((a1, None), (a2, None), (a3, None)))
    assert s.records == 3 and s.campaigns == 2
    assert s.by_level == {"MALICIOUS": 2, "SUSPICIOUS": 1}


def test_statuses_count_missing_sidecar_as_new():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a2 = mk_alert("a2", "e" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    s = queue_stats(pairs((a1, None), (a2, mk_disp("a2", "benign", "2026-11-28T12:00:00Z"))))
    assert s.by_status == {"new": 1, "acknowledged": 0, "benign": 1, "phishing": 0}


def test_decided_and_false_alarm_share():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a2 = mk_alert("a2", "e" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a3 = mk_alert("a3", "d" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a4 = mk_alert("a4", "c" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    s = queue_stats(pairs((a1, mk_disp("a1", "benign", "2026-11-28T11:00:00Z")),
                          (a2, mk_disp("a2", "phishing", "2026-11-28T11:00:00Z")),
                          (a3, mk_disp("a3", "acknowledged", "2026-11-28T11:00:00Z")),
                          (a4, None)))
    assert s.decided == 2 and s.false_alarms == 1     # acknowledged is work queued, not a decision


def test_median_time_to_disposition():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    a2 = mk_alert("a2", "e" * 64, Level.MALICIOUS, 90, "2026-11-28T09:00:00Z")
    s = queue_stats(pairs((a1, mk_disp("a1", "phishing", "2026-11-28T11:00:00Z")),    # 1h
                          (a2, mk_disp("a2", "benign", "2026-11-28T12:00:00Z"))))     # 3h
    assert s.median_ttd_hours == 2.0


def test_ttd_ignores_records_without_a_sidecar():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    s = queue_stats(pairs((a1, None)))
    assert s.median_ttd_hours is None


def test_backlog_age_uses_the_injected_clock():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T09:00:00Z")   # 75h before FIXED_NOW
    a2 = mk_alert("a2", "e" * 64, Level.MALICIOUS, 90, "2026-11-30T00:00:00Z")   # 36h before FIXED_NOW
    s = queue_stats(pairs((a1, None), (a2, None)), now=FIXED_NOW)
    assert s.oldest_new_age_hours == 75.0


def test_backlog_age_is_none_when_the_queue_is_clear():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z")
    s = queue_stats(pairs((a1, mk_disp("a1", "benign", "2026-11-28T11:00:00Z"))), now=FIXED_NOW)
    assert s.oldest_new_age_hours is None


def test_top_senders_capped_at_five_and_sorted():
    items = []
    for i in range(6):
        for _ in range(6 - i):
            items.append((mk_alert(f"a{i}", format(i, "x") * 64, Level.MALICIOUS, 90,
                                   "2026-11-28T10:00:00Z", sender=f"s{i}[@]x[.]com"), None))
    s = queue_stats(items)
    assert [name for name, _ in s.top_senders] == [f"s{i}[@]x[.]com" for i in range(5)]
    assert s.top_senders[0] == ("s0[@]x[.]com", 6)


def test_top_senders_skip_empty_and_tie_breaks_alphabetically():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z", sender="")
    a2 = mk_alert("a2", "e" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z", sender="b[@]x[.]com")
    a3 = mk_alert("a3", "d" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z", sender="a[@]x[.]com")
    s = queue_stats(pairs((a1, None), (a2, None), (a3, None)))
    assert s.top_senders == [("a[@]x[.]com", 1), ("b[@]x[.]com", 1)]


def test_empty_queue_stats_are_zeroed():
    s = queue_stats([])
    assert s.records == 0 and s.campaigns == 0 and s.decided == 0
    assert s.median_ttd_hours is None and s.oldest_new_age_hours is None and s.top_senders == []


# --------------------------- the rendering ------------------------------------ #


def test_render_mentions_every_section():
    a1 = mk_alert("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-28T10:00:00Z", sender="x[@]y[.]com")
    s = queue_stats(pairs((a1, mk_disp("a1", "benign", "2026-11-28T11:00:00Z"))), now=FIXED_NOW)
    text = render_queue_stats(s)
    for word in ("records", "campaigns", "by verdict", "dispositions", "decided",
                 "response time", "backlog", "top senders"):
        assert word in text
    assert "x[@]y[.]com" in text                      # already defanged in the record
    assert "100%" in text                             # the one decided record was benign


# --------------------------- the CLI ------------------------------------------ #

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
           'width:640px;height:1138px"></div></a>')
RAW = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD)


@pytest.fixture(scope="function")
def queue_dir(tmp_path_factory):
    """Three real alert records: a.eml and b.eml byte-identical, c.eml different."""
    from arer.cli import main
    src = tmp_path_factory.mktemp("mail")
    (src / "a.eml").write_text(RAW, encoding="utf-8")
    (src / "b.eml").write_text(RAW, encoding="utf-8")
    (src / "c.eml").write_text(RAW.replace("Subject: win\r\n", "Subject: prize\r\n"), encoding="utf-8")
    alerts = tmp_path_factory.mktemp("out") / "alerts"
    res = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code >= 3, res.output
    return alerts


def test_stats_on_a_real_queue(queue_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "stats", str(queue_dir)])
    assert res.exit_code == 0, res.output
    assert "3 valid" in res.output and "2 distinct mails" in res.output
    assert "3 new" in res.output and "queue is clear" not in res.output


def test_stats_reflect_dispositions(queue_dir):
    from arer.cli import main
    from arer.alert import read_alerts
    alerts = read_alerts(queue_dir)
    CliRunner().invoke(main, ["alerts", "set", str(queue_dir), alerts[0].alert.alert_id[:8], "benign"])
    CliRunner().invoke(main, ["alerts", "set", str(queue_dir), alerts[2].alert.alert_id[:8], "phishing"])
    res = CliRunner().invoke(main, ["alerts", "stats", str(queue_dir)])
    assert res.exit_code == 0
    assert "1 benign" in res.output and "1 phishing" in res.output and "1 new" in res.output
    assert "2 of 3" in res.output and "false-alarm share 50%" in res.output
    assert "median" in res.output


def test_stats_names_a_broken_record_and_exits_1(queue_dir):
    from arer.cli import main
    (queue_dir / "c.eml.alert.json").write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "stats", str(queue_dir)])
    assert res.exit_code == 1
    assert "c.eml.alert.json" in res.output and "2 valid" in res.output


def test_stats_names_a_corrupt_sidecar_and_exits_1(queue_dir):
    from arer.cli import main
    from arer.disposition import disposition_path
    from arer.alert import read_alerts
    p = read_alerts(queue_dir)[0].path
    disposition_path(p).write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "stats", str(queue_dir)])
    assert res.exit_code == 1
    assert "disposition.json" in res.output and "excluded" in res.output


def test_stats_on_an_empty_folder(tmp_path):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "stats", str(tmp_path)])
    assert res.exit_code == 0 and "no alert records" in res.output
