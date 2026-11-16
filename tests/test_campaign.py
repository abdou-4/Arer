"""Phase 6.4: the exact-hash campaign view over the alert queue.

The same mail (byte-identical, same verdict.sha256) often alerts many times:
five copies of one phishing run land as five records in the queue. The
campaign view groups records by exact sha256 so the analyst sees ONE row per
distinct mail - how many times it alerted, when it was first/last seen, and
the combined disposition - and can record one decision for the whole group
(alerts set-group).

v1 groups by EXACT hash only. Mails that merely look similar stay separate
campaigns; fuzzy clustering is deliberately out of scope and must never
change what 6.1b reads or what 6.2 disposes.

Frozen here:
- test_records_group_by_exact_sha256 / ordering tests    the grouping rules
- test_campaign_status_single_and_mixed                  the combined status
- test_campaign_level_is_the_most_severe                 the level/score roll-up

Reading rules inherited from 6.1b/6.2 (tests/test_alert_store.py,
tests/test_disposition.py): a broken record or sidecar is named on stderr and
never stops the whole view - the command exits 1.
"""
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import Alert, AlertRead, ScanSubject
from arer.campaign import build_campaigns, campaign_level, campaign_status
from arer.models import Level, Verdict


# --------------------------- the pure grouping ------------------------------- #


def mk(aid: str, sha: str, level: Level, score: int, gen: str, sender: str = "") -> Alert:
    return Alert(alert_id=aid, generated_utc=gen, source_file=f"{aid}.eml", logic_hash="h" * 16,
                 scan=ScanSubject(from_=sender), verdict=Verdict(sha256=sha, level=level, score=score))


def as_reads(alerts: list[Alert]) -> list[AlertRead]:
    return [AlertRead(Path(f"/q/{a.source_file}.alert.json"), a, None) for a in alerts]


def test_records_group_by_exact_sha256():
    reads = as_reads([
        mk("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T09:00:00Z"),
        mk("b1", "e" * 64, Level.SUSPICIOUS, 40, "2026-11-17T09:05:00Z"),
        mk("a2", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T10:00:00Z"),   # same mail again
    ])
    campaigns = build_campaigns(reads)
    assert [c.mail_sha256 for c in campaigns] == ["f" * 64, "e" * 64]      # newest activity first
    big = campaigns[0]
    assert [a.alert_id for a in big.alerts] == ["a1", "a2"]                # members oldest first
    assert len(big.paths) == 2


def test_campaign_members_are_sorted_oldest_first():
    reads = as_reads([
        mk("late", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T10:00:00Z"),
        mk("early", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T08:00:00Z"),
    ])
    big = build_campaigns(reads)[0]
    assert [a.alert_id for a in big.alerts] == ["early", "late"]


def test_campaigns_are_sorted_by_newest_activity():
    reads = as_reads([
        mk("old", "e" * 64, Level.MALICIOUS, 90, "2026-11-17T08:00:00Z"),
        mk("new", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T10:00:00Z"),
    ])
    assert [c.mail_sha256 for c in build_campaigns(reads)] == ["f" * 64, "e" * 64]


def test_broken_records_never_join_a_group():
    reads = as_reads([mk("a1", "f" * 64, Level.MALICIOUS, 90, "2026-11-17T09:00:00Z")])
    reads.append(AlertRead(Path("/q/broken.alert.json"), None, "broken.alert.json: not valid JSON"))
    campaigns = build_campaigns(reads)
    assert len(campaigns) == 1 and campaigns[0].mail_sha256 == "f" * 64


def test_campaign_status_single_and_mixed():
    assert campaign_status(["new", "new"]) == "new"
    assert campaign_status(["phishing"]) == "phishing"
    assert campaign_status(["acknowledged", "acknowledged"]) == "acknowledged"
    assert campaign_status(["new", "acknowledged"]) == "mixed"
    assert campaign_status(["benign", "phishing"]) == "mixed"


def test_campaign_level_is_the_most_severe_and_score_is_the_max():
    reads = as_reads([
        mk("a1", "f" * 64, Level.SUSPICIOUS, 40, "2026-11-17T09:00:00Z"),
        mk("a2", "f" * 64, Level.MALICIOUS, 85, "2026-11-17T09:05:00Z"),
        mk("a3", "f" * 64, Level.LIKELY_PHISHING, 70, "2026-11-17T09:10:00Z"),
    ])
    c = build_campaigns(reads)[0]
    assert campaign_level(c.alerts) is Level.MALICIOUS
    assert max(a.verdict.score for a in c.alerts) == 85


def test_empty_directory_groups_to_nothing():
    assert build_campaigns([]) == []


# --------------------------- the real queue (CLI) ---------------------------- #

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
           'width:640px;height:1138px"></div></a>')
RAW = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
       "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD)


@pytest.fixture(scope="function")
def campaign_dir(tmp_path_factory):
    """Three real alert records: a.eml and b.eml are byte-identical (one
    campaign of 2), c.eml differs (its own campaign)."""
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


def _group_of_two(queue: Path):
    from arer.campaign import build_campaigns
    from arer.alert import read_alerts
    return next(c for c in build_campaigns(read_alerts(queue)) if len(c.alerts) == 2)


def test_campaigns_table_shows_one_row_per_distinct_mail(campaign_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir)])
    assert res.exit_code == 0, res.output
    assert "sha256" in res.output and "seen" in res.output and "first" in res.output
    big = _group_of_two(campaign_dir)
    assert big.mail_sha256[:12] in res.output
    # two campaigns, so two data rows: one with 2 alerts, one with 1
    assert res.output.count("  2  ") == 1 and res.output.count("  1  ") == 1


def test_campaigns_status_is_combined(campaign_dir):
    from arer.cli import main
    from arer.alert import read_alerts
    big = _group_of_two(campaign_dir)
    res = CliRunner().invoke(main, ["alerts", "set", str(campaign_dir),
                                    read_alerts(campaign_dir)[0].alert.alert_id[:8], "acknowledged"])
    assert res.exit_code == 0, res.output
    row = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir)])
    # the pair shows its combined status; no single record's decision leaks into the view
    assert row.exit_code == 0 and " mixed\n" in row.output and " acknowledged\n" not in row.output
    assert CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--status", "mixed"]).exit_code == 0
    gone = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--status", "new"])
    assert gone.exit_code == 0 and big.mail_sha256[:12] not in gone.output


def test_campaigns_new_filter_means_every_member_is_new(campaign_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--status", "new"])
    assert res.exit_code == 0 and res.output.count(" new\n") == 2


def test_campaigns_level_filter(campaign_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--level", "SUSPICIOUS"])
    assert res.exit_code == 0 and res.output.count("  2  ") == 1
    empty = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--level", "MALICIOUS"])
    assert empty.exit_code == 0 and "no alert records" in empty.output


def test_campaigns_names_a_broken_record(campaign_dir):
    from arer.cli import main
    bad = campaign_dir / "b.eml.alert.json"
    bad.write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir)])
    assert res.exit_code == 1 and "b.eml.alert.json" in res.output and "unreadable" in res.output


def test_campaigns_drops_a_member_with_a_corrupt_sidecar(campaign_dir):
    """The corrupt sidecar is named and the group is shown without that member
    (seen 1, not 2) - same contract as alerts list."""
    from arer.cli import main
    from arer.disposition import disposition_path
    big = _group_of_two(campaign_dir)
    disposition_path(big.paths[0]).write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir)])
    assert res.exit_code == 1
    assert big.mail_sha256[:12] in res.output and "  1  " in res.output and "unreadable" in res.output


# --------------------------- alerts set-group --------------------------------- #


def test_set_group_marks_every_member(campaign_dir):
    from arer.cli import main
    from arer.disposition import read_disposition
    big = _group_of_two(campaign_dir)
    res = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir),
                                    big.mail_sha256[:8], "phishing", "--note", "real run"])
    assert res.exit_code == 0, res.output
    assert "2 alert(s) marked phishing" in res.output
    for p in big.paths:
        d = read_disposition(p)
        assert d is not None and d.status == "phishing" and d.note == "real run"
        assert d.mail_sha256 == big.mail_sha256
    # the untouched campaign stays new
    row = CliRunner().invoke(main, ["alerts", "campaigns", str(campaign_dir), "--status", "phishing"])
    assert row.exit_code == 0 and row.output.count(" phishing\n") == 1


def test_set_group_then_the_list_filter_sees_all_members(campaign_dir):
    from arer.cli import main
    big = _group_of_two(campaign_dir)
    res = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir), big.mail_sha256[:8], "benign"])
    assert res.exit_code == 0, res.output
    listing = CliRunner().invoke(main, ["alerts", "list", str(campaign_dir), "--status", "benign"])
    assert listing.exit_code == 0
    assert "a[.]eml" in listing.output and "b[.]eml" in listing.output


def test_set_group_overwrites_existing_sidecars(campaign_dir):
    from arer.cli import main
    from arer.alert import read_alerts
    from arer.disposition import disposition_path, load_disposition
    big = _group_of_two(campaign_dir)
    aid = read_alerts(campaign_dir)[0].alert.alert_id[:8]
    assert CliRunner().invoke(main, ["alerts", "set", str(campaign_dir), aid, "acknowledged"]).exit_code == 0
    res = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir), big.mail_sha256[:8], "benign"])
    assert res.exit_code == 0
    for p in big.paths:
        assert load_disposition(disposition_path(p)).status == "benign"


def test_set_group_names_unknown_and_ambiguous_sha(campaign_dir):
    from arer.cli import main
    miss = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir), "dead00", "benign"])
    assert miss.exit_code == 1 and "no campaign matches" in miss.output
    assert "alerts campaigns" in miss.output               # the hint names the command to copy from


def test_set_group_rejects_unknown_status(campaign_dir):
    from arer.cli import main
    big = _group_of_two(campaign_dir)
    res = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir), big.mail_sha256[:8], "WAT"])
    assert res.exit_code == 2                              # Click usage error


def test_set_group_does_not_touch_other_campaigns(campaign_dir):
    from arer.cli import main
    big = _group_of_two(campaign_dir)
    res = CliRunner().invoke(main, ["alerts", "set-group", str(campaign_dir), big.mail_sha256[:8], "benign"])
    assert res.exit_code == 0
    # exactly 2 sidecars were written, none for the single-mail campaign
    sidecars = sorted(p.name for p in campaign_dir.glob("*.disposition.json"))
    assert len(sidecars) == 2
