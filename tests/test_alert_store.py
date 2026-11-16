"""Phase 6.1b: reading alert records back (the queue Phase 6.2 dispositions).

6.1a froze what a record looks like (tests/test_alert.py). This file freezes
what a reader does with one:

- dispatch on the top-level "schema" marker: unknown schema -> explicit error,
  never a silent mis-read (docs/alert-record.md: readers dispatch on "schema");
- validation errors name the file, so a corrupt record in a folder of 10,000
  is one line on stderr, not a crash;
- unknown extra keys are ignored (the forward-compatibility rule of
  docs/alert-record.md: additions must be optional for readers);
- one bad file never stops a directory scan (same batch rule as `arer parse`).
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import AlertError, SCHEMA_VERSION, read_alert, read_alerts

# --------------------------- fixtures -------------------------------------- #

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); width:640px;height:1138px"></div></a>')

BOARING = ("From: sam@shop.com\r\nTo: v@example.com\r\nSubject: weekly digest\r\n"
           "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
           "Hello Sam, here is your weekly digest with plenty of real text in it.")


@pytest.fixture(scope="module")
def alert_dir(tmp_path_factory):
    """One real alert record, produced the way production produces it."""
    import os
    from arer.cli import main

    src = tmp_path_factory.mktemp("mail")
    (src / "salad.eml").write_text(
        "From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD,
        encoding="utf-8")
    (src / "boring.eml").write_text(BOARING, encoding="utf-8")
    alerts = tmp_path_factory.mktemp("out") / "alerts"
    res = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code >= 3, res.output
    assert os.environ.get("ARER_TEST_ALERTS") is None or True   # keep linters calm
    return alerts


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


VALID = {
    "schema": "arer.alert.v1",
    "alert_id": "a" * 32,
    "generated_utc": "2026-11-17T09:30:00Z",
    "source_file": "alert[.]eml",
    "logic_hash": "0123abcd",
    "scan": {"from": "news[@]discord[.]com", "message_id": "<m[@]x[.]com>", "date": "Sun, 01 Nov 2026"},
    "verdict": {
        "sha256": "b" * 64, "subject": "win", "score": 25, "level": "SUSPICIOUS",
        "by_category": {"body": 25},
        "findings": [{"id": "body.html_obfuscation", "category": "body", "summary": "s",
                      "evidence": {}, "weight": 25, "confidence": 1.0, "source": "rule"}],
        "overridden_by": None, "analyzer_errors": [],
    },
}

# --------------------------- read_alert ------------------------------------ #


def test_valid_record_round_trips(tmp_path):
    p = tmp_path / "x.alert.json"
    write_json(p, VALID)
    a = read_alert(p)
    # the fixture is a v1 record: v1 keeps reading back exactly as before
    assert a.schema_ == "arer.alert.v1" and SCHEMA_VERSION == "arer.alert.v2"
    assert a.alert_id == "a" * 32
    assert a.generated_utc == "2026-11-17T09:30:00Z"
    assert a.scan.from_ == "news[@]discord[.]com"
    assert a.verdict.level.value == "SUSPICIOUS" and a.verdict.score == 25
    assert a.verdict.findings[0].id == "body.html_obfuscation"


def test_unknown_schema_version_is_rejected(tmp_path):
    p = tmp_path / "x.alert.json"
    d = dict(VALID, schema="arer.alert.v99")
    write_json(p, d)
    with pytest.raises(AlertError) as e:
        read_alert(p)
    assert "arer.alert.v99" in str(e.value) and p.name in str(e.value)


def test_missing_schema_marker_is_rejected(tmp_path):
    p = tmp_path / "x.alert.json"
    write_json(p, {k: v for k, v in VALID.items() if k != "schema"})
    with pytest.raises(AlertError):
        read_alert(p)


def test_non_json_and_non_object_files_are_rejected(tmp_path):
    bad = tmp_path / "bad.alert.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(AlertError):
        read_alert(bad)
    arr = tmp_path / "arr.alert.json"
    write_json(arr, [VALID])
    with pytest.raises(AlertError):
        read_alert(arr)


def test_schema_violations_name_the_field(tmp_path):
    p = tmp_path / "x.alert.json"
    d = json.loads(json.dumps(VALID))
    d["verdict"]["level"] = "WAT"                      # not a Level
    write_json(p, d)
    with pytest.raises(AlertError) as e:
        read_alert(p)
    assert "level" in str(e.value)

    d["verdict"]["level"] = "SUSPICIOUS"
    d["verdict"]["score"] = 9000                       # out of the 0..100 contract
    write_json(p, d)
    with pytest.raises(AlertError):
        read_alert(p)

    del d["alert_id"]                                  # missing required key
    write_json(p, d)
    with pytest.raises(AlertError) as e:
        read_alert(p)
    assert "alert_id" in str(e.value)


def test_unknown_extra_keys_are_ignored(tmp_path):
    """The forward-compat rule: readers ignore keys added by newer producers."""
    p = tmp_path / "x.alert.json"
    d = json.loads(json.dumps(VALID))
    d["disposition"] = {"status": "acknowledged"}      # what 6.2 might add
    d["verdict"]["new_thing"] = 1
    write_json(p, d)
    a = read_alert(p)
    assert a.alert_id == VALID["alert_id"]


# --------------------------- read_alerts ----------------------------------- #


def test_directory_scan_is_sorted_and_skips_unrelated_files(tmp_path):
    for name in ("b.alert.json", "a.alert.json"):
        write_json(tmp_path / name, dict(VALID, alert_id=("a" if name.startswith("a") else "b") * 32))
    (tmp_path / "notes.txt").write_text("not a record", encoding="utf-8")
    (tmp_path / "z.report.json").write_text(json.dumps(VALID), encoding="utf-8")   # not *.alert.json

    reads = read_alerts(tmp_path)
    assert [r.path.name for r in reads] == ["a.alert.json", "b.alert.json"]
    assert all(r.alert and not r.error for r in reads)


def test_one_bad_file_never_stops_the_batch(tmp_path):
    write_json(tmp_path / "good.alert.json", VALID)
    (tmp_path / "corrupt.alert.json").write_text("{oops", encoding="utf-8")
    write_json(tmp_path / "alien.alert.json", {"schema": "other.tool.v1", "x": 1})

    reads = read_alerts(tmp_path)
    by_name = {r.path.name: r for r in reads}
    assert by_name["good.alert.json"].alert is not None
    assert by_name["corrupt.alert.json"].alert is None and "corrupt.alert.json" in by_name["corrupt.alert.json"].error
    assert "other.tool.v1" in by_name["alien.alert.json"].error
    assert {r.path.name for r in reads} == {"good.alert.json", "corrupt.alert.json", "alien.alert.json"}


def test_real_produced_record_reads_back(alert_dir):
    reads = read_alerts(alert_dir)
    assert len(reads) == 1
    a = reads[0].alert
    assert a is not None
    assert a.schema_ == "arer.alert.v2"
    assert a.source_file == "salad[.]eml"
    assert a.verdict.level.value in {"SUSPICIOUS", "LIKELY_PHISHING", "MALICIOUS"}
    assert a.verdict.sha256 and len(a.verdict.sha256) == 64


def test_empty_or_missing_directory(tmp_path):
    assert read_alerts(tmp_path / "nope") == []        # missing dir: no records, no crash
    empty = tmp_path / "empty"
    empty.mkdir()
    assert read_alerts(empty) == []


# --------------------------- CLI: arer alerts ------------------------------- #


def test_cli_alerts_list(alert_dir):
    from arer.cli import main
    res = CliRunner().invoke(main, ["alerts", "list", str(alert_dir)])
    assert res.exit_code == 0, res.output
    assert "SUSPICIOUS" in res.output or "LIKELY_PHISHING" in res.output or "MALICIOUS" in res.output
    assert "salad" in res.output


def test_cli_alerts_list_reports_broken_files(tmp_path):
    from arer.cli import main
    write_json(tmp_path / "good.alert.json", VALID)
    (tmp_path / "corrupt.alert.json").write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "list", str(tmp_path)])
    assert res.exit_code == 1                          # parse-style: listed, but exit 1
    assert "alert[.]eml" in res.output                 # the good record is still listed
    assert "corrupt.alert.json" in res.output          # and the bad file is named
    assert "1 valid, 1 unreadable" in res.output


def test_cli_alerts_list_level_filter(alert_dir):
    from arer.cli import main
    ok = CliRunner().invoke(main, ["alerts", "list", str(alert_dir), "--level", "MALICIOUS"])
    assert ok.exit_code == 0
    assert "salad" not in ok.output                    # a SUSPICIOUS record is filtered out


def test_cli_alerts_show_by_id_prefix(alert_dir):
    from arer.cli import main
    reads = read_alerts(alert_dir)
    full_id = reads[0].alert.alert_id
    res = CliRunner().invoke(main, ["alerts", "show", str(alert_dir), full_id[:8]])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["schema"] == "arer.alert.v2"


def test_cli_alerts_show_rejects_bad_ids(alert_dir):
    from arer.cli import main
    nope = CliRunner().invoke(main, ["alerts", "show", str(alert_dir), "deadbeef"])
    assert nope.exit_code == 1 and "no alert record matches" in nope.output
