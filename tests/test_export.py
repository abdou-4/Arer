"""Phase 6.3: exporting the alert queue for SIEM / SOAR / spreadsheets.

One flat line (JSONL) or row (CSV) per alert, dispositions merged in. The
full record stays in the queue folder; the export is the aggregate view.

Frozen here:
- EXPORT_KEYS / COLUMNS               the flat schema of one exported alert
- the batch rule                      corrupt files are named, exit 1,
                                      healthy rows still export
- safe-by-default                     export is defanged even when the queue
                                      was written with `scan --raw`;
                                      --raw passes everything through
"""
import csv
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import read_alerts
from arer.disposition import read_disposition
from arer.export import COLUMNS, EXPORT_KEYS, export_row, render

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE><!DOCTYPE><!DOCTYPE>"
         + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); width:640px;height:1138px"></div></a>')

SALAD_EML = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD)


def make_queue(tmp_path, raw=False, subject="win"):
    """One real alert record + the alerts folder, produced the production way."""
    from arer.cli import main
    src = tmp_path / "mail"
    src.mkdir()
    (src / "salad.eml").write_text(SALAD_EML.replace("Subject: win", f"Subject: {subject}"), encoding="utf-8")
    alerts = tmp_path / "alerts"
    args = ["scan", str(src), "--alerts", str(alerts), "-q", "--skip", "intel", "--skip", "history"]
    if raw:
        args.append("--raw")
    res = CliRunner().invoke(main, args)
    assert res.exit_code >= 3, res.output
    return alerts


# --------------------------- the flat schema -------------------------------- #


def test_export_keys_are_frozen():
    alerts = read_alerts(make_queue(tmp_path_mkdir()))
    row = export_row(alerts[0].alert, None, alerts[0].path.name)
    assert list(row) == EXPORT_KEYS == COLUMNS
    assert row["schema"] == "arer.alert.v1"
    assert row["record_file"].endswith(".alert.json")
    assert row["disposition_status"] == "" and row["disposition_set_utc"] == ""


def tmp_path_mkdir():
    import tempfile
    return Path(tempfile.mkdtemp())


def test_disposition_is_merged_into_the_row():
    from arer.cli import main
    d = make_queue(tmp_path_mkdir())
    alert = read_alerts(d)[0].alert
    CliRunner().invoke(main, ["alerts", "set", str(d), alert.alert_id[:8], "phishing", "--note", "real campaign"])
    a = read_alerts(d)[0]
    row = export_row(a.alert, read_disposition(a.path), a.path.name)
    assert row["disposition_status"] == "phishing"
    assert row["disposition_note"] == "real campaign"
    assert row["disposition_set_utc"].endswith("Z")


def test_render_jsonl_is_one_object_per_line():
    d = make_queue(tmp_path_mkdir())
    reads = read_alerts(d)
    rows = [export_row(r.alert, None, r.path.name) for r in reads]
    text = render(rows, "jsonl")
    lines = text.splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["alert_id"] == rows[0]["alert_id"]
    assert obj["level"] in {"SUSPICIOUS", "LIKELY_PHISHING", "MALICIOUS"}


def test_render_csv_has_header_and_one_row():
    d = make_queue(tmp_path_mkdir())
    reads = read_alerts(d)
    rows = [export_row(r.alert, None, r.path.name) for r in reads]
    parsed = list(csv.reader(render(rows, "csv").splitlines()))
    assert parsed[0] == COLUMNS
    assert len(parsed) == 2 and parsed[1][COLUMNS.index("alert_id")] == rows[0]["alert_id"]


def test_render_is_safe_by_default_and_raw_stays_raw():
    import tempfile
    # a subject carrying a live URL is stored raw by `scan --raw`
    raw_dir = make_queue(Path(tempfile.mkdtemp()), raw=True,
                         subject="Verify at https://evil-phish.example/login now")
    r = read_alerts(raw_dir)[0]
    row = export_row(r.alert, None, r.path.name)
    assert "https://evil-phish.example" in row["subject"]      # the queue was raw
    safe = render([row], "jsonl", defang=True)
    assert "hxxps://evil-phish[.]example" in safe
    assert "https://" not in safe                              # export is safe by default
    raw_text = render([row], "jsonl", defang=False)
    assert "https://evil-phish.example" in raw_text            # --raw passes through
    assert json.loads(raw_text)["schema"] == "arer.alert.v1"


# --------------------------- CLI --------------------------------------------- #


def test_cli_export_jsonl_to_stdout_and_file(tmp_path):
    from arer.cli import main
    from arer.alert import read_alerts
    d = make_queue(tmp_path)
    rec = read_alerts(d)[0]
    out = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert out.exit_code == 0, out.output
    assert json.loads(out.output.splitlines()[0])["schema"] == "arer.alert.v1"
    f = tmp_path / "dump" / "alerts.jsonl"
    to_file = CliRunner().invoke(main, ["alerts", "export", str(d), "-o", str(f)])
    assert to_file.exit_code == 0 and "exported 1 alert" in to_file.output
    # R1.1: the record file name is the immutable alert_id, not the mail name;
    # it is defanged like every string in the export (safe-by-default)
    from arer.util.defang import clean
    assert json.loads(f.read_text(encoding="utf-8").splitlines()[0])["record_file"] == clean(rec.path.name)


def test_cli_export_csv(tmp_path):
    from arer.cli import main
    d = make_queue(tmp_path)
    f = tmp_path / "q.csv"
    res = CliRunner().invoke(main, ["alerts", "export", str(d), "--format", "csv", "-o", str(f)])
    assert res.exit_code == 0, res.output
    parsed = list(csv.reader(f.read_text(encoding="utf-8").splitlines()))
    assert parsed[0] == COLUMNS and len(parsed) == 2


def test_cli_export_filters(tmp_path):
    from arer.cli import main
    from arer.alert import read_alerts
    from arer.util.defang import clean
    d = make_queue(tmp_path)
    rec_name = clean(read_alerts(d)[0].path.name)   # export defangs file names too
    alert = read_alerts(d)[0].alert
    CliRunner().invoke(main, ["alerts", "set", str(d), alert.alert_id[:8], "benign"])
    hit = CliRunner().invoke(main, ["alerts", "export", str(d), "--status", "benign"])
    assert hit.exit_code == 0 and rec_name in hit.output
    miss = CliRunner().invoke(main, ["alerts", "export", str(d), "--status", "new"])
    assert miss.exit_code == 0 and rec_name not in miss.output
    miss2 = CliRunner().invoke(main, ["alerts", "export", str(d), "--level", "MALICIOUS"])
    assert miss2.exit_code == 0 and rec_name not in miss2.output


def test_cli_export_names_corrupt_files_and_still_exports(tmp_path):
    from arer.cli import main
    from arer.alert import read_alerts
    from arer.util.defang import clean
    d = make_queue(tmp_path)
    rec_name = clean(read_alerts(d)[0].path.name)
    (d / "corrupt.alert.json").write_text("{oops", encoding="utf-8")
    res = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert res.exit_code == 1
    assert "corrupt.alert.json" in res.output
    json_line = next(l for l in res.output.splitlines() if l.startswith("{"))   # stderr is interleaved first
    assert json.loads(json_line)["record_file"] == rec_name
    assert "exported, 1 unreadable" in res.output


def test_cli_export_empty_folder(tmp_path):
    from arer.cli import main
    empty = tmp_path / "empty"
    empty.mkdir()
    res = CliRunner().invoke(main, ["alerts", "export", str(empty)])
    assert res.exit_code == 0 and "no alert records" in res.output
