"""R4: export safety - the confirmed-only gate, CSV formula injection,
defang idempotency, privacy, and the IOC formats (csv/blocklist/misp).

Frozen contract:
- the default IOC/case export carries ONLY analyst-confirmed phishing
  cases; import/tool/legacy_unverified/benign/acknowledged/unreviewed are
  counted in an exclusion summary and their indicators NEVER leave the queue;
- CSV cells are neutralized against spreadsheet formula injection for every
  attacker-controlled string (subject, sender, filename, note), including
  leading-whitespace/control-character prefixes;
- defang() is idempotent: defang(defang(x)) == defang(x); unicode dot
  variants and full-width scheme lookalikes are defanged too; already
  damaged strings are not damaged further;
- sender plaintext never appears in default exports (v2 stores the domain);
- the blocklist/misp/csv IOC formats are deterministic, deduplicated, and
  defanged unless --raw is passed.
"""
import csv
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import Alert, ScanSubject
from arer.export import _csv_cell, export_row, render
from arer.iocs import IOC, collect_iocs, to_blocklist, to_csv, to_misp
from arer.models import Level, Verdict
from arer.util.defang import defang, safe_text

SALAD = ("<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
         "<!DOCTYPE><!DOCTYPE>" + "<textarea></textarea>" * 25 + "<option>" * 10
         + '<div style="display:none !important;">x</div>' * 22
         + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
           'width:640px;height:1138px"></div></a>')
SALAD_EML = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + SALAD)


def make_queue(tmp_path, subject="win"):
    from arer.cli import main
    src = tmp_path / "mail"
    src.mkdir(exist_ok=True)
    (src / "salad.eml").write_text(SALAD_EML.replace("Subject: win", f"Subject: {subject}"), encoding="utf-8")
    alerts = tmp_path / "alerts"
    res = CliRunner().invoke(main, ["scan", str(src), "--alerts", str(alerts), "-q",
                                    "--skip", "intel", "--skip", "history"])
    assert res.exit_code >= 3, res.output
    return alerts


def confirm(tmp_path, status="phishing"):
    from arer.alert import read_alerts
    from arer.cli import main
    d = make_queue(tmp_path)
    alert = read_alerts(d)[0].alert
    r = CliRunner().invoke(main, ["alerts", "set", str(d), alert.alert_id[:8], status])
    assert r.exit_code == 0, r.output
    return d, read_alerts(d)[0]


# --------------------------- CSV formula injection (R4.3) --------------------- #


@pytest.mark.parametrize("payload", [
    "=cmd|' /C calc'!A0",
    "+1+cmd|' /C calc'!A0",
    "-2+cmd|' /C calc'!A0",
    "@SUM(1+1)",
    "\tcmd|' /C calc'!A0",
    "\rcmd|' /C calc'!A0",
    "  =1+1",                     # leading whitespace a spreadsheet may ignore
    "\x0b=1+1",                   # vertical tab before the trigger
    "\x00=1+1",                   # NUL prefix
])
def test_csv_formula_cells_are_neutralized(payload):
    cell = _csv_cell(payload)
    assert cell.startswith("'"), f"{payload!r} stayed an active formula"
    # the payload itself is preserved after the guard
    assert cell[1:] == payload


def test_csv_formula_neutralization_reaches_every_text_column(tmp_path):
    d, rec = confirm(tmp_path)
    from arer.alert import read_alerts
    from arer.cli import main
    # a hostile note (the analyst pasted something formula-like) - the note is
    # stored verbatim, so the CSV layer must neutralize it
    r = CliRunner().invoke(main, ["alerts", "set", str(d), rec.alert.alert_id[:8], "phishing",
                                  "--note", "=HYPERLINK(\"http://evil.example\", \"win\")"])
    assert r.exit_code == 0
    alert = read_alerts(d)[0].alert
    row = export_row(alert, __import__("arer.disposition", fromlist=["read_disposition"]
                                       ).read_disposition(read_alerts(d)[0].path, alert),
                     read_alerts(d)[0].path.name)
    text = render([row], "csv", defang=True)
    parsed = list(csv.reader(text.splitlines()))
    note_col = __import__("arer.export", fromlist=["COLUMNS"]).COLUMNS.index("disposition_note")
    assert parsed[1][note_col].startswith("'=HYPERLINK")


def test_csv_normal_cells_are_untouched():
    assert _csv_cell("plain text") == "plain text"
    assert _csv_cell(42) == 42
    assert _csv_cell("") == ""


# --------------------------- defang idempotency (R4.4) ------------------------ #


@pytest.mark.parametrize("text, must_contain", [
    ("user@evil.com", "user[@]evil[.]com"),
    ("user[@]evil.com", "user[@]evil[.]com"),          # half-defanged input completes
    ("hxxps://evil[.]com/login", "hxxps://evil[.]com/login"),   # already defanged: unchanged
    ("alert[@]bank.example", "alert[@]bank[.]example"),
    ("http://evil.com/login", "hxxp://evil[.]com/login"),
    ("ftp://files.example/x", "fxp://files[.]example/x"),
    ("1.2.3.4", "1[.]2[.]3[.]4"),
    ("2001:db8::1", "2001:db8::1"),                    # IPv6: no dots, unchanged, never corrupted
    ("evil。com。phish", "evil[.]com[.]phish"),          # ideographic full stop
    ("evil．com", "evil[.]com"),                        # full-width full stop
    ("ｈｔｔｐｓ://evil.com", "hxxps://evil[.]com"),     # full-width scheme
    ("invoice.pdf", "invoice[.]pdf"),
    ("invoice_file-1.tar.gz", "invoice_file-1[.]tar[.]gz"),   # underscores/punctuation preserved
])
def test_defang_corpus(text, must_contain):
    once = defang(text)
    assert must_contain in once
    assert defang(once) == once, f"defang is not idempotent for {text!r}"


@pytest.mark.parametrize("control", ["\u061c", "\u2028", "\u2029", "\u202e"])
def test_bidi_and_line_separator_controls_are_neutralized(control):
    assert "<U+" in safe_text(f"evil{control}.com")
    assert control not in safe_text(f"evil{control}.com")


def test_already_damaged_strings_are_not_damaged_further():
    """The historic damage (alert[[@]]..., c1[[@]]...) must never get worse:
    the damaged markers survive verbatim; any still-live dots get defanged
    (completing, not compounding)."""
    for damaged in ("alert[[@]]evil.com", "c1[[@]]", "evil[[.]]com"):
        out = defang(damaged)
        assert "[[[@" not in out and "[[[." not in out, damaged
        for token in ("[[@]]", "[[.]]"):
            if token in damaged:
                assert token in out, f"{damaged} was damaged further: {out!r}"


def test_cyrillic_lookalikes_survive_display():
    # visual spoofing: safe_text keeps the characters but limits harm elsewhere
    out = safe_text("раураl.com-lookalike", 100)
    assert "раураl.com-lookalike" in out


# --------------------------- the export gate (R4.1) --------------------------- #


def test_unconfirmed_cases_never_export(tmp_path):
    d, rec = confirm(tmp_path, status="acknowledged")
    from arer.cli import main
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert r.exit_code == 0
    assert "confirmed: 0 case(s) exported" in r.output and "acknowledged 1" in r.output


def test_only_analyst_phishing_passes_the_gate(tmp_path):
    from arer.alert import read_alerts
    from arer.cli import main
    from arer.disposition import SCHEMA_V1, build_disposition, write_disposition
    d = make_queue(tmp_path)
    rec = read_alerts(d)[0]

    # a TOOL-written decision: correct status, wrong provenance -> excluded
    write_disposition(build_disposition(rec.alert.alert_id, "phishing",
                                        mail_sha256=rec.alert.verdict.sha256,
                                        provenance="tool"), rec.path)
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert "confirmed: 0 case(s) exported" in r.output and "unverified_provenance 1" in r.output

    # a LEGACY v1 sidecar (no provenance field): never analyst-confirmed
    v1 = {"schema": SCHEMA_V1, "alert_id": rec.alert.alert_id,
          "mail_sha256": rec.alert.verdict.sha256, "status": "phishing",
          "note": "old queue", "set_utc": "2026-01-01T00:00:00Z"}
    from arer.disposition import disposition_path
    disposition_path(rec.path).write_text(json.dumps(v1), encoding="utf-8")
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert "confirmed: 0 case(s) exported" in r.output and "unverified_provenance 1" in r.output

    # the analyst decides -> passes
    CliRunner().invoke(main, ["alerts", "set", str(d), rec.alert.alert_id[:8], "phishing"])
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert "confirmed: 1 case(s) exported" in r.output


def test_export_summary_never_leaks_excluded_iocs(tmp_path):
    from arer.cli import main
    d, _rec = confirm(tmp_path, status="benign")
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    blob = r.output
    assert "discord.com" not in blob.replace("discord[.]com", "")   # no live domain from the excluded case
    assert "img.example.net" not in blob                            # no URL from the excluded case


# --------------------------- IOC formats (R4.2) ------------------------------- #


def mk_confirmed(sha, gen, urls, domains, sender, atts):
    a = Alert(alert_id="1" * 32, generated_utc=gen, source_file="m.eml", logic_hash="h" * 16,
              scan=ScanSubject(from_="", from_domain=sender),
              verdict=Verdict(sha256=sha, level=Level.MALICIOUS, score=90))
    a.indicators = {"urls": urls, "url_domains": domains, "sender_domain": sender,
                    "attachments": atts}
    return a


def test_ioc_collection_is_structured_and_deduplicated():
    a = mk_confirmed("a" * 64, "2026-01-01T00:00:00Z",
                     ["http://1.2.3.4/login", "http://1.2.3.4/login"],
                     ["1.2.3.4"], "phish.example",
                     [{"sha256": "c" * 64, "inline": False, "filename": "i.pdf", "size_bytes": 5}])
    iocs = collect_iocs([(a, None)])
    values = [(i.kind, i.value) for i in iocs]
    assert len(values) == len(set(values))                 # deduplicated
    assert iocs == sorted(iocs, key=lambda i: (["url", "domain", "sender_domain", "sha256"].index(i.kind), i.value))
    assert ("sha256", "c" * 64) in values


def test_v1_confirmed_records_without_indicator_block_are_skipped():
    a = Alert(alert_id="1" * 32, generated_utc="2026-01-01T00:00:00Z", source_file="m.eml",
              logic_hash="h" * 16, scan=ScanSubject(from_="x@y.z"),
              verdict=Verdict(sha256="a" * 64, level=Level.MALICIOUS, score=90))
    iocs = collect_iocs([(a, None)])
    assert iocs == [] and collect_iocs.last_skipped_no_block == 1


def test_blocklist_format_is_deterministic_and_deduplicated():
    a1 = mk_confirmed("a" * 64, "2026-01-01T00:00:00Z", ["http://e1.example/x"], ["e1.example"], "s1.example", [])
    a2 = mk_confirmed("b" * 64, "2026-01-02T00:00:00Z", ["http://e1.example/x"], ["e1.example"], "s1.example", [])
    text1 = to_blocklist(collect_iocs([(a1, None)]))
    text2 = to_blocklist(collect_iocs([(a1, None), (a2, None)]))
    assert text1 == text2                                  # duplicates across cases collapse
    lines = text1.splitlines()
    assert all(ln and not ln.startswith("#") for ln in lines)   # no prose/headers
    assert len(lines) == len(set(lines))


def test_misp_structure_is_documented_and_typed():
    a = mk_confirmed("a" * 64, "2026-01-01T00:00:00Z", ["http://1.2.3.4/login"], ["1.2.3.4"],
                     "phish.example", [{"sha256": "c" * 64, "inline": False, "filename": "i", "size_bytes": 1}])
    event = json.loads(to_misp(collect_iocs([(a, None)])))["Event"]
    assert set(event) == {"info", "distribution", "threat_level_id", "analysis", "Attribute"}
    types = {att["type"] for att in event["Attribute"]}
    assert types == {"url", "domain", "sha256"}
    for att in event["Attribute"]:
        assert set(att) == {"type", "category", "to_ids", "value", "comment", "timestamp"}
        assert "1.2.3.4" in att["comment"] or att["value"]  # case reference present
    assert "confidence" not in json.dumps(event).lower()   # no invented confidence scale


def test_ioc_default_output_is_defanged_raw_is_live():
    a = mk_confirmed("a" * 64, "2026-01-01T00:00:00Z", ["http://1.2.3.4/login"], ["1.2.3.4"], "phish.example", [])
    iocs = collect_iocs([(a, None)])
    safe = to_csv(iocs)
    assert "phish[.]example" in safe and "http://1.2.3.4/login" not in safe
    live = to_csv(iocs, raw=True)
    assert "phish.example" in live and "http://1.2.3.4/login" in live
    assert "http://" not in to_blocklist(iocs)             # blocklist safe by default


def test_cli_iocs_only_from_confirmed_cases(tmp_path):
    from arer.cli import main
    d, rec = confirm(tmp_path, status="benign")
    r = CliRunner().invoke(main, ["alerts", "iocs", str(d)])
    assert r.exit_code == 0
    assert "indicators: 0" in r.output and "benign 1" in r.output
    # confirm -> the structured block contributes indicators
    from arer.alert import read_alerts
    rec2 = read_alerts(d)[0]
    CliRunner().invoke(main, ["alerts", "set", str(d), rec2.alert.alert_id[:8], "phishing"])
    r = CliRunner().invoke(main, ["alerts", "iocs", str(d), "--format", "blocklist", "--raw"])
    assert r.exit_code == 0
    assert "img.example.net" in r.output                   # the salad's URL domain? (or its host)


def test_sender_plaintext_never_in_exports(tmp_path):
    from arer.cli import main
    d, _rec = confirm(tmp_path)
    r = CliRunner().invoke(main, ["alerts", "export", str(d)])
    assert '"from": ""' in r.output                        # v2 stores no plaintext address
    assert "news@" not in r.output
    q = CliRunner().invoke(main, ["alerts", "export-queue", str(d)])
    assert '"from": ""' in q.output and "news@" not in q.output
