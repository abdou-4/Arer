"""End-to-end CLI tests. Builds a small phishing-style .eml on the fly."""
from email.message import EmailMessage

import pytest
from click.testing import CliRunner

from arer.cli import exit_code_for, main
from arer.config import load_config
from arer.loader import LoadError, load_any
from arer.models import Level
from arer.pipeline import run_pipeline


@pytest.fixture
def eml(tmp_path):
    m = EmailMessage()
    m["From"] = '"PayPal Support" <support@paypa1-secure.com>'
    m["To"] = "victim@corp.com"
    m["Reply-To"] = "collector@evil.example"
    m["Subject"] = "Verify now"
    m.set_content("Go to http://1.2.3.4/login")
    m.add_attachment(b"MZ\x90\x00" + b"\0" * 50, maintype="application",
                     subtype="octet-stream", filename="invoice.pdf.exe")
    p = tmp_path / "phish.eml"
    p.write_bytes(m.as_bytes())
    return p


def _level_of(path):
    return run_pipeline(load_any(path), load_config()).level


def test_load_any_eml_reads_attachment_and_magic(eml):
    e = load_any(eml)
    assert e.from_domain == "paypa1-secure.com" and e.reply_to_domain == "evil.example"
    a = e.attachments[0]
    assert a.extension == ".exe" and a.magic_hex.startswith("4d5a") and a.sha256


def test_load_any_rejects_unknown_type(tmp_path):
    f = tmp_path / "x.txt"; f.write_text("hi")
    with pytest.raises(LoadError):
        load_any(f)


def test_exit_code_mapping_is_frozen():
    assert exit_code_for(Level.CLEAN) == 0
    assert exit_code_for(Level.SUSPICIOUS) == 3
    assert exit_code_for(Level.LIKELY_PHISHING) == 4
    assert exit_code_for(Level.MALICIOUS) == 5
    assert exit_code_for(Level.INSUFFICIENT_DATA) == 6

def test_scan_eml_flags_phishing_and_alert_exit_code(eml):
    level = _level_of(eml)
    assert level in {Level.LIKELY_PHISHING, Level.MALICIOUS}
    r = CliRunner().invoke(main, ["scan", str(eml)])
    assert r.exit_code == exit_code_for(level) >= 4          # scripts: >= 3 means alert
    for finding in ("sender.reply_to_mismatch", "attachment.executable", "url.ip_host"):
        assert finding in r.output


def test_scan_clean_eml_exits_0(tmp_path):
    m = EmailMessage()
    m["From"] = "Sam <sam@example.org>"; m["To"] = "me@example.org"; m["Subject"] = "Lunch"
    m["Date"] = "Mon, 05 Jan 2026 09:00:00 +0000"; m["Message-ID"] = "<1@example.org>"
    m.set_content("Hi, lunch on Friday?")
    f = tmp_path / "ok.eml"; f.write_bytes(m.as_bytes())
    r = CliRunner().invoke(main, ["scan", str(f), "-q"])
    assert r.exit_code == 0 and "ok.eml" in r.output


def test_parse_then_scan_json(eml, tmp_path):
    out = tmp_path / "out"
    r = CliRunner().invoke(main, ["parse", str(eml), "-o", str(out)])
    assert r.exit_code == 0 and (out / "phish.eml.json").is_file()
    r = CliRunner().invoke(main, ["scan", str(out / "phish.eml.json"), "-q"])
    assert r.exit_code == exit_code_for(_level_of(out / "phish.eml.json")) and "phish.eml.json" in r.output


def test_scan_folder_writes_reports_and_skips_them(eml, tmp_path):
    rep = tmp_path / "rep"
    CliRunner().invoke(main, ["scan", str(eml), "--out", str(rep)])
    assert (rep / "phish.eml.report.json").is_file()
    r = CliRunner().invoke(main, ["scan", str(rep)])            # only report files inside
    assert r.exit_code == 1 and "nothing to scan" in r.output


def test_json_flag_rejects_many(eml, tmp_path):
    r = CliRunner().invoke(main, ["scan", str(eml), str(eml), "--json", str(tmp_path / "x.json")])
    assert r.exit_code == 2                                   # usage error, not a verdict

def test_scan_without_arguments_is_usage_error(eml):
    r = CliRunner().invoke(main, ["scan"])
    assert r.exit_code == 2                                   # Click usage convention stays 2


def test_bad_file_does_not_stop_batch(eml, tmp_path):
    bad = tmp_path / "bad.json"; bad.write_text("{nope")
    r = CliRunner().invoke(main, ["scan", str(bad), str(eml), "-q"])
    assert "phish.eml" in r.output
    assert r.exit_code == exit_code_for(_level_of(eml)) > 1   # verdict severity outranks the load error
