from pathlib import Path

from arer.mail_parser import parse_mail_file

SAMPLE = Path(__file__).parent.parent / "data" / "samples" / "phish_sample.eml"


def test_eml_core_fields():
    d = parse_mail_file(SAMPLE)
    assert d["file"]["format"] == "eml"
    assert d["envelope"]["subject"] == "Urgent: verify your account"
    assert d["envelope"]["from"][0]["domain"] == "paypa1.example"
    assert d["attachments"][0]["filename"] == "inv.pdf"
    assert d["indicators"]["href_text_mismatches"]
